# Lygos DLC Verify for Turnkey Verifiable Cloud

A deterministic Rust/DDK implementation of [Lygos DLC Verify](https://github.com/LygosLabs/dlc-verify), packaged to run inside Turnkey Verifiable Cloud (TVC). The compatibility target is PR #9 at commit `e46703e7adf21ce407e150d4f46ff455ba46fd57`.

For the current Lygos contract shape—one enumerated contract and one oracle—the Rust verifier reconstructs the funding transaction, CETs, and refund transaction; binds the signed oracle event descriptor to the contract outcomes; verifies the oracle announcement, adaptor signatures, refund signatures, contract linkage, and available funding witnesses; and returns the complete PR #9 result and policy schemas. Checked-in TypeScript goldens cover unsigned and fully signed real transcripts, including exact txids, output facts, contract ID, transcript hash, policy hash, verification digest, and every output field.

The consensus-critical dependency line is pinned exactly to `ddk-messages = 2.0.0-rc.9`, `ddk-dlc = 2.0.0-rc.9`, `bitcoin = 0.32.6`, `lightning = 0.2.2`, and `secp256k1-zkp = 0.11.0`. This implementation does not use `rust-dlc`.

## API

- `GET /health` — inexpensive TVC health check.
- `GET /version` — release/schema versions, frozen compatibility target, DDK line, and egress requirement.
- `POST /api/verify` — exact DLC Verify compatibility request and bare `DlcVerifyResult` response.
- `POST /api/verify-policy` — exact PR #9 policy request and `DlcPolicyVerificationResult` response.
- `POST /v1/verify` — versioned request with a required caller challenge; returns the complete policy result plus a Turnkey App Proof.
- `GET /metrics` — request metadata only. Raw DLC messages and loan terms are never logged.

The compatibility verification body is:

```json
{
  "offer": "hex",
  "accept": "hex",
  "signHex": "optional hex",
  "expectedOraclePubkey": "optional x-only key",
  "network": "optional address-rendering network"
}
```

`/api/verify-policy` replaces `expectedOraclePubkey` with the complete optional `policy` object. `/v1/verify` uses the same `offer`, `accept`, `signHex`, `network`, and `policy` fields and adds a required, unique `challenge`:

```json
{
  "offer": "hex",
  "accept": "hex",
  "signHex": "optional hex",
  "network": "testnet",
  "policy": {
    "expectedOraclePubkey": "hex",
    "expectedTotalCollateralSats": "20000",
    "oracleEvent": { "expectedEventId": "repaid-..." }
  },
  "challenge": "required caller-generated unique value"
}
```

The proof-bearing response is `{ "result": ..., "proof": ... }`. The proof uses Turnkey's standard `scheme`, `publicKey`, `proofPayload`, and `signature` fields, and its signed payload binds the proof type, schema and verifier versions, canonical request digest, caller challenge, and complete policy result. Malformed DLC input produces a signed negative result; unsigned errors are reserved for invalid transport-level requests or internal failures.

## Trust boundary

Consumers must verify the App Proof against the Boot Proof for that exact ephemeral public key, compare the proof-bound deployment identity with a separately trusted Lygos release policy, check the request digest and one-time challenge, and act only on the result inside `proofPayload`.

`crates/verifier-client` uses Turnkey's official `turnkey_proofs = 0.15.0` verifier and checks the AWS Nitro/COSE chain, three-way ephemeral-key equality, PCRs, manifest and executable digests, QOS identity, operator threshold/set, arguments, ingress, debug mode, DNS/client bridges, and signed invocation. The current Turnkey proof schema does not expose `pivotPath` or the TVC application's top-level `enableEgress`; strict verification therefore fails closed with a named unsupported-evidence error. See [the client boundary](crates/verifier-client/README.md) and [PARITY.md](PARITY.md).

## Development and packaging

```sh
make test
make lint
make run
make out/dlc-verify-tvc/index.json
```

Build and test commands use `Cargo.lock`. Local and TVC runtime defaults are `0.0.0.0:3000`. Each decoded DLC message is limited to 1 MiB, policy outcome expectations to 4,096, and the JSON body to 7 MiB. At most eight CPU-heavy jobs can continue at once—even after a request timeout—because the blocking jobs themselves retain the permits. HTTP requests time out after 30 seconds.

The StageX build produces one static `linux/amd64` ELF at `/tvc_app`, with dependency fetching separated from a network-disabled release build. Start from `tvc-configs/*.example.json`, replace every placeholder, and deploy only an immutable GHCR digest. Production requires debug disabled, egress disabled, and a 2-of-3 Lygos-controlled manifest set. Named testing release artifacts may record an observed live deployment, but remain explicitly non-authorization-ready.

Release identity templates live under `release/`. A production release is not authorization-ready until the live TVC canary supplies an exact-key Boot Proof and the independently trusted release/deployment controls pass.

An empty `qosCommit` records the value actually committed by the current QOS manifest; it does not establish QOS source-commit provenance. Release artifacts must set `qosCommitProvenanceAvailable` accordingly and rely on the pinned PCRs and manifest hash for the evidence QOS actually provides.

## Mint attester

`crates/mint-attester` is a second TVC application in this workspace. It checks a Midnight DLC and its Bitcoin lock by SPV, then signs the receipt that `lygos-contracts` `Verifier.sol` accepts. The signer is the signing half of the application's quorum key, so it must run as its own TVC app with a quorum key Lygos generates. The default Turnkey quorum key is shared and must not be used.

- `GET /health` — liveness.
- `POST /v1/attest` — DLC transcript, lock proof, and loan terms in; signed receipt out, or `422` with the reason for refusal.

Everything the attester pins is a launch argument, so the QOS manifest measures it: `--network`, `--lygos-funding-pubkey`, `--midnight-oracle-keys`, `--min-confirmations` (default 6, at least 1: an unconfirmed lock is never attested). Any network other than mainnet is refused unless `--allow-insecure-network` is also passed, because its proof of work is free to forge. The SPV check proves that work was done on a chain containing the funding transaction, not that the chain is Bitcoin's, so `--min-confirmations` is the enclave's own floor on what a forged lock costs; the `Verifier` contract may require more, never less. Egress stays disabled; a relayer supplies the headers and Merkle proof. A Midnight DLC must refund to the accepter (contract flag `0x01`), and its two funding keys must differ; anything else is refused. The accepter is the Lygos side, below.

The attester pins one Lygos key, on every network. `--lygos-funding-pubkey` is the Bitcoin key of the Fordefi vault Lygos co-signs every Midnight DLC with, one vault per environment, and the DLC's accepter key must be that key. The transcript check verifies the accepter's CET adaptor signatures and refund signature under it, and those signatures cover this DLC's funding output, every CET and the refund. So a request passes only if the vault signed this exact DLC, and that is Lygos's approval: anyone can lock Bitcoin to a public key, but only the vault can produce its signatures. The enclave compares the key before any signature work; that only saves work, since the key is public. Whoever can make the vault sign can approve a DLC, so it must sit in a Fordefi org only Lygos controls. Staging runs on Mutinynet with a Fordefi testnet vault the same way: Fordefi signs and Lygos broadcasts.

Requests may still carry `authorization`, the signature of the retired Midnight authorizer, an EVM key that earlier releases also pinned. It is read and ignored, so a client that still sends it keeps working.

The Midnight oracle signs with one key per calendar quarter. `--midnight-oracle-keys` takes the same line as orange-grove's `MIDNIGHT_ORACLE_KEYS`, so the key ceremony's output feeds both: comma-separated `keyVersion:xonlyHex` pairs, each split at its last `:`, e.g. `midnight-2026Q4-mainnet-v1:<key>,midnight-2027Q1-mainnet-v1:<key>`. Every key version must name its quarter: `midnight-YYYYQn`, then `-`, `:`, or nothing. One key per quarter. An announcement must be signed by the key pinned for its market's maturity quarter (UTC); a quarter with no key, or any other key, is refused, so one quarter's key cannot sign for another. A new quarter's key needs a new deployment.

The event id commits to orange-grove's `requestId` for the announcement, sent in the attest body as a lowercase hyphenated UUID: `sha256("lygos-midnight-v1" // chainId // originator // marketId // requestId // liquidators // controller // mintDeadline // announcedAt)`, named `midnight-<DDMMMYY>-<digest>`. The borrower's funding key is not in the event id, because ddk generates it after the announcement exists; `termsHash` binds both funding keys from the DLC instead.

Build the image with `make out/mint-attester/index.json`. CI publishes it as `ghcr.io/lygoslabs/mint-attester` and prints the image digest and executable digest.

### Environments and branches

| Branch | Environment | Bitcoin network | TVC app config | Release config | Who approves |
|---|---|---|---|---|---|
| `dev` | staging | mutinynet (signet) | `app.mint-attester.staging.json` | `release.mint-attester.staging.json` | hosted operators, automatic |
| `master` | production | mainnet | `app.mint-attester.mainnet.json` | `release.mint-attester.mainnet.json` | two YubiKey operators, by hand |

Staging on Mutinynet is the one test enclave. It pins a Fordefi funding key like mainnet, and differs only in its network, `--allow-insecure-network` and `--min-confirmations 1` (mainnet 6). There is no testnet4 attester; the old `mint-attester-testnet4` app was deleted on 2026-11-05.

Every deployment runs one replica on the smallest TVC instance, 2 CPUs and 1 GiB (`replicas`, `instanceSizeCpus`, `instanceSizeRam` in the deploy config); the attester is idle almost all the time. One replica means no failover: a replacement enclave needs its quorum-key shares provisioned again, which the hosted operators do on staging and two YubiKey operators must do by hand on mainnet, so mainnet attests nothing until they do.

Each environment is one TVC app, created once. The app owns the quorum key, so a new deployment under the same app signs with the same key and the `Verifier` contract pinned to it never changes. The 24-hour timelock in `lygos-contracts` applies only when a key changes, which means a new app and a new `Verifier`. Enclave code on mainnet is governed by the app's 2-of-3 manifest set instead: whoever holds two operator keys can ship code that signs with the mainnet key, so those keys stay on YubiKeys held by separate people and every mainnet release is announced with its image digest.

### Every merge

`.github/workflows/stagex.yml` builds the reproducible image, pushes it to GHCR, then runs `scripts/tvc-release.sh` for each environment of the branch:

1. `tvc deploy create` from the environment's deploy config, with the image and executable digests overridden by the ones just built. The config file is a template and is not committed back.
2. On `dev`: the two hosted operators in the release config approve the manifest and provision their shares, the deployment is set live once all its replicas are ready, `/health` is checked and the previous deployment is re-targeted if it fails, otherwise the previous deployment is deleted (restorable with `tvc deploy restore`).
3. On `master`: stop after step 1. The job summary prints the deployment and manifest ids. Two operators then run `tvc deploy approve --deploy-id <id> --serial <yubikey serial>`, provision, and one runs `tvc app set-live-deploy`.

CI authenticates with `TVC_ORG_ID`, `TVC_API_KEY_PUBLIC`, and `TVC_API_KEY_PRIVATE` from the GitHub environment of the same name. The release script turns them into a normal `tvc` login using `tvc-configs/tvc.config.ci.toml`, which lists the hosted operators; env-var auth on its own cannot approve or provision as a hosted operator. The production key only needs permission to create deployments.

A release that changes the receipt format needs a new `Verifier` first: deploy it, queue the pointer change, execute after the timelock, then merge to `master` and set the new deployment live.

### Opening a production release PR

After staging/testnet4 QA, run **Actions → Open production release PR → Run workflow**, selecting `dev`. The action opens a `dev` → `master` PR, reuses an existing open one, or exits without creating one when there are no commits to release. It does not merge or deploy. Further pushes to `dev` update the release PR, so review its final head before merging.

The workflow must first be merged into the repository's default branch to appear in Actions. It only runs its job on `dev`. Enable **Allow GitHub Actions to create and approve pull requests** in repository Actions settings when using the default `GITHUB_TOKEN`. GitHub documents that PR CI opened by that token waits for a user with write access to select **Approve workflows to run** on the PR. A repository-scoped GitHub App token or PAT in `RELEASE_PR_TOKEN` allows PR CI to start automatically without that prompt. Give that token repository contents read and pull requests write access; the workflows it triggers run on their own token. Existing branch protection and review requirements still apply.

After merging, `stagex` uses the GitHub `production` environment to create the pending mainnet deployment. Two YubiKey operators approve and provision it manually. See the [production setup and release runbook](https://github.com/LygosLabs/morpho-midnight-planning/blob/master/docs/production-tvc-yubikey-setup.md) for the release steps, key-share commands and rollback procedure. Documentation-only changes can skip `stagex` because of its path filter; run that workflow manually on `master` when a deployment is needed.

### Production approval notifications

After a mainnet candidate is created, `stagex` posts a Slack message with the commit/Actions links, App/deployment/manifest IDs, image and executable digests, the YubiKey approval command, and the release runbook. It says **awaiting 2-of-3 approval (not live)**. There is no notification when placeholder configuration skips deployment, and the staging flow does not use this webhook.

Recommended channel: `#turnkey-deploys`, alongside `#oracle-deploys`. Create a Slack incoming webhook for the chosen release channel and save its URL as `SLACK_PRODUCTION_RELEASE_WEBHOOK_URL` in the GitHub **production environment**. The webhook controls the channel; do not commit its URL. If the secret is missing or Slack rejects the request, the notification step fails visibly after candidate creation. The candidate remains pending and its details remain in the Actions summary; a notification failure does not roll back or approve anything. Rerunning the entire deployment job may create another candidate, so use the existing deployment details for a manual handoff instead of blindly rerunning it.

### Creating an environment

Once per environment, from `tvc-configs/*.mint-attester.example.json`. For mainnet, each operator first sets up a YubiKey with [OPERATOR_YUBIKEY.md](OPERATOR_YUBIKEY.md).

1. Generate the quorum key, split 2-of-3 to the operators. Write both files outside the repository; the metadata file holds the encrypted shares.
   ```bash
   tvc keys init-local-quorum-key -o <dir>/quorum_key.json
   tvc keys generate-local-quorum-key -c <dir>/quorum_key.json --quorum-key-metadata-out <dir>/quorum_key_metadata.json
   ```
2. Put the quorum public key and the three operators in the app config, then `tvc app create --config-file <app config>`. With your own quorum key the config must also declare `shareSetParams` (`name`, `threshold`, `newOperators`, `existingOperatorIds`) listing the operators holding shares; a null share set selects Turnkey's shared default key and provisioning fails with "not part of the manifest share set". Apps cannot be edited afterwards and deleted app names stay reserved.
3. Take the compressed public key of the Fordefi Bitcoin vault that co-signs the environment's Midnight DLCs, in a Fordefi org only Lygos controls, never a lender's. It is the deploy config's `--lygos-funding-pubkey`.
4. Put the app id and pinned keys in the deploy config and the operator ids in the release config. Replace every `REPLACE_WITH_` placeholder; the release script skips an environment whose deploy config still has one.
5. Give the `Verifier` for that environment the app's quorum key, then merge to the branch, or run `scripts/tvc-release.sh <env> <image> <digest>` locally.

The `Verifier` constructor takes the signing half of the quorum public key: the second 65-byte SEC1 point of the 130-byte key, as `signerX` and `signerY`.

### Local (orange-grove dev stack)

Outside TVC the binary needs no QOS: it reads the quorum key from `--quorum-file`. `dev/mint-attester/dev-only-quorum.key` is a fixed quorum key for local development only. It is public, so a `Verifier` that trusts it accepts receipts anyone can sign; never deploy it outside a local chain. The file is a QOS master seed, `sha256("lygos.dev.mint-attester")` in hex, and QOS derives the receipt signing key from it with HKDF-SHA512. The values below are what the attester signs with, pinned by `crates/mint-attester/tests/dev_quorum_key.rs`:

| | |
|---|---|
| Signing scalar (`ENCLAVE_P256_KEY` in lygos-contracts `Deploy.s.sol`) | `0x1c61464af96b6a97655f9a0c51bf5c59ef12a98f56c216e14360875ebb70aa2e` |
| Public key x (`ENCLAVE_X`, the `Verifier`'s `signerX`) | `0xeab1fb2e525b4744a49e099469697402f422646db4747e0cb2340d35c3b0b9c1` |
| Public key y (`ENCLAVE_Y`, the `Verifier`'s `signerY`) | `0x4b839e4f3117435cdc62dd8e63c147130f8adef488482af54746e591b4c35941` |

From the repository root, with `MIDNIGHT_ORACLE_KEYS` as orange-grove sets it and `LYGOS_FUNDING_PUBKEY` the compressed key the dev lender co-signs every DLC with:

```sh
cargo run --locked -p mint-attester -- \
  --quorum-file dev/mint-attester/dev-only-quorum.key \
  --host 0.0.0.0 --port 3000 \
  --network regtest --allow-insecure-network --min-confirmations 1 \
  --midnight-oracle-keys "$MIDNIGHT_ORACLE_KEYS" \
  --lygos-funding-pubkey "$LYGOS_FUNDING_PUBKEY"
```

Confirmations count headers after the funding block's, so with `--min-confirmations 1` the lock proof must carry the funding block's header and at least one after it: mine one block past the funding block before attesting. That is two confirmations as Bitcoin Core counts them; lygos-contracts' `MIN_CONFIRMATIONS` (default 1) counts the same way as the attester.

It builds with `cargo build --locked -p mint-attester` in a stock `rust:1.x-bookworm` image: rustup installs the toolchain `rust-toolchain.toml` pins (1.94), and the native dependencies (`ring`, `secp256k1-sys`, `secp256k1-zkp-sys`) build with the C compiler the image ships. No other system packages are needed.

## Payout script overrides

An offer may carry one DDK 2.0.0-rc.9 `PayoutScriptOverrides` record (TLV type 65005), which makes the CET of each outcome it names pay a third party's script, a liquidator for instance, in place of the accepter's payout script. Reconstruction applies it as `ddk-manager` does: the covered CET is rebuilt with the override script, and funding reserves the CET fee for the longest script the accepter's output can pay. An override must name an outcome of the descriptor whose CET pays the accepter at least the 1,000-sat dust limit, and no outcome may be overridden twice. The record's bytes are in the transcript hash, so the verifier is stricter than DDK about records that build the same transactions as another: the record must be canonically encoded, name at least one override, list its overrides in the descriptor's outcome order, and pay neither party's payout script. Overrides are also supported only on a contract whose descriptor lists its outcomes in the oracle announcement's signed order (the descriptor's own order is in no signature), that refunds to the accepter (contract flag `0x01`) with distinct party payout scripts, and only on a CET that pays the offerer nothing; the first outcome in descriptor order whose CET pays anyone but the accepter must pay the offerer and not be overridden. The refund then fixes the accepter's own script, that first outcome fixes the offerer's, and an overridden CET's single output fixes its override script; otherwise a script could trade places with another, or an outcome be read as the other party's, and build the same transactions. A Midnight DLC has that shape when its descriptor follows its announcement, whose borrower outcomes come before its liquidation outcomes. The overrides record, and which party or override each CET output pays, are then determined by the signed transactions and the oracle's signed outcome order; other transcript fields, such as an unused change script or the serial ids, are not, with or without a record. An offer writer has to follow these rules too, or its offer is refused. Any other TLV record, and any record on an accept or sign message, is refused as trailing data. Each overridden outcome reports its script as `accepterPayoutOverride`, and a policy whose lender is the accepter credits the lender nothing on it. A test checks the funding transaction, CETs and refund against `ddk-manager`'s own builder byte for byte.

## Refund mode compatibility

The verifier accepts contract flags `0x00` (refund each party its collateral) and
`0x01` (DDK refund-to-accepter). Unknown bits remain rejected. The original signed
flag is passed to DDK transaction reconstruction, and both refund signatures
are verified against that transaction. The existing refund-pays-lender policy is
unchanged: supporting a flag does not approve a lender role or a loan policy.

DDK tests the flag-one refund layout itself; this repo tests that unknown bits
are refused, and builds flag-one contracts only in its payout override tests. The frozen TypeScript goldens remain the flag-zero compatibility
target; this extension does not claim TypeScript flag-one parity.
