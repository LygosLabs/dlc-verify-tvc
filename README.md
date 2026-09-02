# Lygos DLC Verify for Turnkey Verifiable Cloud

A deterministic Rust/DDK implementation of [Lygos DLC Verify](https://github.com/LygosLabs/dlc-verify), packaged to run inside Turnkey Verifiable Cloud (TVC). The compatibility target is PR #9 at commit `e46703e7adf21ce407e150d4f46ff455ba46fd57`.

For the current Lygos contract shape—one enumerated contract and one oracle—the Rust verifier reconstructs the funding transaction, CETs, and refund transaction; binds the signed oracle event descriptor to the contract outcomes; verifies the oracle announcement, adaptor signatures, refund signatures, contract linkage, and available funding witnesses; and returns the complete PR #9 result and policy schemas. Checked-in TypeScript goldens cover unsigned and fully signed real transcripts, including exact txids, output facts, contract ID, transcript hash, policy hash, verification digest, and every output field.

The consensus-critical dependency line is pinned exactly to `ddk-messages = 1.1.2`, `ddk-dlc = 1.1.2`, `bitcoin = 0.32.6`, `lightning = 0.2.2`, and `secp256k1-zkp = 0.11.0`. This implementation does not use `rust-dlc`.

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

The StageX build produces one static `linux/amd64` ELF at `/tvc_app`, with dependency fetching separated from a network-disabled release build. Start from `tvc-configs/*.example.json`, replace every placeholder, and deploy only an immutable GHCR digest. Production requires debug disabled, egress disabled, and a 2-of-3 Lygos-controlled manifest set. No repository artifact claims a deployment is live.

Release identity templates live under `release/`. A production release is not authorization-ready until the live TVC canary supplies an exact-key Boot Proof and the independently trusted release/deployment controls pass.
