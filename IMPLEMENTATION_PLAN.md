# DLC Verify Rust/TVC implementation plan

Status: active  
Parity target: `LygosLabs/dlc-verify` PR #9 at `e46703e7adf21ce407e150d4f46ff455ba46fd57`  
TVC base: `tkhq/tvc-template` at `fcafd3faf2e9ff18f6a259ed049edd1e9e02423e`  
Rust foundation: `LygosLabs/dlc-verify-tvc` at `3e620cef4405fddcf39804c9e79854d3b5daa848`

## Objective

Deliver a deterministic Rust verifier that reproduces DLC Verify's supported verification and policy outputs, runs without egress inside Turnkey Verifiable Cloud, and returns a Turnkey App Proof whose Boot Proof can be checked against a separately trusted Lygos release identity.

“Parity” is not satisfied by decoding the messages or matching the JSON field names. It requires the Rust implementation to reconstruct the same funding, CET, and refund transactions; reach the same cryptographic conclusions; evaluate the same policy; and produce the same hashes, digests, status, and material output fields for the frozen fixture corpus.

## Fixed technical decisions

- Use Rust and DDK-native crates, not `rust-dlc` or the demo's custom wire/transaction implementation.
- Pin consensus-critical dependencies exactly. The initial supported line is `ddk-messages = 1.1.2`, `ddk-dlc = 1.1.2`, `bitcoin = 0.32.6`, `lightning = 0.2.2`, and `secp256k1-zkp = 0.11.0`.
- Support the current Lygos shape first: a single contract, enumerated descriptor, and single oracle. Unsupported numeric, disjoint, or multi-oracle contracts fail explicitly; they are not approximated.
- Preserve the current event-ID formula from PR #9: `eventType + "-" + SHA256(eventType//loanId//repaymentAddress//repaymentAmount)`, with every component trimmed.
- Derive the protocol network from the Offer chain hash. A caller-selected network is only an address-rendering choice and cannot override the signed protocol fact.
- Keep TVC egress disabled. Explorer, RPC, broadcasting, and oracle lookup are outside the first verifier trust boundary.
- Never return `pass` while a verification required by the defined trust boundary is unavailable. Unsupported or missing checks produce `fail` or `incomplete`, not optimistic success.
- The exact result embedded in the signed App Proof payload is authoritative. Any duplicated outer result is convenience data only.

## Architecture

```text
crates/verifier-schema    Stable compatibility and v1 wire types
crates/verifier-core      Pure deterministic DLC parsing/reconstruction/verification
crates/dlc-verify-tvc     Bounded HTTP service and App Proof production
crates/verifier-client    Offline App Proof + Boot Proof + release-policy verification
crates/e2e                Process and HTTP conformance tests
scripts/differential      TypeScript/Rust golden-vector generation and comparison
tvc-configs               Development and production configuration templates
release                   Machine-readable release identity manifests
```

`verifier-core` must remain side-effect free: no filesystem, clock, randomness, environment, RPC, or network access. All non-determinism belongs at the service/client boundary and must not affect the verification result.

## Workstream 1 — exact DLC verification parity

### 1.1 Parsing and structural validation

- Decode Offer, Accept, and optional Sign with full byte consumption and bounded lengths.
- Validate protocol/version fields and reject unknown versions.
- Validate Offer/Accept temporary contract-ID linkage.
- Validate collateral arithmetic, payout bounds, unique outcome labels, oracle nonce count, and signature-count cardinality before expensive cryptography.
- Preserve structured failures in a result object so a TEE can sign negative verdicts; malformed user input must not collapse into an unsigned generic server error.
- Fail explicitly for unsupported contract/oracle shapes.

### 1.2 Funding, CET, and refund reconstruction

- Convert DDK message funding inputs, including DLC/spliced inputs where present, into the exact party parameters expected by `ddk-dlc`.
- Reconstruct the funding script, funding transaction, funding output index/value, ordered CETs, and refund transaction using the pinned DDK APIs.
- Match DLC Verify's input ordering, serial-ID ordering, fee computation, locktimes, scripts, output ordering, transaction serialization, and txids.
- Compute the final contract ID from the reconstructed funding outpoint and temporary contract ID, then compare it with every applicable Sign/message reference.
- Extract the same funding, payout, change, refund, and CET address/output facts as the TypeScript result.

### 1.3 Cryptographic verification

- Verify the oracle announcement signature and event nonce cardinality.
- Verify every accepter CET adaptor signature and the accepter refund signature against the reconstructed transactions.
- When Sign is supplied, verify every offerer CET adaptor signature and the offerer refund signature, and compare the Sign contract ID to the computed ID.
- Verify Sign funding witnesses where the message/input form permits deterministic verification. If a funding-input form lacks the necessary prevout/script data, expose a specific incomplete reason rather than treating the signature set as valid.
- Keep per-side valid/total counts and stable error identifiers compatible with DLC Verify.

### 1.4 Exact result semantics

- Implement the complete PR #9 `VerificationResult` field set, names, nullability, and stable failure/incomplete identifiers.
- Match the PR #9 transcript hash exactly: domain separator, labeled Offer/Accept/Sign slots, normalized bytes, and four-byte big-endian lengths.
- Preserve the three-state `pass` / `fail` / `incomplete` behavior.
- A supported Offer+Accept with all accepter checks valid may be `incomplete` only because Sign was not supplied. A supplied Sign must be fully checked before `pass`.

## Workstream 2 — policy and compatibility parity

- Implement every PR #9 policy field: lender role, network, oracle key, lender funding key, lender payout address, total collateral, oracle event, CET/refund locktimes, and exact duplicate-free outcome/payout coverage.
- Keep cryptographic verification separate from policy verification.
- Match policy coverage, policy status, overall verdict, stable canonicalization, policy hash, verification digest, and attestation payload byte-for-byte.
- `/api/verify` accepts the TypeScript body and returns the exact compatibility `VerificationResult`.
- `/api/verify-policy` accepts the TypeScript body and returns the exact `DlcPolicyVerificationResult`.
- `/v1/verify` accepts the versioned nested request and returns the compatibility result plus the standard Turnkey App Proof.
- The compatibility endpoints remain available for migration, but relying parties must use the proof-bearing endpoint for a TEE-authenticated decision.

## Workstream 3 — TVC proof and relying-party verification

### 3.1 Enclave application

- Build one static `x86_64-unknown-linux-musl` ELF at `/tvc_app`.
- Listen on `0.0.0.0:3000`, keep `/health` inexpensive, and use HTTP/1-compatible ingress.
- Load only the QOS ephemeral key from `/qos.ephemeral.key`; no compiled development fallback and no Quorum Key dependency for this stateless service.
- Bound JSON size, decoded message size, outcome/signature counts, concurrent work, and wall-clock execution. Run CPU-heavy verification on the bounded blocking pool.
- Do not log request bodies, loan terms, oracle material, or signatures.

### 3.2 App Proof

- Require a non-empty caller challenge on the proof-bearing endpoint.
- Canonically serialize and sign a payload containing a proof type, schema version, verifier/release version, request digest, challenge, and full result.
- Emit Turnkey's standard `{scheme, publicKey, proofPayload, signature}` envelope using the QOS composite public key and raw P-256 signature.
- Verify every produced proof in tests using `turnkey_proofs = 0.15.0`.
- Return signed structured negative verification results. Reserve unsigned HTTP errors for transport/server faults that cannot produce a valid result.

### 3.3 Offline verifier client

- Accept an App Proof, its exact Boot Proof, and a trusted Lygos release policy; verification must not require network access.
- Verify the App Proof signature, AWS Nitro/COSE certificate chain, QOS/manifest binding, and equality of every ephemeral-key representation.
- Pin the expected application/deployment identity, Turnkey production trust anchor and PCR3, QOS PCR set, manifest operator set/threshold, executable digest, pivot path/args/ports, debug state, and egress state.
- Fetching is a separate adapter. If implemented, fetch the Boot Proof by the exact App Proof public key, never “latest by app.” Do not embed broad Turnkey credentials in the verifier.

## Workstream 4 — differential and adversarial validation

- Freeze the three public Lygos fixtures plus generated minimal vectors as repository test data with provenance and hashes.
- Produce TypeScript golden results from the frozen PR #9 commit and compare every compatibility field against Rust.
- Add cross-language golden vectors for event ID, transcript hash, policy hash, verification digest, reconstructed transaction bytes, txids, contract ID, and proof payload request digest.
- Add mutations for trailing bytes, malformed hex, temporary-ID mismatch, collateral/payout overflow, duplicate/missing outcomes, wrong chain hash, oracle-key mismatch, corrupted oracle announcement, wrong adaptor signatures, wrong refund signatures, wrong Sign ID, wrong funding witnesses, oversize bodies/messages, and unsupported shapes.
- Require deterministic repeated output and no panics for arbitrary bounded input. Add property/fuzz targets for parsers, payout arithmetic, canonicalization, and policy evaluation.

## Workstream 5 — release and deployment

- CI gates: format, Clippy with warnings denied, all unit/integration/differential tests, dependency/advisory audit, static StageX build, packaged-image smoke test, and App Proof interoperability test.
- Build a single-platform `linux/amd64` OCI image from digest-pinned builder images with dependency fetching separated from the network-disabled release build.
- Perform two clean builds and require identical `/tvc_app` SHA-256 digests before a production release.
- Publish a release manifest containing source commit, `Cargo.lock` digest, OCI digest, executable digest, QOS version/PCR set, TVC IDs, path/args/ports, debug/egress state, and manifest operator policy.
- Generate fresh TVC configuration with the installed CLI and query the live QOS-version API at deployment time. `0.12.1` is current, but it must not be assumed permanent.
- Use separate development and production TVC applications. Production requires debug disabled, egress disabled, and a 2-of-3 Lygos-controlled manifest set.
- Deployment gate: 3/3 healthy replicas, valid/invalid/malformed/oversize/concurrency canaries, a verified real App Proof and exact-key Boot Proof, and independent release-policy validation before `set-live-deploy`.

## Milestones and acceptance gates

### M1 — deterministic core parity

- All supported fixture transactions and cryptographic checks match TypeScript/DDK expectations.
- Full compatibility result is produced.
- No required implemented check is marked unavailable for a fully signed supported fixture.

### M2 — policy/API parity

- All PR #9 API and policy golden vectors match byte-for-byte after canonicalization.
- Existing DLC Verify callers can switch the base URL without changing request or response handling.

### M3 — TVC relying-party completeness

- Standard App Proofs and exact-key Boot Proofs verify offline against a pinned release policy.
- Negative DLC verdicts are signed and distinguishable from transport failures.

### M4 — production release candidate

- All CI, differential, fuzz/property, reproducibility, packaged-image, and enclave-proof gates pass.
- Release identity is published and independently reproducible.
- Only then may the verifier be used to authorize funding, minting, or settlement.

## Out of scope until parity is complete

- CET execution or broadcasting.
- Bitcoin RPC/explorer confirmation.
- Oracle discovery or attestation lookup.
- Numeric, disjoint, or multi-oracle DLC support without real Lygos requirements and fixtures.
- Package publication or a DDK dependency-line change without a separate registry audit and explicit approval.
