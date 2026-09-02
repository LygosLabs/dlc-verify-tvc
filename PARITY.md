# TypeScript parity ledger

Compatibility target: DLC Verify PR #9 at `e46703e7adf21ce407e150d4f46ff455ba46fd57`.

## Supported parity envelope

The current Lygos shape—one contract, enumerated descriptor, and one oracle—has exact result and policy parity. Numeric, disjoint, and multi-oracle contracts are rejected explicitly rather than approximated. The protocol network is derived from the signed Offer chain hash; the optional request network controls address rendering only.

| Surface | Rust behavior | Status |
|---|---|---|
| `/api/verify` | Accepts `offer`, `accept`, optional `signHex`, `expectedOraclePubkey`, and `network`; returns bare PR #9 `DlcVerifyResult` | Exact |
| `/api/verify-policy` | Accepts PR #9 request and returns `DlcPolicyVerificationResult` | Exact |
| `/v1/verify` | Adds required challenge and standard Turnkey App Proof around the complete policy result | Rust/TVC extension |
| Negative DLC verdicts | Structured result, and signed on `/v1/verify` | Implemented |

## Verification parity

| Field/check group | Status |
|---|---|
| Full PR #9 field names, nullability, failure/incomplete identifiers | Exact on frozen goldens |
| Chain-hash network, contract shape, collateral, outcomes and payouts | Exact on PR #9 inputs; reversed/Testnet4/Signet hashes are rejected rather than broadened |
| Oracle key/event, announcement signature, nonce cardinality, and maturity/locktime ordering | Exact on valid inputs; Rust additionally requires the signed enum event outcomes to equal the contract outcome set and the CET/refund locktimes to bracket event maturity |
| Funding/payout/change keys, scripts, addresses and inputs | Exact |
| Funding transaction txid/output facts, CET txids/outputs, refund txid/outputs | Exact |
| Temporary/final contract IDs and Sign linkage | Exact |
| Accepter and offerer adaptor signatures and refund signatures | DDK-native verification |
| Offerer funding witnesses | Verified for DLC input, native P2WPKH and P2SH-P2WPKH forms; unavailable forms fail/incomplete explicitly |
| Transcript hash | Exact domain-separated PR #9 algorithm |
| Three-state `pass` / `fail` / `incomplete` semantics | Exact |

The funding-witness verification is a Rust-side hardening beyond the TypeScript target. It does not change valid PR #9 golden output; invalid or unverifiable witnesses add explicit failure/incomplete identifiers.

## Policy parity

Every PR #9 policy field is implemented: lender role, network, oracle key, lender funding key, lender payout address, total collateral, direct or derived oracle event ID, CET/refund locktimes, refund-pays-lender, and exact duplicate-free outcome/payout coverage. Policy coverage, status, overall verdict, canonical policy hash, verification digest, and attestation payload match the frozen TypeScript output.

The intentionally current event-ID formula remains `eventType + "-" + SHA256(eventType//loanId//repaymentAddress//repaymentAmount)`, with all components trimmed.

## Differential and adversarial evidence

- Three frozen fixture cases generated from the TypeScript target, representing two unique transcript pairs: the sample and matured fixtures share Offer/Accept bytes, while the fully signed fixture is distinct.
- Exact JSON equality over every compatibility field for all fixture cases.
- Exact fully signed policy result, policy hash, verification digest, and attestation payload equality.
- Deterministic repeated-output tests.
- Mutations for structural/cardinality failures, mismatched oracle descriptors, malformed expected oracle keys, malformed funding serials/witnesses, oversized policy outcomes, policy errors, missing proof challenges, and signed malformed DLC verdicts.
- A deterministic bounded arbitrary-input parser smoke test is required not to panic. This is not represented as comprehensive fuzz coverage.

The fixtures and their generated golden outputs are checked in under `crates/verifier-core/tests/golden` and `crates/verifier-policy/tests/golden`.

## TVC compatibility and proof boundary

- Static `x86_64-unknown-linux-musl` ELF at `/tvc_app`.
- HTTP/1 service on `0.0.0.0:3000`, with `GET /health` on port 3000.
- QOS ephemeral P-256 key loaded only from `/qos.ephemeral.key`.
- No verifier egress requirement; example TVC application config sets `enableEgress: false`.
- App Proofs verified in tests with `turnkey_proofs = 0.15.0`.
- Offline client is implemented to verify the exact App/Boot ephemeral key, official proof chain, proof-bound release identity, and invocation binding.

Turnkey's current Boot Proof and signed QOS manifest do not carry `pivotPath` or top-level `enableEgress`. Consequently, proof-bound diagnostics return `authorizationGrade: false`, and strict authorization verification fails closed until those external deployment controls are independently authenticated and bound. A real successful Boot Proof fixture is also a live deployment artifact and is not checked in; tests positively cover App Proofs and rejection/progression behavior for Boot Proof inputs, not a mocked successful AWS attestation. This is an attestation-evidence limitation, not a DLC verification gap.

No result should authorize funding, minting, or settlement until the release manifest, live exact-key Boot Proof, one-time challenge, and deployment-control evidence have all been checked.
