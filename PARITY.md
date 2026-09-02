# TypeScript parity ledger

This ledger compares Rust v0.2 with the TypeScript result introduced by DLC Verify PR #9. Rust v0.2 is a production-oriented foundation, **not an authorization-grade verifier yet**. It returns `incomplete` until transaction reconstruction and every required signature check are implemented.

## Input and endpoint mapping

| TypeScript surface | Rust v0.2 | Status |
|---|---|---|
| `/api/verify` body `offer`, `accept`, optional `signHex`, `expectedOraclePubkey`, `network` | Accepted; `offerHex` and `acceptHex` are additional aliases | Implemented |
| `/api/verify` bare `VerificationResult` | Returns the Rust foundation result without an App Proof | Partial; schema expansion remains |
| `/api/verify-policy` | Accepts the transitional flat body and returns a standard TVC proof envelope | Transitional, not PR #9 response-compatible |
| `/v1/verify` | Canonical nested `policy`, required non-empty `challenge`; returns `{result,proof}` | Implemented |

## VerificationResult mapping

| PR #9 field group | Rust v0.2 | Next phase |
|---|---|---|
| `network`, `chainHashNetwork` | Derives `chainHashNetwork` exclusively from the DLC chain hash, including Testnet4 | Add separate address-rendering `network` when address extraction lands |
| Contract type and collateral | Single/disjoint shape, enumerated/numeric distinction, total/party collateral | Preserve exact TS field names and unsupported-shape behavior |
| `outcomes` | Exact enumerated labels and both payouts with checked arithmetic | Numeric/disjoint support only if explicitly authorized |
| Oracle fields | Extracts event ID/key and validates announcement signature and nonce count | Exact error/null compatibility |
| CET/refund locktimes, fee rate | Locktimes implemented; fee field not exposed yet | Add fee and all exact TS fields |
| Funding/payout/change keys, scripts, addresses, inputs | Funding keys only | Reconstruct scripts, addresses, and validated prevouts |
| `contractId` | Sign-carried contract ID only | Compute final ID and compare Offer/Accept/Sign linkage |
| `transcriptHash` | Exact PR #9 domain-separated, labeled, length-prefixed algorithm | Golden cross-language vector |
| Funding transaction facts | Not implemented; explicitly incomplete | DDK-native reconstruction and byte/txid parity |
| CET/refund transaction facts | Not implemented; explicitly incomplete | DDK-native reconstruction and exact ordered outputs |
| Accepter adaptor/refund verification | Counts signatures but does not verify them; explicitly incomplete | Verify every adaptor proof and refund signature |
| Sign adaptor/refund/funding verification | Parses and counts Sign content; explicitly incomplete | Verify every offerer adaptor/refund/funding signature |
| `verificationStatus`, failures, incomplete | Fail-closed three-state result | Align every identifier and nullability with PR #9 |

## Policy mapping

| PR #9 policy/check | Rust v0.2 |
|---|---|
| `network` | Implemented against the offer chain hash, not a caller-selected rendering network |
| `expectedOraclePubkey` | Implemented against the signed announcement |
| `expectedTotalCollateralSats` | Implemented |
| Direct oracle event ID | Implemented |
| Event-ID preimage | Implemented with the intentional current formula `eventType//loanId//repaymentAddress//repaymentAmount` |
| Lender role, funding key, payout address | Next phase |
| Refund-pays-lender check | Next phase after refund reconstruction |
| CET/refund locktime expectations | Next phase |
| Exact lender outcome/payout policy | Next phase |
| Policy coverage/hash/digest and exact PR #9 attestation payload | Next phase |

## TVC compatibility

- One statically linked `x86_64-unknown-linux-musl` ELF is placed at `/tvc_app`.
- The process listens on `0.0.0.0:3000`; `GET /health` is the TVC health check.
- The application is deterministic and `enableEgress` is false.
- `/v1/verify` signs exact `qos_json` bytes using the QOS ephemeral P-256 key.
- The envelope is Turnkey's standard `{scheme,publicKey,proofPayload,signature}` form and is verified in tests with `turnkey_proofs 0.15.0`.
- The signed payload binds a canonical request digest, required non-empty caller challenge, verifier version, and complete Rust result. No timestamp is included so identical inputs remain deterministic; freshness is caller-controlled through a unique challenge.
- QOS runtime version `0.12.1` is separate from the pinned Rust SDK/QOS libraries (`turnkey_proofs 0.15.0`, `qos_* 0.14.1`).

Do not use a v0.2 `incomplete` result to authorize advancement of funds, minting, or settlement.
