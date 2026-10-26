# Dependency audit ledger

The release gate runs the current RustSec database against `Cargo.lock`. On 2026-09-02, `cargo-audit 0.22.2` reported no vulnerabilities after pinning transitive `h2` to `0.4.16` and `rustls-webpki` to `0.103.13`.

Three upstream warnings remain visible and are not suppressed:

| Package | RustSec classification | Owner in this graph | Assessment |
|---|---|---|---|
| `serde_cbor 0.11.2` | Unmaintained | Turnkey `turnkey_proofs 0.15.0`, QOS, and AWS Nitro attestation dependencies | Required by the official proof verifier; track the next Turnkey proof release. |
| `rand 0.9.2` | Unsound with a custom logger that re-enters `rand::rng()` | `qos_crypto 0.14.1` | The verifier does not install such a logger or call the affected API directly; track the next QOS release. |
| `spin 0.10.0` | Yanked | Optional `multiexp -> std-shims` lockfile branch | Not present in the `x86_64-unknown-linux-musl` build graph, but retained by Cargo's optional dependency resolution. |

## Ignored: RUSTSEC-2026-0387 (`crypto-bigint`)

On 2026-10-23 RustSec published RUSTSEC-2026-0387: operations in `crypto-bigint` before 0.7.6 that are meant to be constant-time (subtraction, zero counting, division, Montgomery multiplication) may branch on secret data, depending on compiler and CPU. `.cargo/audit.toml` ignores it, for this reason:

- **No fix is reachable.** `crypto-bigint 0.5.5` comes in through `elliptic-curve 0.13` (`p256`, `p384`, `k256`). The latest Turnkey releases, `qos_p256 0.15.1` and `turnkey_proofs 0.16.1`, still require `p256 ^0.13`, and the QOS runtime the enclaves boot under uses the same line.
- **Where secrets meet it.** `p256 0.13` scalar arithmetic is `crypto-bigint`'s, so ECDSA signing runs the affected operations on the nonce and the private key. In this repository that is the mint attester signing receipts with the quorum key, and DLC Verify signing App Proofs with the QOS ephemeral key.
- **Exposure.** Exploiting it means timing many signatures by the same key; a leak of nonce bits is as damaging as a leak of the key, since lattice attacks recover the key from it. RFC 6979 does not help, because the deterministic nonce changes with every message and goes through the same arithmetic. The mint attester signs only for a DLC the Midnight authorizer signed and a lock proven by SPV, so a caller cannot ask it for signatures at will. DLC Verify is the exposed one: it signs a proof for every request, which gives any caller an unbounded chosen-message timing oracle on its ephemeral key. What bounds that is the key's scope, not the attack: the key lives for one enclave boot and only vouches for DLC Verify results, which a consumer checks against the Boot Proof for that key.
- **What would remove it.** A Turnkey/QOS release on `p256 0.14` (`crypto-bigint >= 0.7.6`). Short of that, the mint attester could sign receipts with `p256 0.14` from the quorum key's secret bytes, which covers receipts but not QOS itself.

Revisit by 2026-12-31 or at the next Turnkey/QOS release, whichever comes first, and remove the ignore as soon as the graph allows.

These warnings must be re-evaluated whenever the Turnkey/QOS or DDK dependency line changes. Do not add audit ignores without a written threat assessment and reviewer approval.
