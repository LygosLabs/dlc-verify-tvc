# Dependency audit ledger

The release gate runs the current RustSec database against `Cargo.lock`. On 2026-09-02, `cargo-audit 0.22.2` reported no vulnerabilities after pinning transitive `h2` to `0.4.16` and `rustls-webpki` to `0.103.13`.

Three upstream warnings remain visible and are not suppressed:

| Package | RustSec classification | Owner in this graph | Assessment |
|---|---|---|---|
| `serde_cbor 0.11.2` | Unmaintained | Turnkey `turnkey_proofs 0.15.0`, QOS, and AWS Nitro attestation dependencies | Required by the official proof verifier; track the next Turnkey proof release. |
| `rand 0.9.2` | Unsound with a custom logger that re-enters `rand::rng()` | `qos_crypto 0.14.1` | The verifier does not install such a logger or call the affected API directly; track the next QOS release. |
| `spin 0.10.0` | Yanked | Optional `multiexp -> std-shims` lockfile branch | Not present in the `x86_64-unknown-linux-musl` build graph, but retained by Cargo's optional dependency resolution. |

These warnings must be re-evaluated whenever the Turnkey/QOS or DDK dependency line changes. Do not add audit ignores without a written threat assessment and reviewer approval.
