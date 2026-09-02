# Offline TVC verifier client

This crate verifies a DLC verifier App Proof together with the Boot Proof for
that exact ephemeral key. It uses `turnkey_proofs = 0.15.0` for AWS Nitro,
COSE, QOS manifest approval, PCR, manifest commitment, and three-way
ephemeral-key verification. It then compares the proof-bound manifest and the
signed App Proof payload with a separately trusted Lygos release policy and
one-time invocation expectation.

`verify_proof_bound_offline` is practically usable for offline diagnostics and
release verification: it runs the official verifier and every check supported
by proof-bound evidence, then returns a result whose `authorizationGrade` field
is always `false`. It must not be used to authorize funding, minting, or
settlement unless an authenticated external assertion separately establishes
the deployment controls and binds them to this exact release.

`verify_offline` remains deliberately fail closed. It accepts a
`StrictVerificationPolicy` that separates the proof-bound
`TrustedReleasePolicy` from `TrustedDeploymentControls`. Turnkey's v0.15.0
`BootProof` and signed QOS manifest do not expose either:

- the deployment configuration's `pivotPath`; or
- the TVC application's top-level `enableEgress` setting.

The QOS manifest does bind the executable digest, pivot arguments, ingress and
client bridges, DNS configuration, debug mode, QOS namespace, PCR0-PCR3, QOS
commit, and manifest operator set/threshold. The client checks all of those,
rejects client bridges and DNS, and then returns the named
`UnsupportedEvidence { fields: ["pivotPath", "enableEgress"] }` error. Absence
of a client bridge or DNS entry is not misrepresented as proof that Turnkey's
separate application-level egress control is disabled.

## Live verification

Unit tests exercise policy validation, invocation replay protection, exact
App/Boot ephemeral-key matching, and prove malformed matching artifacts reach
the official Turnkey verifier. A real deployed release can be checked with the
`verify-live` binary:

```sh
cargo build --locked -p verifier-client --bin verify-live

TVC_ORG_ID=<organization-id> \
TVC_API_KEY_PUBLIC=<api-public-key> \
TVC_API_KEY_PRIVATE="$(your-secret-reader)" \
target/debug/verify-live \
  .tvc-evidence/request.json \
  .tvc-evidence/response.json \
  release/trusted-release-policy.json \
  release/release-manifest.json \
  .tvc-evidence/boot-proof.json
```

The command recomputes the canonical request digest, fetches the Boot Proof for
the exact App Proof ephemeral key, verifies the official Turnkey proof chain,
compares every proof-bound field with the trusted release policy, and queries
the authenticated control plane to compare the live app, deployment, image,
manifest IDs, QOS version, pivot configuration, health/ingress ports, egress,
and debug settings with the supplied release manifest. It also confirms that
strict offline verification fails with exactly the currently unsupported
proof-bound controls.

Build the binary before placing credentials in its environment so Cargo and
dependency build scripts never inherit them. Use a dedicated, least-privilege
read credential where Turnkey permissions allow, load its private material from
a secret store instead of command-line text, and clear it from the process
environment after the check. The ignored `.tvc-evidence/` directory is the
default location for live requests, responses, and Boot Proofs; do not commit
those artifacts when they contain confidential DLC or deployment material.

The optional Boot Proof output uses create-new semantics, mode `0600`, and is
written only after every proof and control-plane check passes. Remove or rename
an existing output before deliberately capturing a newer proof.

Do not use `verify_proof_bound_offline` alone to authorize funding, minting, or
settlement while `pivotPath` and `enableEgress` remain outside the
cryptographically bound proof evidence. An authenticated control-plane query is
useful operational corroboration, but it does not turn those fields into
authorization-grade evidence.
