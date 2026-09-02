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

## Integration gate

Unit tests exercise policy validation, invocation replay protection, exact
App/Boot ephemeral-key matching, and prove malformed matching artifacts reach
the official Turnkey verifier. They do not positively establish complete Boot
Proof interoperability: a checked-in real Boot Proof fixture is not available
yet, so there is intentionally no mocked "successful attestation" test.

M3 requires a real Boot Proof captured by the exact App Proof public key from a
non-debug, egress-disabled TVC canary. Add that immutable fixture and its
trusted release policy, then test:

1. the official verifier accepts the App/Boot pair offline;
2. every proof-bound policy field passes;
3. one mutation per pinned field fails; and
4. Turnkey supplies proof-bound evidence for `pivotPath` and `enableEgress`, or
   the published threat model explicitly removes those values from the
   authorization claim for a documented cryptographic reason.

Do not use `verify_proof_bound_offline` alone to authorize funding, minting, or
settlement while the strict evidence error remains.
