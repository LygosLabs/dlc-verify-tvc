# DLC Verify PR #9 policy golden

`pr9-signed-policy.json` contains both the complete policy and complete result produced by `LygosLabs/dlc-verify` PR #9 commit `e46703e7adf21ce407e150d4f46ff455ba46fd57` for the fully signed public fixture.

The Rust test evaluates the embedded policy and compares the entire serialized result, including ordered checks, coverage/status/verdict, canonical policy hash, verification digest, attestation payload, and nested DLC verification result.
