# DLC Verify PR #9 goldens

These complete JSON results were generated from `LygosLabs/dlc-verify` PR #9 commit `e46703e7adf21ce407e150d4f46ff455ba46fd57` using the matching public fixture in `../fixtures` and `network: "regtest"`.

- `pr9-sample.json` corresponds to `sample.json` without `signHex` or an expected oracle key.
- `pr9-matured.json` corresponds to `loan-matured-7932e4c2.json` without `signHex` or an expected oracle key.
- `pr9-signed.json` corresponds to `testnet-loan-118c9fc9.json`, including `signHex` and its fixture oracle key.

Tests compare the fully serialized Rust result with these files; they do not select only convenient fields. Regenerate them only from the frozen TypeScript commit, and review any difference as a compatibility change.
