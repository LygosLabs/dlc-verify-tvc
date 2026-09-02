# Frozen TypeScript differential check

The Rust tests compare their full serialized outputs with the checked-in PR #9 goldens. This script independently verifies that those goldens still equal the TypeScript implementation at commit `e46703e7adf21ce407e150d4f46ff455ba46fd57`.

Prepare a clean checkout of that exact commit, install its locked dependencies, build it, then run:

```sh
node scripts/differential/compare-pr9.mjs /path/to/frozen-pr9-checkout
```

The script is read-only. It compares every result field for all fixture cases and the complete signed policy response, and exits nonzero on any difference. Security hardenings for malformed or adversarial inputs intentionally live outside the frozen valid-result goldens.
