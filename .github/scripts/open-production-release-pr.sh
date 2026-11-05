#!/usr/bin/env bash
# Open the release PR only. Merging and enclave approval remain manual.
set -euo pipefail
: "${GH_REPO:?set GH_REPO to owner/repository}"
: "${GH_TOKEN:?set GH_TOKEN}"

existing=$(gh pr list --repo "${GH_REPO}" --base master --head dev --state open --json url --jq '.[0].url // empty')
if [ -n "${existing}" ]; then
  echo "Existing release PR: ${existing}"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf 'Existing production release PR: %s\n' "${existing}" >>"${GITHUB_STEP_SUMMARY}"
  fi
  exit 0
fi

ahead=$(gh api "repos/${GH_REPO}/compare/master...dev" --jq '.ahead_by')
if [ "${ahead}" -eq 0 ]; then
  echo "No dev commits to release."
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo 'No dev commits to release.' >>"${GITHUB_STEP_SUMMARY}"
  fi
  exit 0
fi

body_file=$(mktemp)
trap 'rm -f "${body_file}"' EXIT
cat >"${body_file}" <<EOF
## Summary

Promote the current dev branch to master for a production release. Review the [full comparison](https://github.com/${GH_REPO}/compare/master...dev) and confirm staging/testnet4 QA before merging. This PR follows the dev branch; further pushes to dev change its contents.

## Release checklist

- [ ] Review changes and required CI checks; confirm staging/testnet4 QA.
- [ ] Verify the production app/configuration and restricted production GitHub environment credentials are ready; no unresolved placeholders.
- [ ] Merge after review. The stagex workflow creates a pending mainnet deployment for relevant changes; a green creation job does not mean it is live.
- [ ] Two YubiKey operators independently review and approve the resulting manifest, then verify attestation and provision their key shares.
- [ ] Confirm all replicas are ready, switch traffic, and verify health. Keep the previous deployment available for rollback.

For a documentation-only release, the stagex path filter may skip the build/deployment. Run stagex manually on master if a deployment is required.

[Production setup and release runbook](https://github.com/LygosLabs/morpho-midnight-planning/blob/master/docs/production-tvc-yubikey-setup.md)
EOF
url=$(gh pr create --repo "${GH_REPO}" --base master --head dev --title 'release: promote dev to production' --body-file "${body_file}")
echo "Created release PR: ${url}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  printf 'Production release PR: %s\n\nIf GitHub requests it, select Approve workflows to run on the PR. Review CI and QA before merging. YubiKey approval remains manual.\n' "${url}" >>"${GITHUB_STEP_SUMMARY}"
fi
