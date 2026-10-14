#!/usr/bin/env bash
# Roll one mint attester environment forward to a freshly built image.
#
#   scripts/tvc-release.sh <env> <image url with @sha256 digest> <executable sha256>
#
# Reads tvc-configs/release.mint-attester.<env>.json. The deploy config named there is a template:
# its image and executable digest are overridden here and never committed back. Dev environments
# (autoLive: true) are approved and provisioned by the hosted operators listed in the release file
# and switched live; production stops after `deploy create` so YubiKey operators approve by hand.
#
# Auth: TVC_ORG_ID, TVC_API_KEY_PUBLIC, TVC_API_KEY_PRIVATE, or a logged-in ~/.config/turnkey.
set -euo pipefail

env_name=${1:?environment}
image=${2:?image url}
exec_digest=${3:?executable digest}

release_cfg="tvc-configs/release.mint-attester.${env_name}.json"
deploy_cfg=$(jq -r '.deployConfig' "${release_cfg}")
auto_live=$(jq -r '.autoLive' "${release_cfg}")
app_id=$(jq -r '.appId' "${deploy_cfg}")
health_url="https://app-${app_id}.app.turnkey.cloud/health"

if grep -q 'REPLACE_WITH' "${deploy_cfg}"; then
  echo "::notice::${deploy_cfg} still has placeholders; nothing deployed for ${env_name}"
  exit 0
fi

tvc_json() { tvc "$@" --non-interactive --message-format json; }

previous=$(tvc_json app status --app-id "${app_id}" | jq -r '.targetedDeploymentId // empty')

created=$(tvc_json deploy create \
  --config-file "${deploy_cfg}" \
  --pivot-image-url "${image}" \
  --expected-pivot-digest "${exec_digest}")
deploy_id=$(jq -r '.deploymentId' <<<"${created}")
manifest_id=$(tvc_json deploy status --deploy-id "${deploy_id}" | jq -r '.manifestId')
echo "created deployment ${deploy_id} (manifest ${manifest_id}) on app ${app_id}"

summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  {
    echo "## ${env_name}: $1"
    echo
    echo "- app \`${app_id}\`"
    echo "- deployment \`${deploy_id}\`"
    echo "- manifest \`${manifest_id}\`"
    echo "- image \`${image}\`"
    echo "- executable \`${exec_digest}\`"
  } >>"${GITHUB_STEP_SUMMARY}"
}

if [ "${auto_live}" != "true" ]; then
  echo "approve with two manifest-set operators, provision, then set live:"
  echo "  tvc deploy approve --deploy-id ${deploy_id} --serial <yubikey serial>"
  echo "  tvc deploy provision --deploy-id ${deploy_id} --operator-id <operator>"
  echo "  tvc app set-live-deploy --deploy-id ${deploy_id}"
  summary "created, awaiting operator approval"
  exit 0
fi

for op in $(jq -r '.approvers[]' "${release_cfg}"); do
  tvc_json deploy approve --deploy-id "${deploy_id}" --operator-id "${op}" --dangerous-skip-interactive >/dev/null
  echo "approved by ${op}"
done

# The enclave must boot and post its attestation before a share can be provisioned.
for op in $(jq -r '.provisioners[]' "${release_cfg}"); do
  for attempt in $(seq 1 30); do
    if tvc_json deploy provision --deploy-id "${deploy_id}" --operator-id "${op}" >/dev/null 2>"${TMPDIR:-/tmp}/provision.err"; then
      echo "provisioned by ${op}"
      break
    fi
    if [ "${attempt}" -eq 30 ]; then
      cat "${TMPDIR:-/tmp}/provision.err"
      echo "provisioning by ${op} did not succeed"
      exit 1
    fi
    sleep 20
  done
done

# Only switch traffic once every replica of the new deployment is up; an unhealthy enclave must
# never become live. The public health endpoint reflects the live deployment, so it is checked
# after the switch and the previous deployment is re-targeted if it fails.
replicas() {
  tvc_json app status --app-id "${app_id}" \
    | jq -r --arg id "${deploy_id}" '.deployments[] | select(.deploymentId == $id) | "\(.replicas.ready)/\(.replicas.desired)"'
}

for attempt in $(seq 1 60); do
  ready=$(replicas) || ready=""
  if [ "${ready}" = "3/3" ]; then
    echo "${deploy_id} replicas ready (${ready})"
    break
  fi
  if [ "${attempt}" -eq 60 ]; then
    echo "${deploy_id} replicas not ready after 10 minutes (${ready:-none}); live deployment ${previous:-none} untouched"
    exit 1
  fi
  sleep 10
done

tvc_json app set-live-deploy --deploy-id "${deploy_id}" >/dev/null
echo "live deployment set to ${deploy_id}"

for attempt in $(seq 1 12); do
  if curl --fail --silent --max-time 10 "${health_url}" >/dev/null; then
    echo "${health_url} ok"
    break
  fi
  if [ "${attempt}" -eq 12 ]; then
    echo "${health_url} not healthy 2 minutes after switching to ${deploy_id}"
    if [ -n "${previous}" ] && [ "${previous}" != "${deploy_id}" ]; then
      tvc_json app set-live-deploy --deploy-id "${previous}" >/dev/null
      echo "rolled live deployment back to ${previous}; ${deploy_id} left for inspection"
    else
      echo "::warning::no previous deployment to roll back to; ${deploy_id} is still live and needs manual attention"
    fi
    exit 1
  fi
  sleep 10
done

if [ -n "${previous}" ] && [ "${previous}" != "${deploy_id}" ]; then
  tvc_json deploy delete --deploy-id "${previous}" >/dev/null
  echo "deleted previous deployment ${previous} (restorable with tvc deploy restore)"
fi
summary "live"
