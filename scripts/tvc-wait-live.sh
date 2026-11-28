#!/usr/bin/env bash
# Shared by the release script and its offline regression tests.
# Caller provides tvc_json (the CLI with noninteractive JSON output).
wait_for_live_deployment() {
  local app_id=$1 deploy_id=$2 health_url=$3
  local attempt apps runtime body last=""
  for attempt in $(seq 1 30); do
    # Both API metadata and cluster routing must have converged. A 200 from the previous
    # deployment alone does not prove that this release is serving traffic. Each check records
    # what it saw, so a timeout says which one never passed.
    if ! apps=$(tvc_json app list); then
      last="tvc app list failed"
    elif ! jq -e --arg app "${app_id}" --arg deploy "${deploy_id}" \
        'any(.apps[]; .id == $app and .liveDeploymentId == $deploy)' <<<"${apps}" >/dev/null; then
      last="Turnkey reports live deployment $(jq -r --arg app "${app_id}" \
        'first(.apps[] | select(.id == $app) | .liveDeploymentId // "none") // "none (app missing)"' \
        <<<"${apps}" 2>/dev/null || echo "unknown (unparseable app list)")"
    elif ! runtime=$(tvc_json deploy get-status --deploy-id "${deploy_id}"); then
      last="tvc deploy get-status failed"
    elif ! jq -e --arg app "${app_id}" --arg deploy "${deploy_id}" \
        '.appId == $app and .deploymentId == $deploy and .isTargeted == true
         and .replicas.desired > 0 and .replicas.ready == .replicas.desired' <<<"${runtime}" >/dev/null; then
      last="runtime status $(jq -c '{appId, deploymentId, isTargeted, replicas}' <<<"${runtime}" 2>/dev/null \
        || echo "unparseable: ${runtime:0:200}")"
    elif ! body=$(curl --fail --silent --show-error --max-time 10 "${health_url}" 2>&1); then
      last="health request failed: ${body:0:200}"
    elif ! jq -e '.status == "healthy"' <<<"${body}" >/dev/null 2>&1; then
      last="health body ${body:0:200}"
    else
      echo "${deploy_id} is live, all replicas are ready, and ${health_url} is healthy"
      return 0
    fi
    echo "waiting for ${deploy_id} routing, replicas, and public health (${attempt}/30): ${last}"
    if [ "${attempt}" -lt 30 ]; then sleep 10; fi
  done
  echo "${deploy_id} verification timed out; last state seen: ${last}"
  return 1
}
