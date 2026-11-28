#!/usr/bin/env bash
# Shared by the release script and its offline regression tests.
# Caller provides tvc_json (the CLI with noninteractive JSON output).
wait_for_live_deployment() {
  local app_id=$1 deploy_id=$2 health_url=$3
  local attempt apps runtime body
  for attempt in $(seq 1 30); do
    # Both API metadata and cluster routing must have converged. A 200 from the previous
    # deployment alone does not prove that this release is serving traffic.
    if apps=$(tvc_json app list) \
      && jq -e --arg app "${app_id}" --arg deploy "${deploy_id}" \
        'any(.apps[]; .id == $app and .liveDeploymentId == $deploy)' <<<"${apps}" >/dev/null \
      && runtime=$(tvc_json deploy get-status --deploy-id "${deploy_id}") \
      && jq -e --arg app "${app_id}" --arg deploy "${deploy_id}" \
        '.appId == $app and .deploymentId == $deploy and .isTargeted == true
         and .replicas.desired > 0 and .replicas.ready == .replicas.desired' <<<"${runtime}" >/dev/null \
      && body=$(curl --fail --silent --show-error --max-time 10 "${health_url}") \
      && jq -e '.status == "healthy"' <<<"${body}" >/dev/null; then
      echo "${deploy_id} is live, all replicas are ready, and ${health_url} is healthy"
      return 0
    fi
    echo "waiting for ${deploy_id} routing, replicas, and public health (${attempt}/30)"
    if [ "${attempt}" -lt 30 ]; then sleep 10; fi
  done
  return 1
}
