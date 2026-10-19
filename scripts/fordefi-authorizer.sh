#!/usr/bin/env bash
# Create a Midnight authorizer vault in Fordefi and check it signs what the enclave accepts.
#
#   scripts/fordefi-authorizer.sh create <vault name>
#   scripts/fordefi-authorizer.sh check <vault id> <chain id> <originator>
#   scripts/fordefi-authorizer.sh verify <transaction id> <chain id> <originator>
#
# create makes an EVM vault and prints its id and address; the address is the deploy config's
# --lygos-authorizer. check has the vault sign MidnightAuthorization over an all-zero termsHash,
# which names no DLC, and recovers the signer with the enclave's code. verify re-reads a check
# that was left waiting for approval.
#
# Auth: FORDEFI_API_TOKEN, an API user in the Lygos org that owns the vault (never a lender's org).
# check also needs FORDEFI_SIGNING_KEY, the path to that API user's P-256 request-signing key, and
# the user's API Signer online. FORDEFI_API_URL defaults to https://api.fordefi.com.
# Keep the API token out of shell tracing and curl's process arguments.
set +x
set -euo pipefail

api=${FORDEFI_API_URL:-https://api.fordefi.com}
: "${FORDEFI_API_TOKEN:?set FORDEFI_API_TOKEN}"
zero_hash=0x0000000000000000000000000000000000000000000000000000000000000000

get() {
  curl -fsS "${api}$1" -H @- <<<"Authorization: Bearer ${FORDEFI_API_TOKEN}"
}

# Fordefi signs transaction requests: P-256 over "path|timestamp|body", base64 DER.
post() {
  local path=$1 body=$2 timestamp signature
  # Match Orange Grove's milliseconds, using macOS-compatible whole-second precision.
  timestamp=$(date +%s)000 || return
  signature=$(printf '%s|%s|%s' "${path}" "${timestamp}" "${body}" |
    openssl dgst -sha256 -sign "${FORDEFI_SIGNING_KEY:?set FORDEFI_SIGNING_KEY}" | openssl base64 -A) || return
  curl -sS "${api}${path}" -H @- \
    -H 'Content-Type: application/json' -H "x-timestamp: ${timestamp}" \
    -H "x-signature: ${signature}" -d "${body}" <<<"Authorization: Bearer ${FORDEFI_API_TOKEN}"
}

# Recover the signer of a signed authorization transaction and compare it with the vault.
recover() {
  local tx=$1 chain_id=$2 originator=$3 vault_id signature vault_address signer
  if [ "$(jq -r '.state' <<<"${tx}")" != "signed" ] && [ "$(jq -r '.state' <<<"${tx}")" != "completed" ]; then
    echo "transaction $(jq -r '.id' <<<"${tx}") is $(jq -r '.state' <<<"${tx}")" >&2
    echo "approve it in Fordefi, then: $0 verify $(jq -r '.id' <<<"${tx}") ${chain_id} ${originator}" >&2
    exit 1
  fi
  vault_id=$(jq -r '.vault.id' <<<"${tx}")
  signature=$(jq -r '.signatures[0].data' <<<"${tx}" | openssl base64 -d -A | od -An -tx1 -v | tr -d ' \n')
  vault_address=$(get "/api/v1/vaults/${vault_id}" | jq -r '.address' | tr '[:upper:]' '[:lower:]')
  signer=$(cargo run -q -p mint-attester --example authorizer_check -- \
    "${chain_id}" "${originator}" "${zero_hash}" "${signature}")
  echo "signature ${signature} (v byte 0x${signature: -2})"
  echo "vault  ${vault_address}"
  echo "signer ${signer}"
  if [ "${signer}" != "${vault_address}" ]; then
    echo "the enclave would not accept this vault's signature" >&2
    exit 1
  fi
  echo "ok: the enclave accepts this vault's authorizations"
}

case ${1:-} in
  create)
    name=${2:?vault name}
    vault=$(curl -fsS "${api}/api/v1/vaults" -H @- \
      -H 'Content-Type: application/json' \
      -d "$(jq -cn --arg name "${name}" '{name: $name, type: "evm"}')" <<<"Authorization: Bearer ${FORDEFI_API_TOKEN}")
    jq -r '"vault id \(.id)\naddress  \(.address)"' <<<"${vault}"
    ;;
  check)
    vault_id=${2:?vault id} chain_id=${3:?chain id} originator=${4:?originator}
    typed=$(jq -cn --argjson chainId "${chain_id}" --arg originator "${originator}" \
      --arg termsHash "${zero_hash}" '{
        types: {
          EIP712Domain: [
            {name: "name", type: "string"},
            {name: "version", type: "string"},
            {name: "chainId", type: "uint256"},
            {name: "verifyingContract", type: "address"}
          ],
          MidnightAuthorization: [{name: "termsHash", type: "bytes32"}]
        },
        primaryType: "MidnightAuthorization",
        domain: {name: "Lygos Midnight Authorizer", version: "1", chainId: $chainId,
          verifyingContract: $originator},
        message: {termsHash: $termsHash}
      }')
    body=$(jq -cn --arg vault "${vault_id}" --argjson chain "${chain_id}" --arg raw "${typed}" '{
      vault_id: $vault, type: "evm_message", signer_type: "api_signer", sign_mode: "auto",
      note: "Midnight authorizer check: all-zero termsHash, names no DLC",
      details: {type: "typed_message_type", chain: $chain, raw_data: $raw},
      wait_for_state: "signed", timeout: 50
    }')
    tx=$(post /api/v1/transactions/create-and-wait "${body}")
    if ! jq -e '.id' <<<"${tx}" >/dev/null; then
      echo "Fordefi refused the request: ${tx}" >&2
      exit 1
    fi
    recover "${tx}" "${chain_id}" "${originator}"
    ;;
  verify)
    tx_id=${2:?transaction id} chain_id=${3:?chain id} originator=${4:?originator}
    recover "$(get "/api/v1/transactions/${tx_id}")" "${chain_id}" "${originator}"
    ;;
  *)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
