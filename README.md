# Lygos DLC Verify for Turnkey Verifiable Cloud

Rust implementation of Lygos DLC Verify designed to run as a deterministic application inside a Turnkey Verifiable Cloud enclave.

The current v0.2 code is the TVC-compatible foundation. It strictly parses real DDK Offer/Accept/Sign messages, validates core structure and oracle announcements, evaluates the initial policy subset, and signs the result with the enclave's QOS-managed ephemeral key. It deliberately reports `incomplete` while transaction reconstruction and full adaptor/refund/funding signature verification are being implemented. See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the committed execution plan and [PARITY.md](PARITY.md) for the current parity ledger.

## Endpoints

- `GET /health` — TVC health check.
- `GET /version` — service/schema version and egress declaration.
- `POST /v1/verify` — canonical request and standard Turnkey App Proof response.
- `POST /api/verify` — transitional TypeScript-style input and unsigned bare result.
- `POST /api/verify-policy` — transitional TypeScript-style input with App Proof; its result schema is not yet PR #9-compatible.
- `GET /metrics` — request metadata only; raw DLC messages and loan terms are never logged.

The canonical body is:

```json
{
  "offer": "hex",
  "accept": "hex",
  "sign": "optional hex",
  "policy": {
    "network": "testnet4",
    "expectedOraclePubkey": "hex",
    "expectedTotalCollateralSats": "20000",
    "oracleEvent": { "expectedEventId": "repaid-..." }
  },
  "challenge": "required caller-generated unique value"
}
```

The response proof uses Turnkey's standard fields: `scheme`, `publicKey`, `proofPayload`, and `signature`. Consumers must verify the App Proof and its Boot Proof, compare the enclave manifest and executable digest to a separately trusted Lygos release, check the request digest and challenge, and act only on the result inside `proofPayload`.

## Development

```sh
make test
make lint
make run
```

Local and TVC runtime defaults are `0.0.0.0:3000`. Each decoded DLC message is limited to 1 MiB and the containing JSON request to 7 MiB; verification concurrency is capped at eight requests and request execution at 30 seconds. The CPU-bound verifier runs on Tokio's blocking pool. Proof-bearing endpoints reject a missing or empty challenge to prevent unintentional replay.

Build the StageX image:

```sh
make out/dlc-verify-tvc/index.json
```

The deterministic static binary is placed at `/tvc_app`. Start from `tvc-configs/*.example.json`, replace every placeholder, and deploy only an immutable GHCR digest. The initial application must retain `enableEgress: false`.
