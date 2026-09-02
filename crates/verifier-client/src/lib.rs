//! Offline verification of a DLC verifier App Proof against its exact TVC
//! Boot Proof and an independently trusted release policy.
//!
//! [`verify_offline`] is intentionally fail closed. Turnkey's proof schema at
//! version 0.15.0 does not expose the deployment `pivotPath` or the TVC
//! application's `enableEgress` setting, so strict authorization-grade
//! verification ends with [`VerificationError::UnsupportedEvidence`] after
//! all proof-bound evidence has been checked. This prevents callers from
//! confusing manifest-local network configuration with the separate TVC
//! application egress control.

use std::{collections::BTreeSet, fmt, panic::AssertUnwindSafe};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qos_core::protocol::services::boot::{
    BridgeConfig, VersionedManifest, VersionedManifestEnvelope,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use turnkey_client::generated::external::data::v1::{AppProof, BootProof};

/// Evidence fields required by the release policy but absent from Turnkey's
/// v0.15.0 Boot Proof and signed QOS manifest.
pub const UNSUPPORTED_STRICT_EVIDENCE: [&str; 2] = ["pivotPath", "enableEgress"];

/// Independently trusted identity and configuration for one released binary.
///
/// Values in this structure must come from a trusted Lygos release channel,
/// never from the Boot Proof being verified.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedReleasePolicy {
    /// Turnkey deployment label expected in Boot Proof metadata.
    pub deployment_label: String,
    /// Turnkey application identity expected in Boot Proof metadata.
    pub enclave_app: String,
    /// Turnkey owner identity expected in Boot Proof metadata.
    pub owner: String,
    /// Expected Turnkey QOS manifest schema label (`v0`, `v1`, or `v2`).
    pub manifest_schema_version: String,
    /// QOS manifest version reported by the Turnkey Boot Proof API.
    pub qos_manifest_version: String,
    /// Exact QOS manifest hash, encoded as lowercase hex.
    pub manifest_hash: String,
    /// Cryptographically bound QOS namespace name.
    pub namespace_name: String,
    /// Cryptographically bound QOS namespace anti-downgrade nonce.
    pub namespace_nonce: u32,
    /// Exact QOS source commit embedded in the manifest.
    pub qos_commit: String,
    /// SHA-256 digest of the executable pivot, encoded as lowercase hex.
    pub executable_digest: String,
    /// Expected Nitro PCR values from the approved manifest.
    pub pcrs: TrustedPcrs,
    /// Exact approved manifest operator set and threshold.
    pub manifest_operators: TrustedOperatorSet,
    /// Exact arguments passed to the pivot executable.
    pub pivot_args: Vec<String>,
    /// Exact ingress bridge configuration. Client bridges are always rejected.
    pub ingress: Vec<TrustedIngress>,
}

/// Trusted deployment controls that are required for strict authorization but
/// are not carried by Turnkey's v0.15.0 proof artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedDeploymentControls {
    /// Expected deployment extraction path. This is retained as a mandatory
    /// policy field even though Turnkey v0.15.0 cannot prove it.
    pub pivot_path: String,
    /// Must be `false`. This is retained as a mandatory policy field even
    /// though Turnkey v0.15.0 cannot prove application-level egress state.
    pub enable_egress: bool,
}

/// Complete strict policy: proof-bound release identity plus external TVC
/// deployment controls.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StrictVerificationPolicy {
    /// Identity and configuration bound by the Boot Proof and QOS manifest.
    pub release: TrustedReleasePolicy,
    /// Required deployment controls absent from the proof schema.
    pub deployment_controls: TrustedDeploymentControls,
}

/// Expected Nitro PCR0 through PCR3.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedPcrs {
    /// Expected PCR0 in lowercase hex.
    pub pcr0: String,
    /// Expected PCR1 in lowercase hex.
    pub pcr1: String,
    /// Expected PCR2 in lowercase hex.
    pub pcr2: String,
    /// Expected PCR3 in lowercase hex.
    pub pcr3: String,
}

/// Exact manifest approval policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedOperatorSet {
    /// Required number of distinct valid manifest approvals.
    pub threshold: u32,
    /// Exact set of approved operator aliases and composite public keys.
    pub members: Vec<TrustedOperator>,
}

/// One trusted manifest operator.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedOperator {
    /// Human-readable alias that is itself committed by the manifest.
    pub alias: String,
    /// QOS composite public key in lowercase hex.
    pub public_key: String,
}

/// One expected inbound bridge.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedIngress {
    /// TCP port exposed through the bridge.
    pub port: u16,
    /// Pivot-side IPv4 listen address.
    pub host: String,
}

/// Per-request facts that prevent an otherwise valid proof from being replayed
/// for another request or caller challenge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedInvocation {
    /// Expected application proof type.
    pub proof_type: String,
    /// Expected proof payload schema version.
    pub schema_version: String,
    /// Expected verifier release version.
    pub verifier_version: String,
    /// Expected canonical request digest in lowercase hex.
    pub request_digest: String,
    /// Exact one-time caller challenge.
    pub challenge: String,
}

/// Facts recovered only after all evidence available in the official proof
/// types has passed verification.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBoundVerification {
    /// Always `false`: proof-bound verification alone does not establish the
    /// external `pivotPath` and top-level `enableEgress` controls.
    pub authorization_grade: bool,
    /// Verified application proof payload, including the signed DLC result.
    pub proof_payload: Value,
    /// Verified ephemeral QOS composite public key.
    pub ephemeral_public_key: String,
    /// Verified manifest hash.
    pub manifest_hash: String,
    /// Verified executable digest.
    pub executable_digest: String,
    /// Manifest schema used by the proof.
    pub manifest_schema_version: String,
}

/// Named offline verification failures.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    /// The trusted policy itself requests an unsafe configuration.
    InvalidPolicy {
        /// Stable policy field name.
        field: &'static str,
        /// Reason the policy is invalid.
        detail: String,
    },
    /// App and Boot Proof ephemeral keys are invalid or differ.
    EphemeralKeyMismatch(String),
    /// Turnkey's official proof verification rejected the pair.
    OfficialProofVerification(String),
    /// Turnkey's official verifier panicked while processing untrusted input.
    OfficialVerifierPanicked,
    /// A base64 manifest artifact could not be decoded.
    ManifestArtifactDecode {
        /// Stable artifact name.
        artifact: &'static str,
        /// Decoder failure detail.
        detail: String,
    },
    /// A decoded QOS manifest artifact was malformed or unsupported.
    ManifestParse {
        /// Stable artifact name.
        artifact: &'static str,
        /// Parser failure detail.
        detail: String,
    },
    /// A proof-bound or API metadata value differs from trusted policy.
    PolicyMismatch {
        /// Stable release-policy field name.
        field: &'static str,
        /// Trusted expected representation.
        expected: String,
        /// Evidence-derived actual representation.
        actual: String,
    },
    /// The signed application payload is not valid JSON.
    AppPayloadParse(String),
    /// A required application payload field is missing or differs.
    AppPayloadMismatch {
        /// Stable signed-payload field name.
        field: &'static str,
        /// Invocation-bound expected representation.
        expected: String,
        /// Signed actual representation.
        actual: String,
    },
    /// Strict policy requires evidence absent from the official proof schema.
    UnsupportedEvidence {
        /// Stable names of fields the proof schema cannot establish.
        fields: Vec<&'static str>,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy { field, detail } => {
                write!(formatter, "invalid trusted policy field {field}: {detail}")
            }
            Self::EphemeralKeyMismatch(detail) => {
                write!(formatter, "ephemeral key mismatch: {detail}")
            }
            Self::OfficialProofVerification(detail) => {
                write!(
                    formatter,
                    "official Turnkey proof verification failed: {detail}"
                )
            }
            Self::OfficialVerifierPanicked => {
                write!(formatter, "official Turnkey proof verifier panicked")
            }
            Self::ManifestArtifactDecode { artifact, detail } => {
                write!(formatter, "failed to decode {artifact}: {detail}")
            }
            Self::ManifestParse { artifact, detail } => {
                write!(formatter, "failed to parse {artifact}: {detail}")
            }
            Self::PolicyMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "release policy mismatch for {field}: expected {expected}, got {actual}"
            ),
            Self::AppPayloadParse(detail) => {
                write!(formatter, "failed to parse App Proof payload: {detail}")
            }
            Self::AppPayloadMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "App Proof payload mismatch for {field}: expected {expected}, got {actual}"
            ),
            Self::UnsupportedEvidence { fields } => write!(
                formatter,
                "strict verification cannot prove fields absent from Turnkey proof schema: {}",
                fields.join(", ")
            ),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Verify an App Proof and its exact Boot Proof offline against independently
/// trusted release and request policy.
///
/// This performs Turnkey's official AWS Nitro, COSE, QOS manifest, approval,
/// PCR, live-key commitment, and three-way ephemeral-key verification first.
/// It then independently pins the release and invocation fields exposed by the
/// official types. Finally it fails with
/// [`VerificationError::UnsupportedEvidence`] because `pivotPath` and
/// application-level `enableEgress` are not proof-bound in v0.15.0.
///
/// # Errors
///
/// Returns a named failure whenever cryptographic verification, release
/// policy, invocation binding, or evidence completeness fails.
pub fn verify_offline(
    app_proof: &AppProof,
    boot_proof: &BootProof,
    policy: &StrictVerificationPolicy,
    invocation: &ExpectedInvocation,
) -> Result<ProofBoundVerification, VerificationError> {
    validate_deployment_controls(&policy.deployment_controls)?;
    let _evidence = verify_proof_bound_offline(app_proof, boot_proof, &policy.release, invocation)?;

    Err(VerificationError::UnsupportedEvidence {
        fields: UNSUPPORTED_STRICT_EVIDENCE.to_vec(),
    })
}

/// Verify every fact cryptographically bound by Turnkey's v0.15.0 App Proof,
/// Boot Proof, and QOS manifest, without claiming external deployment-control
/// verification.
///
/// The returned [`ProofBoundVerification::authorization_grade`] is always
/// `false`. Callers must not authorize funding, minting, or settlement from
/// this result unless `pivotPath` and the top-level TVC `enableEgress` setting
/// have been separately established through an authenticated control-plane
/// assertion with a documented binding to this exact manifest/release.
///
/// # Errors
///
/// Returns a named failure whenever official cryptographic verification,
/// release policy, invocation binding, or artifact decoding fails.
pub fn verify_proof_bound_offline(
    app_proof: &AppProof,
    boot_proof: &BootProof,
    release: &TrustedReleasePolicy,
    invocation: &ExpectedInvocation,
) -> Result<ProofBoundVerification, VerificationError> {
    validate_release_policy(release)?;
    validate_invocation(invocation)?;
    verify_ephemeral_key_fields(app_proof, boot_proof)?;

    let official_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        turnkey_proofs::verify(app_proof, boot_proof)
    }))
    .map_err(|_| VerificationError::OfficialVerifierPanicked)?;
    official_result
        .map_err(|error| VerificationError::OfficialProofVerification(error.to_string()))?;

    verify_proof_bound_release(app_proof, boot_proof, release, invocation)
}

fn validate_deployment_controls(
    controls: &TrustedDeploymentControls,
) -> Result<(), VerificationError> {
    if controls.enable_egress {
        return Err(VerificationError::InvalidPolicy {
            field: "enableEgress",
            detail: "authorization-grade DLC verification requires egress to be disabled".into(),
        });
    }
    if controls.pivot_path != "/tvc_app" {
        return Err(VerificationError::InvalidPolicy {
            field: "pivotPath",
            detail: "the supported release path is exactly /tvc_app".into(),
        });
    }
    Ok(())
}

fn validate_release_policy(release: &TrustedReleasePolicy) -> Result<(), VerificationError> {
    if release.manifest_operators.threshold == 0 {
        return Err(VerificationError::InvalidPolicy {
            field: "manifestOperators.threshold",
            detail: "threshold must be non-zero".into(),
        });
    }
    if release.manifest_operators.threshold as usize > release.manifest_operators.members.len() {
        return Err(VerificationError::InvalidPolicy {
            field: "manifestOperators.threshold",
            detail: "threshold exceeds member count".into(),
        });
    }

    let operators = trusted_operators(&release.manifest_operators.members)?;
    let aliases = release
        .manifest_operators
        .members
        .iter()
        .map(|member| member.alias.as_str())
        .collect::<BTreeSet<_>>();
    let public_keys = release
        .manifest_operators
        .members
        .iter()
        .map(|member| member.public_key.as_str())
        .collect::<BTreeSet<_>>();
    if operators.len() != release.manifest_operators.members.len()
        || aliases.len() != release.manifest_operators.members.len()
        || public_keys.len() != release.manifest_operators.members.len()
    {
        return Err(VerificationError::InvalidPolicy {
            field: "manifestOperators.members",
            detail: "operator aliases and public keys must be unique".into(),
        });
    }
    decode_policy_hex_len("manifestHash", &release.manifest_hash, 32)?;
    decode_policy_hex_len("executableDigest", &release.executable_digest, 32)?;
    decode_policy_hex_len("pcrs.pcr0", &release.pcrs.pcr0, 48)?;
    decode_policy_hex_len("pcrs.pcr1", &release.pcrs.pcr1, 48)?;
    decode_policy_hex_len("pcrs.pcr2", &release.pcrs.pcr2, 48)?;
    decode_policy_hex_len("pcrs.pcr3", &release.pcrs.pcr3, 48)?;
    if !matches!(release.manifest_schema_version.as_str(), "v0" | "v1" | "v2") {
        return Err(VerificationError::InvalidPolicy {
            field: "manifestSchemaVersion",
            detail: "expected v0, v1, or v2".into(),
        });
    }
    if release.qos_manifest_version.trim().is_empty() {
        return Err(VerificationError::InvalidPolicy {
            field: "qosManifestVersion",
            detail: "version must not be empty".into(),
        });
    }
    let ingress = release.ingress.iter().collect::<BTreeSet<_>>();
    if ingress.len() != release.ingress.len() {
        return Err(VerificationError::InvalidPolicy {
            field: "ingress",
            detail: "ingress entries must be unique".into(),
        });
    }
    Ok(())
}

fn validate_invocation(invocation: &ExpectedInvocation) -> Result<(), VerificationError> {
    for (field, value) in [
        ("proofType", invocation.proof_type.as_str()),
        ("schemaVersion", invocation.schema_version.as_str()),
        ("verifierVersion", invocation.verifier_version.as_str()),
        ("challenge", invocation.challenge.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(VerificationError::InvalidPolicy {
                field,
                detail: "value must not be empty".into(),
            });
        }
    }
    decode_policy_hex_len("requestDigest", &invocation.request_digest, 32)?;
    Ok(())
}

fn verify_ephemeral_key_fields(
    app_proof: &AppProof,
    boot_proof: &BootProof,
) -> Result<(), VerificationError> {
    let app_key = qos_hex::decode(&app_proof.public_key).map_err(|error| {
        VerificationError::EphemeralKeyMismatch(format!(
            "App Proof public key is invalid hex: {error:?}"
        ))
    })?;
    let boot_key = qos_hex::decode(&boot_proof.ephemeral_public_key_hex).map_err(|error| {
        VerificationError::EphemeralKeyMismatch(format!(
            "Boot Proof public key is invalid hex: {error:?}"
        ))
    })?;
    if app_key.len() != turnkey_proofs::EXPECTED_EPHEMERAL_PUBLIC_KEY_LENGTH {
        return Err(VerificationError::EphemeralKeyMismatch(format!(
            "App Proof key has {} bytes, expected {}",
            app_key.len(),
            turnkey_proofs::EXPECTED_EPHEMERAL_PUBLIC_KEY_LENGTH
        )));
    }
    if app_key != boot_key {
        return Err(VerificationError::EphemeralKeyMismatch(
            "App Proof and exact Boot Proof name different keys".into(),
        ));
    }
    Ok(())
}

fn verify_proof_bound_release(
    app_proof: &AppProof,
    boot_proof: &BootProof,
    release: &TrustedReleasePolicy,
    invocation: &ExpectedInvocation,
) -> Result<ProofBoundVerification, VerificationError> {
    expect_equal(
        "deploymentLabel",
        &release.deployment_label,
        &boot_proof.deployment_label,
    )?;
    expect_equal("enclaveApp", &release.enclave_app, &boot_proof.enclave_app)?;
    expect_equal("owner", &release.owner, &boot_proof.owner)?;
    expect_equal(
        "qosManifestVersion",
        &release.qos_manifest_version,
        boot_proof
            .qos_manifest_version
            .as_deref()
            .unwrap_or("<missing>"),
    )?;

    let standalone = decode_manifest(&boot_proof.qos_manifest_b64, "qosManifest")?;
    let envelope =
        decode_manifest_envelope(&boot_proof.qos_manifest_envelope_b64, "qosManifestEnvelope")?;
    let envelope_hash = qos_hex::encode(&envelope.manifest_hash());
    expect_equal("manifestHash", &release.manifest_hash, &envelope_hash)?;
    expect_equal(
        "standaloneManifestHash",
        &envelope_hash,
        &qos_hex::encode(&standalone.manifest_hash()),
    )?;

    let manifest = envelope.manifest();
    expect_equal(
        "manifestSchemaVersion",
        &release.manifest_schema_version,
        manifest.version_label(),
    )?;
    expect_equal(
        "namespace.name",
        &release.namespace_name,
        &manifest.namespace().name,
    )?;
    expect_u32(
        "namespace.nonce",
        release.namespace_nonce,
        manifest.namespace().nonce,
    )?;
    expect_equal(
        "qosCommit",
        &release.qos_commit,
        &manifest.enclave().qos_commit,
    )?;
    expect_equal(
        "executableDigest",
        &release.executable_digest,
        &qos_hex::encode(manifest.pivot_hash()),
    )?;
    expect_bytes("pcr0", &release.pcrs.pcr0, &manifest.enclave().pcr0)?;
    expect_bytes("pcr1", &release.pcrs.pcr1, &manifest.enclave().pcr1)?;
    expect_bytes("pcr2", &release.pcrs.pcr2, &manifest.enclave().pcr2)?;
    expect_bytes("pcr3", &release.pcrs.pcr3, &manifest.enclave().pcr3)?;

    let expected_operators = trusted_operators(&release.manifest_operators.members)?;
    let actual_operators = manifest
        .manifest_set()
        .members
        .iter()
        .map(|member| (member.alias.clone(), qos_hex::encode(&member.pub_key)))
        .collect::<BTreeSet<_>>();
    if expected_operators != actual_operators {
        return Err(VerificationError::PolicyMismatch {
            field: "manifestOperators.members",
            expected: format!("{expected_operators:?}"),
            actual: format!("{actual_operators:?}"),
        });
    }
    expect_u32(
        "manifestOperators.threshold",
        release.manifest_operators.threshold,
        manifest.manifest_set().threshold,
    )?;
    if manifest.debug_mode() {
        return Err(VerificationError::PolicyMismatch {
            field: "debugMode",
            expected: "false".into(),
            actual: "true".into(),
        });
    }
    if manifest.args() != release.pivot_args {
        return Err(VerificationError::PolicyMismatch {
            field: "pivotArgs",
            expected: format!("{:?}", release.pivot_args),
            actual: format!("{:?}", manifest.args()),
        });
    }

    let mut ingress = BTreeSet::new();
    let mut server_bridge_count = 0_usize;
    for bridge in manifest.bridge_config() {
        match bridge {
            BridgeConfig::Server { port, host } => {
                server_bridge_count += 1;
                ingress.insert(TrustedIngress {
                    port: *port,
                    host: host.clone(),
                });
            }
            BridgeConfig::Client { .. } => {
                return Err(VerificationError::PolicyMismatch {
                    field: "bridgeConfig",
                    expected: "server bridges only".into(),
                    actual: "contains a client/egress bridge".into(),
                });
            }
        }
    }
    let expected_ingress = release.ingress.iter().cloned().collect::<BTreeSet<_>>();
    if ingress != expected_ingress || server_bridge_count != release.ingress.len() {
        return Err(VerificationError::PolicyMismatch {
            field: "ingress",
            expected: format!("{expected_ingress:?}"),
            actual: format!("{ingress:?}"),
        });
    }
    if manifest.dns_config().is_some() {
        return Err(VerificationError::PolicyMismatch {
            field: "dns",
            expected: "absent for an egress-free verifier".into(),
            actual: "configured".into(),
        });
    }

    let proof_payload = verify_invocation_payload(&app_proof.proof_payload, invocation)?;

    Ok(ProofBoundVerification {
        authorization_grade: false,
        proof_payload,
        ephemeral_public_key: app_proof.public_key.to_ascii_lowercase(),
        manifest_hash: envelope_hash,
        executable_digest: qos_hex::encode(manifest.pivot_hash()),
        manifest_schema_version: manifest.version_label().into(),
    })
}

fn verify_invocation_payload(
    payload: &str,
    expected: &ExpectedInvocation,
) -> Result<Value, VerificationError> {
    let value: Value = serde_json::from_str(payload)
        .map_err(|error| VerificationError::AppPayloadParse(error.to_string()))?;
    expect_payload_field(&value, "proofType", &expected.proof_type)?;
    expect_payload_field(&value, "schemaVersion", &expected.schema_version)?;
    expect_payload_field(&value, "verifierVersion", &expected.verifier_version)?;
    expect_payload_field(&value, "requestDigest", &expected.request_digest)?;
    expect_payload_field(&value, "challenge", &expected.challenge)?;
    if value.get("result").is_none() {
        return Err(VerificationError::AppPayloadMismatch {
            field: "result",
            expected: "present".into(),
            actual: "missing".into(),
        });
    }
    Ok(value)
}

fn expect_payload_field(
    value: &Value,
    field: &'static str,
    expected: &str,
) -> Result<(), VerificationError> {
    let actual = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    if actual != expected {
        return Err(VerificationError::AppPayloadMismatch {
            field,
            expected: expected.into(),
            actual: actual.into(),
        });
    }
    Ok(())
}

fn decode_manifest(
    encoded: &str,
    artifact: &'static str,
) -> Result<VersionedManifest, VerificationError> {
    let bytes = decode_base64(encoded, artifact)?;
    VersionedManifest::try_from_slice_compat(&bytes).map_err(|error| {
        VerificationError::ManifestParse {
            artifact,
            detail: error.to_string(),
        }
    })
}

fn decode_manifest_envelope(
    encoded: &str,
    artifact: &'static str,
) -> Result<VersionedManifestEnvelope, VerificationError> {
    let bytes = decode_base64(encoded, artifact)?;
    VersionedManifestEnvelope::try_from_slice_compat(&bytes).map_err(|error| {
        VerificationError::ManifestParse {
            artifact,
            detail: error.to_string(),
        }
    })
}

fn decode_base64(encoded: &str, artifact: &'static str) -> Result<Vec<u8>, VerificationError> {
    STANDARD
        .decode(encoded)
        .map_err(|error| VerificationError::ManifestArtifactDecode {
            artifact,
            detail: error.to_string(),
        })
}

fn trusted_operators(
    members: &[TrustedOperator],
) -> Result<BTreeSet<(String, String)>, VerificationError> {
    members
        .iter()
        .map(|member| {
            decode_policy_hex_len(
                "manifestOperators.members.publicKey",
                &member.public_key,
                turnkey_proofs::EXPECTED_EPHEMERAL_PUBLIC_KEY_LENGTH,
            )?;
            Ok((member.alias.clone(), member.public_key.clone()))
        })
        .collect()
}

fn decode_policy_hex_len(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, VerificationError> {
    let decoded = decode_policy_hex(field, value)?;
    if decoded.len() != expected_len {
        return Err(VerificationError::InvalidPolicy {
            field,
            detail: format!(
                "decoded value has {} bytes, expected {expected_len}",
                decoded.len()
            ),
        });
    }
    Ok(decoded)
}

fn decode_policy_hex(field: &'static str, value: &str) -> Result<Vec<u8>, VerificationError> {
    if value != value.to_ascii_lowercase() {
        return Err(VerificationError::InvalidPolicy {
            field,
            detail: "hex must be lowercase".into(),
        });
    }
    qos_hex::decode(value).map_err(|error| VerificationError::InvalidPolicy {
        field,
        detail: format!("invalid hex: {error:?}"),
    })
}

fn expect_bytes(
    field: &'static str,
    expected_hex: &str,
    actual: &[u8],
) -> Result<(), VerificationError> {
    let expected = decode_policy_hex(field, expected_hex)?;
    if expected != actual {
        return Err(VerificationError::PolicyMismatch {
            field,
            expected: expected_hex.into(),
            actual: qos_hex::encode(actual),
        });
    }
    Ok(())
}

fn expect_equal(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), VerificationError> {
    if expected != actual {
        return Err(VerificationError::PolicyMismatch {
            field,
            expected: expected.into(),
            actual: actual.into(),
        });
    }
    Ok(())
}

fn expect_u32(field: &'static str, expected: u32, actual: u32) -> Result<(), VerificationError> {
    if expected != actual {
        return Err(VerificationError::PolicyMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TrustedReleasePolicy {
        TrustedReleasePolicy {
            deployment_label: "production-1".into(),
            enclave_app: "lygos-dlc-verify".into(),
            owner: "lygos".into(),
            manifest_schema_version: "v2".into(),
            qos_manifest_version: "0.12.1".into(),
            manifest_hash: "11".repeat(32),
            namespace_name: "lygos-dlc-verify".into(),
            namespace_nonce: 7,
            qos_commit: "qos-commit".into(),
            executable_digest: "22".repeat(32),
            pcrs: TrustedPcrs {
                pcr0: "30".repeat(48),
                pcr1: "31".repeat(48),
                pcr2: "32".repeat(48),
                pcr3: "33".repeat(48),
            },
            manifest_operators: TrustedOperatorSet {
                threshold: 2,
                members: vec![
                    TrustedOperator {
                        alias: "operator-a".into(),
                        public_key: "41".repeat(130),
                    },
                    TrustedOperator {
                        alias: "operator-b".into(),
                        public_key: "42".repeat(130),
                    },
                    TrustedOperator {
                        alias: "operator-c".into(),
                        public_key: "43".repeat(130),
                    },
                ],
            },
            pivot_args: vec![
                "--host".into(),
                "0.0.0.0".into(),
                "--port".into(),
                "3000".into(),
            ],
            ingress: vec![TrustedIngress {
                port: 3000,
                host: "0.0.0.0".into(),
            }],
        }
    }

    fn controls() -> TrustedDeploymentControls {
        TrustedDeploymentControls {
            pivot_path: "/tvc_app".into(),
            enable_egress: false,
        }
    }

    fn strict_policy() -> StrictVerificationPolicy {
        StrictVerificationPolicy {
            release: policy(),
            deployment_controls: controls(),
        }
    }

    fn invocation() -> ExpectedInvocation {
        ExpectedInvocation {
            proof_type: "APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION".into(),
            schema_version: "1".into(),
            verifier_version: "0.2.0".into(),
            request_digest: "44".repeat(32),
            challenge: "unique-challenge".into(),
        }
    }

    fn local_proof_bound_artifacts() -> (AppProof, BootProof, TrustedReleasePolicy) {
        use turnkey_client::generated::external::data::v1::SignatureScheme;

        let mut release = policy();
        let manifest = serde_json::json!({
            "version": "v2",
            "namespace": {
                "name": release.namespace_name,
                "nonce": release.namespace_nonce,
                "quorumKey": ""
            },
            "pivot": {
                "hash": release.executable_digest,
                "restart": "Never",
                "bridgeConfig": [{
                    "type": "server",
                    "port": 3000,
                    "host": "0.0.0.0"
                }],
                "debugMode": false,
                "args": release.pivot_args
            },
            "manifestSet": {
                "threshold": release.manifest_operators.threshold,
                "members": release.manifest_operators.members.iter().map(|member| {
                    serde_json::json!({
                        "alias": member.alias,
                        "pubKey": member.public_key
                    })
                }).collect::<Vec<_>>()
            },
            "shareSet": {"threshold": 0, "members": []},
            "enclave": {
                "pcr0": release.pcrs.pcr0,
                "pcr1": release.pcrs.pcr1,
                "pcr2": release.pcrs.pcr2,
                "pcr3": release.pcrs.pcr3,
                "awsRootCertificate": "",
                "qosCommit": release.qos_commit
            }
        });
        let envelope = serde_json::json!({
            "manifest": manifest,
            "manifestSetApprovals": [],
            "shareSetApprovals": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap_or_default();
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap_or_default();
        let parsed_envelope = VersionedManifestEnvelope::try_from_slice_compat(&envelope_bytes);
        release.manifest_hash = parsed_envelope
            .as_ref()
            .ok()
            .map(VersionedManifestEnvelope::manifest_hash)
            .map(|hash| qos_hex::encode(&hash))
            .unwrap_or_default();

        let key = "11".repeat(130);
        let expected = invocation();
        let payload = serde_json::json!({
            "proofType": expected.proof_type,
            "schemaVersion": expected.schema_version,
            "verifierVersion": expected.verifier_version,
            "requestDigest": expected.request_digest,
            "challenge": expected.challenge,
            "result": {"verificationStatus": "pass"}
        });
        let app = AppProof {
            scheme: SignatureScheme::EphemeralKeyP256,
            public_key: key.clone(),
            proof_payload: payload.to_string(),
            signature: "22".repeat(64),
        };
        let boot = BootProof {
            ephemeral_public_key_hex: key,
            aws_attestation_doc_b64: String::new(),
            qos_manifest_b64: STANDARD.encode(manifest_bytes),
            qos_manifest_envelope_b64: STANDARD.encode(envelope_bytes),
            deployment_label: release.deployment_label.clone(),
            enclave_app: release.enclave_app.clone(),
            owner: release.owner.clone(),
            created_at: None,
            qos_manifest_version: Some(release.qos_manifest_version.clone()),
        };
        (app, boot, release)
    }

    #[test]
    fn invalid_egress_policy_is_rejected() {
        let mut deployment_controls = controls();
        deployment_controls.enable_egress = true;
        assert!(matches!(
            validate_deployment_controls(&deployment_controls),
            Err(VerificationError::InvalidPolicy {
                field: "enableEgress",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_operator_is_rejected() {
        let mut release = policy();
        release.manifest_operators.members[1] = release.manifest_operators.members[0].clone();
        assert!(matches!(
            validate_release_policy(&release),
            Err(VerificationError::InvalidPolicy {
                field: "manifestOperators.members",
                ..
            })
        ));
    }

    #[test]
    fn app_payload_binds_request_and_result() {
        let expected = invocation();
        let payload = serde_json::json!({
            "proofType": expected.proof_type,
            "schemaVersion": expected.schema_version,
            "verifierVersion": expected.verifier_version,
            "requestDigest": expected.request_digest,
            "challenge": expected.challenge,
            "result": {"verificationStatus": "pass"}
        });
        let parsed = verify_invocation_payload(&payload.to_string(), &expected);
        assert_eq!(
            parsed
                .as_ref()
                .ok()
                .and_then(|value| value["result"]["verificationStatus"].as_str()),
            Some("pass")
        );
    }

    #[test]
    fn app_payload_replay_is_rejected() {
        let expected = invocation();
        let payload = serde_json::json!({
            "proofType": expected.proof_type,
            "schemaVersion": expected.schema_version,
            "verifierVersion": expected.verifier_version,
            "requestDigest": expected.request_digest,
            "challenge": "different-challenge",
            "result": {}
        });
        assert!(matches!(
            verify_invocation_payload(&payload.to_string(), &expected),
            Err(VerificationError::AppPayloadMismatch {
                field: "challenge",
                ..
            })
        ));
    }

    #[test]
    fn local_qos_manifest_matches_all_proof_bound_release_fields() {
        let (app, boot, release) = local_proof_bound_artifacts();
        let result = verify_proof_bound_release(&app, &boot, &release, &invocation());
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            result.as_ref().ok().map(|value| value.authorization_grade),
            Some(false)
        );
        assert_eq!(
            result
                .as_ref()
                .ok()
                .map(|value| value.manifest_hash.as_str()),
            Some(release.manifest_hash.as_str())
        );
    }

    #[test]
    fn local_qos_manifest_executable_mutation_is_rejected() {
        let (app, boot, mut release) = local_proof_bound_artifacts();
        release.executable_digest = "ff".repeat(32);
        let result = verify_proof_bound_release(&app, &boot, &release, &invocation());
        assert!(
            matches!(
                result,
                Err(VerificationError::PolicyMismatch {
                    field: "executableDigest",
                    ..
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn mismatched_exact_boot_key_is_rejected_before_attestation() {
        use turnkey_client::generated::external::data::v1::SignatureScheme;

        let app = AppProof {
            scheme: SignatureScheme::EphemeralKeyP256,
            public_key: "11".repeat(130),
            proof_payload: "{}".into(),
            signature: "22".repeat(64),
        };
        let boot = BootProof {
            ephemeral_public_key_hex: "33".repeat(130),
            aws_attestation_doc_b64: String::new(),
            qos_manifest_b64: String::new(),
            qos_manifest_envelope_b64: String::new(),
            deployment_label: String::new(),
            enclave_app: String::new(),
            owner: String::new(),
            created_at: None,
            qos_manifest_version: None,
        };
        assert!(matches!(
            verify_proof_bound_offline(&app, &boot, &policy(), &invocation()),
            Err(VerificationError::EphemeralKeyMismatch(_))
        ));
    }

    #[test]
    fn matching_fake_keys_reach_official_turnkey_verifier() {
        use turnkey_client::generated::external::data::v1::SignatureScheme;

        let key = "11".repeat(130);
        let app = AppProof {
            scheme: SignatureScheme::EphemeralKeyP256,
            public_key: key.clone(),
            proof_payload: "{}".into(),
            signature: "22".repeat(64),
        };
        let boot = BootProof {
            ephemeral_public_key_hex: key,
            aws_attestation_doc_b64: String::new(),
            qos_manifest_b64: String::new(),
            qos_manifest_envelope_b64: String::new(),
            deployment_label: String::new(),
            enclave_app: String::new(),
            owner: String::new(),
            created_at: None,
            qos_manifest_version: None,
        };
        assert!(matches!(
            verify_proof_bound_offline(&app, &boot, &policy(), &invocation()),
            Err(VerificationError::OfficialProofVerification(_))
        ));
    }

    #[test]
    fn strict_policy_keeps_unproven_controls_separate() {
        let strict = strict_policy();
        assert_eq!(strict.release, policy());
        assert_eq!(strict.deployment_controls, controls());
        assert_eq!(UNSUPPORTED_STRICT_EVIDENCE, ["pivotPath", "enableEgress"]);
    }
}
