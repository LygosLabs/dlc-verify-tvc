//! Fetch and verify the exact Boot Proof for a live DLC verifier App Proof.

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt as _,
};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    TurnkeyClient,
    generated::{
        GetBootProofRequest, GetTvcAppRequest, GetTvcDeploymentRequest,
        external::data::v1::AppProof,
    },
};
use verifier_client::{
    ExpectedInvocation, StrictVerificationPolicy, TrustedPcrs, VerificationError, verify_offline,
    verify_proof_bound_offline,
};
use verifier_schema::TvcVerificationRequest;

#[derive(Deserialize)]
struct ProofResponse {
    proof: AppProof,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseManifest {
    container_image: String,
    executable_path: String,
    executable_sha256: String,
    qos_version: String,
    pivot_args: Vec<String>,
    health_check_type: String,
    health_check_port: u32,
    public_ingress_port: u32,
    has_pull_secret: bool,
    dangerous_deploy_debug_mode: bool,
    dangerous_enable_debug_mode_deployments: bool,
    enable_egress: bool,
    qos_commit_provenance_available: bool,
    deployment_identity: DeploymentIdentity,
    authorization_ready: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentIdentity {
    app_id: String,
    deployment_id: String,
    deployment_label: String,
    manifest_set_id: String,
    manifest_id: String,
    manifest_hash: String,
    qos_manifest_version: String,
    qos_commit: String,
    pcrs: TrustedPcrs,
    manifest_operators: ReleaseOperatorSet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseOperatorSet {
    threshold: u32,
    members: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let request_path = required_arg(args.next(), "request JSON path")?;
    let response_path = required_arg(args.next(), "proof response JSON path")?;
    let policy_path = required_arg(args.next(), "strict policy JSON path")?;
    let release_manifest_path = required_arg(args.next(), "release manifest JSON path")?;
    let boot_proof_output = args.next();
    if args.next().is_some() {
        return Err(io::Error::other("too many arguments").into());
    }

    let request: TvcVerificationRequest = read_json(&request_path)?;
    let response: ProofResponse = read_json(&response_path)?;
    let policy: StrictVerificationPolicy = read_json(&policy_path)?;
    let release_manifest: ReleaseManifest = read_json(&release_manifest_path)?;
    verify_release_policy_consistency(&release_manifest, &policy)?;
    let challenge = request
        .challenge
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("request challenge is missing"))?;
    let request_digest = format!("{:x}", Sha256::digest(qos_json::to_vec(&request)?));

    let organization_id = required_env("TVC_ORG_ID")?;
    let api_public_key = required_env("TVC_API_KEY_PUBLIC")?;
    let api_private_key = required_env("TVC_API_KEY_PRIVATE")?;
    let stamper = TurnkeyP256ApiKey::from_strings(&api_private_key, Some(&api_public_key))?;
    let client = TurnkeyClient::builder().api_key(stamper).build()?;
    let boot_proof = client
        .get_boot_proof(GetBootProofRequest {
            organization_id: organization_id.clone(),
            ephemeral_key: response.proof.public_key.clone(),
        })
        .await?
        .boot_proof
        .ok_or_else(|| io::Error::other("Turnkey returned no Boot Proof"))?;
    let app = client
        .get_tvc_app(GetTvcAppRequest {
            organization_id: organization_id.clone(),
            tvc_app_id: release_manifest.deployment_identity.app_id.clone(),
        })
        .await?
        .tvc_app
        .ok_or_else(|| io::Error::other("Turnkey returned no TVC app"))?;
    let deployment = client
        .get_tvc_deployment(GetTvcDeploymentRequest {
            organization_id,
            deployment_id: release_manifest.deployment_identity.deployment_id.clone(),
        })
        .await?
        .tvc_deployment
        .ok_or_else(|| io::Error::other("Turnkey returned no TVC deployment"))?;

    let identity = &release_manifest.deployment_identity;
    expect_control("app.id", &identity.app_id, &app.id)?;
    expect_control("deployment.id", &identity.deployment_id, &deployment.id)?;
    expect_control("deployment.appId", &identity.app_id, &deployment.app_id)?;
    expect_control(
        "app.liveDeploymentId",
        &identity.deployment_id,
        app.live_deployment_id.as_deref().unwrap_or("<missing>"),
    )?;
    expect_control(
        "bootProof.deploymentLabel",
        &identity.deployment_label,
        &boot_proof.deployment_label,
    )?;
    expect_control(
        "bootProof.enclaveApp",
        &identity.app_id,
        &boot_proof.enclave_app,
    )?;
    if app.enable_egress {
        return Err(io::Error::other("authenticated app control enables egress").into());
    }
    if app.enable_debug_mode_deployments || deployment.debug_mode {
        return Err(
            io::Error::other("authenticated application or deployment allows debug mode").into(),
        );
    }
    expect_control_bool(
        "app.enableEgress",
        release_manifest.enable_egress,
        app.enable_egress,
    )?;
    expect_control_bool(
        "deployment.debugMode",
        release_manifest.dangerous_deploy_debug_mode,
        deployment.debug_mode,
    )?;
    expect_control_bool(
        "app.enableDebugModeDeployments",
        release_manifest.dangerous_enable_debug_mode_deployments,
        app.enable_debug_mode_deployments,
    )?;
    expect_control(
        "deployment.qosVersion",
        &release_manifest.qos_version,
        &deployment.qos_version,
    )?;
    let manifest_set_id = app
        .manifest_set
        .as_ref()
        .map(|set| set.id.clone())
        .ok_or_else(|| io::Error::other("app is missing its manifest set"))?;
    expect_control(
        "app.manifestSetId",
        &identity.manifest_set_id,
        &manifest_set_id,
    )?;
    let deployment_manifest_set_id = deployment
        .manifest_set
        .as_ref()
        .map(|set| set.id.as_str())
        .ok_or_else(|| io::Error::other("deployment is missing its manifest set"))?;
    expect_control(
        "deployment.manifestSetId",
        &identity.manifest_set_id,
        deployment_manifest_set_id,
    )?;
    let manifest_id = deployment
        .manifest
        .as_ref()
        .map(|manifest| manifest.id.clone())
        .ok_or_else(|| io::Error::other("deployment is missing its manifest"))?;
    expect_control("deployment.manifestId", &identity.manifest_id, &manifest_id)?;
    let pivot = deployment
        .pivot_container
        .as_ref()
        .ok_or_else(|| io::Error::other("deployment is missing its pivot container"))?;
    expect_control(
        "deployment.containerImage",
        &release_manifest.container_image,
        &pivot.container_url,
    )?;
    expect_control(
        "deployment.pivotPath",
        &release_manifest.executable_path,
        &pivot.path,
    )?;
    expect_control_vec(
        "deployment.pivotArgs",
        &release_manifest.pivot_args,
        &pivot.args,
    )?;
    expect_control_bool(
        "deployment.hasPullSecret",
        release_manifest.has_pull_secret,
        pivot.has_pull_secret,
    )?;
    expect_control(
        "deployment.healthCheckType",
        &release_manifest.health_check_type,
        pivot.health_check_type.as_str_name(),
    )?;
    expect_control_u32(
        "deployment.healthCheckPort",
        release_manifest.health_check_port,
        pivot.health_check_port,
    )?;
    expect_control_u32(
        "deployment.publicIngressPort",
        release_manifest.public_ingress_port,
        pivot.public_ingress_port,
    )?;

    let invocation = ExpectedInvocation {
        proof_type: "APP_PROOF_TYPE_LYGOS_DLC_VERIFICATION".into(),
        schema_version: "1".into(),
        verifier_version: env!("CARGO_PKG_VERSION").into(),
        request_digest,
        challenge: challenge.into(),
    };
    let verified =
        verify_proof_bound_offline(&response.proof, &boot_proof, &policy.release, &invocation)?;
    let strict_result = verify_offline(&response.proof, &boot_proof, &policy, &invocation);
    let strict_unsupported_evidence = match strict_result {
        Err(VerificationError::UnsupportedEvidence { fields }) => fields,
        Err(error) => return Err(error.into()),
        Ok(_) => {
            return Err(io::Error::other(
                "strict verification unexpectedly claimed authorization-grade evidence",
            )
            .into());
        }
    };

    if let Some(path) = boot_proof_output {
        write_verified_boot_proof(&path, &boot_proof)?;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "proofBoundVerification": verified,
            "strictUnsupportedEvidence": strict_unsupported_evidence,
            "bootProof": {
                "deploymentLabel": boot_proof.deployment_label,
                "enclaveApp": boot_proof.enclave_app,
                "owner": boot_proof.owner,
                "qosManifestVersion": boot_proof.qos_manifest_version,
            },
            "authenticatedDeploymentControls": {
                "appId": app.id,
                "deploymentId": deployment.id,
                "liveDeploymentId": app.live_deployment_id,
                "manifestSetId": manifest_set_id,
                "manifestId": manifest_id,
                "containerImage": pivot.container_url,
                "pivotPath": pivot.path,
                "pivotArgs": pivot.args,
                "enableEgress": app.enable_egress,
                "dangerousEnableDebugModeDeployments": app.enable_debug_mode_deployments,
                "dangerousDeployDebugMode": deployment.debug_mode,
            }
        }))?
    );
    Ok(())
}

fn required_arg(value: Option<String>, name: &str) -> Result<String, io::Error> {
    value.ok_or_else(|| {
        io::Error::other(format!(
            "missing {name}; usage: verify-live <request.json> <response.json> <strict-policy.json> <release-manifest.json> [boot-proof.json]"
        ))
    })
}

fn required_env(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other(format!("missing required environment variable {name}")))
}

fn expect_control(field: &str, expected: &str, actual: &str) -> Result<(), io::Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "authenticated control-plane mismatch for {field}: expected {expected}, got {actual}"
        )))
    }
}

fn expect_control_bool(field: &str, expected: bool, actual: bool) -> Result<(), io::Error> {
    expect_control(field, &expected.to_string(), &actual.to_string())
}

fn expect_control_u32(field: &str, expected: u32, actual: u32) -> Result<(), io::Error> {
    expect_control(field, &expected.to_string(), &actual.to_string())
}

fn expect_control_vec(
    field: &str,
    expected: &[String],
    actual: &[String],
) -> Result<(), io::Error> {
    if expected == actual {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "authenticated control-plane mismatch for {field}: expected {expected:?}, got {actual:?}"
        )))
    }
}

fn verify_release_policy_consistency(
    release: &ReleaseManifest,
    policy: &StrictVerificationPolicy,
) -> Result<(), io::Error> {
    let identity = &release.deployment_identity;
    expect_control(
        "release.deploymentLabel",
        &format!("deploy-{}", identity.deployment_id),
        &identity.deployment_label,
    )?;
    if release.enable_egress {
        return Err(io::Error::other("release manifest must disable egress"));
    }
    if release.dangerous_deploy_debug_mode || release.dangerous_enable_debug_mode_deployments {
        return Err(io::Error::other(
            "release manifest must disable all debug-mode controls",
        ));
    }
    if release.executable_path != "/tvc_app" {
        return Err(io::Error::other(
            "release manifest executablePath must be /tvc_app",
        ));
    }
    if release.authorization_ready {
        return Err(io::Error::other(
            "strict proof evidence is incomplete, so authorizationReady must be false",
        ));
    }
    if release.qos_commit_provenance_available == identity.qos_commit.is_empty() {
        return Err(io::Error::other(
            "qosCommitProvenanceAvailable must equal whether qosCommit is non-empty",
        ));
    }
    expect_control(
        "release.deploymentLabel",
        &policy.release.deployment_label,
        &identity.deployment_label,
    )?;
    expect_control(
        "release.enclaveApp",
        &policy.release.enclave_app,
        &identity.app_id,
    )?;
    expect_control(
        "release.manifestHash",
        &policy.release.manifest_hash,
        &identity.manifest_hash,
    )?;
    expect_control(
        "release.qosManifestVersion",
        &policy.release.qos_manifest_version,
        &identity.qos_manifest_version,
    )?;
    expect_control(
        "release.qosCommit",
        &policy.release.qos_commit,
        &identity.qos_commit,
    )?;
    expect_control(
        "release.executableSha256",
        &policy.release.executable_digest,
        &release.executable_sha256,
    )?;
    expect_control_vec(
        "release.pivotArgs",
        &policy.release.pivot_args,
        &release.pivot_args,
    )?;
    expect_control(
        "release.executablePath",
        &policy.deployment_controls.pivot_path,
        &release.executable_path,
    )?;
    expect_control_bool(
        "release.enableEgress",
        policy.deployment_controls.enable_egress,
        release.enable_egress,
    )?;
    if identity.pcrs != policy.release.pcrs {
        return Err(io::Error::other(format!(
            "release/trusted-policy mismatch for pcrs: expected {:?}, got {:?}",
            policy.release.pcrs, identity.pcrs
        )));
    }
    expect_control_u32(
        "release.manifestOperators.threshold",
        policy.release.manifest_operators.threshold,
        identity.manifest_operators.threshold,
    )?;
    let policy_operator_keys = policy
        .release
        .manifest_operators
        .members
        .iter()
        .map(|operator| operator.public_key.as_str())
        .collect::<BTreeSet<_>>();
    let release_operator_keys = identity
        .manifest_operators
        .members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if policy_operator_keys != release_operator_keys
        || release_operator_keys.len() != identity.manifest_operators.members.len()
    {
        return Err(io::Error::other(format!(
            "release/trusted-policy mismatch for manifestOperators.members: expected {policy_operator_keys:?}, got {release_operator_keys:?}"
        )));
    }
    Ok(())
}

fn write_verified_boot_proof(
    path: &str,
    boot_proof: &impl serde::Serialize,
) -> Result<(), Box<dyn Error>> {
    let bytes = serde_json::to_vec_pretty(boot_proof)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture() -> (ReleaseManifest, StrictVerificationPolicy) {
        let release = serde_json::from_str(include_str!(
            "../../../../release/release-manifest.dlc-verify-testing.json"
        ))
        .unwrap();
        let policy = serde_json::from_str(include_str!(
            "../../../../release/trusted-release-policy.dlc-verify-testing.json"
        ))
        .unwrap();
        (release, policy)
    }

    #[test]
    fn checked_in_release_and_policy_are_consistent() {
        let (release, policy) = fixture();
        verify_release_policy_consistency(&release, &policy).unwrap();
    }

    #[test]
    fn unsafe_release_flags_fail_closed() {
        let (mut release, policy) = fixture();
        release.dangerous_enable_debug_mode_deployments = true;
        assert!(verify_release_policy_consistency(&release, &policy).is_err());

        let (mut release, policy) = fixture();
        release.authorization_ready = true;
        assert!(verify_release_policy_consistency(&release, &policy).is_err());
    }

    #[test]
    fn release_provenance_must_match_the_manifest() {
        let (mut release, policy) = fixture();
        release.qos_commit_provenance_available = true;
        assert!(verify_release_policy_consistency(&release, &policy).is_err());
    }

    #[test]
    fn release_pcr_and_operator_drift_is_rejected() {
        let (mut release, policy) = fixture();
        release.deployment_identity.pcrs.pcr3 = "00".repeat(48);
        assert!(verify_release_policy_consistency(&release, &policy).is_err());

        let (mut release, policy) = fixture();
        release.deployment_identity.manifest_operators.members[0] = "00".repeat(130);
        assert!(verify_release_policy_consistency(&release, &policy).is_err());
    }

    #[test]
    fn deployment_label_must_bind_the_control_plane_id() {
        let (mut release, policy) = fixture();
        release.deployment_identity.deployment_id = "00000000-0000-0000-0000-000000000000".into();
        assert!(verify_release_policy_consistency(&release, &policy).is_err());
    }
}
