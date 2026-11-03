//! Every committed mint-attester deploy config launches through the real CLI, and the profile
//! rules hold for it: mainnet runs exactly one mainnet profile, the shared dev enclave runs
//! staging and testnet4 and nothing on mainnet.
//!
//! Placeholders (`REPLACE_WITH_…`) are swapped for well-formed values of the field's type
//! first, so a template is checked for shape before anyone fills it in.

#![allow(clippy::expect_used, clippy::panic)]

use clap::Parser;
use mint_attester::cli::Cli;
use serde_json::Value;
use std::{fs, path::Path};

const ORACLE_KEYS: &str =
    "midnight-2026Q4-ci-v1:79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const FUNDING_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// The launch arguments of `tvc-configs/deploy.mint-attester.<env>.json`, placeholders filled.
fn launch_args(env: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tvc-configs")
        .join(format!("deploy.mint-attester.{env}.json"));
    let config: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("config")).expect("json");
    let mut filled = 0u8;
    let mut args = vec!["mint-attester".to_owned()];
    let mut raw = config["pivotArgs"].as_array().expect("pivotArgs").iter();
    while let Some(arg) = raw.next() {
        let arg = arg.as_str().expect("string arg");
        args.push(arg.to_owned());
        if arg != "--profile" {
            assert!(
                !arg.starts_with("REPLACE_WITH"),
                "{env}: only profile fields may be placeholders, found {arg}"
            );
            continue;
        }
        let mut profile: Value =
            serde_json::from_str(raw.next().and_then(Value::as_str).expect("profile json"))
                .expect("profile is JSON");
        for (field, value) in profile.as_object_mut().expect("object") {
            if !value
                .as_str()
                .is_some_and(|value| value.starts_with("REPLACE_WITH"))
            {
                continue;
            }
            filled += 1;
            *value = match field.as_str() {
                // Filled the way an operator would: the placeholder text replaced in place.
                "chainId" => Value::from("8453"),
                "lygosAuthorizer" | "verifier" | "originator" => {
                    Value::from(format!("0x{}", format!("{filled:02x}").repeat(20)))
                }
                "lygosFundingPubkey" => Value::from(FUNDING_KEY),
                "midnightOracleKeys" => Value::from(ORACLE_KEYS),
                other => panic!("{env}: no stand-in for placeholder field {other}"),
            };
        }
        args.push(profile.to_string());
    }
    args
}

/// `(name, network)` of each profile the config launches, after the CLI and the sharing rules.
fn profiles(env: &str) -> Vec<(String, bitcoin::Network)> {
    let cli = Cli::try_parse_from(launch_args(env))
        .unwrap_or_else(|error| panic!("{env} does not parse: {error}"));
    cli.profiles()
        .unwrap_or_else(|error| panic!("{env} may not launch: {error}"))
        .into_iter()
        .map(|profile| (profile.name, profile.network))
        .collect()
}

#[test]
fn mainnet_runs_exactly_one_mainnet_profile() {
    for env in ["mainnet", "example"] {
        let profiles = profiles(env);
        assert_eq!(profiles.len(), 1, "{env}: {profiles:?}");
        assert_eq!(profiles[0].1, bitcoin::Network::Bitcoin, "{env}");
    }
}

#[test]
fn the_shared_dev_enclave_serves_staging_and_testnet4() {
    assert_eq!(
        profiles("staging"),
        [
            ("staging".to_owned(), bitcoin::Network::Signet),
            ("testnet4".to_owned(), bitcoin::Network::Testnet4),
        ]
    );
}

#[test]
fn every_mint_attester_deploy_config_is_checked() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tvc-configs");
    let mut envs: Vec<String> = fs::read_dir(dir)
        .expect("tvc-configs")
        .filter_map(|entry| {
            let name = entry.expect("entry").file_name().into_string().ok()?;
            Some(
                name.strip_prefix("deploy.mint-attester.")?
                    .strip_suffix(".json")?
                    .to_owned(),
            )
        })
        .collect();
    envs.sort();
    assert_eq!(
        envs,
        ["example", "mainnet", "staging"],
        "a new config needs a test above"
    );
}
