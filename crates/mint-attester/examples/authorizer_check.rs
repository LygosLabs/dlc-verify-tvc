//! Recover the signer of a Midnight authorization with the enclave's own code.
//!
//! `cargo run -q -p mint-attester --example authorizer_check -- <chain id> <originator> <terms hash>
//! <signature>` prints the signer's address. `scripts/fordefi-authorizer.sh check` uses it to
//! confirm a Fordefi vault's signature is one the enclave accepts.

use mint_attester::authorizer::{digest, signer};
use std::{env, process::ExitCode};

fn decode<const N: usize>(field: &str, value: &str) -> Result<[u8; N], String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| format!("invalid {field}: {error}"))?
        .try_into()
        .map_err(|_| format!("invalid {field}: expected {N} bytes"))
}

fn run(args: &[String]) -> Result<[u8; 20], String> {
    let [chain_id, originator, terms_hash, signature] = args else {
        return Err(
            "usage: authorizer_check <chain id> <originator> <terms hash> <signature>".to_owned(),
        );
    };
    let chain_id = chain_id
        .parse()
        .map_err(|error| format!("invalid chain id: {error}"))?;
    let approval = digest(
        chain_id,
        &decode("originator", originator)?,
        &decode("terms hash", terms_hash)?,
    );
    signer(&approval, &decode("signature", signature)?)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(address) => {
            println!("0x{}", hex::encode(address));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
