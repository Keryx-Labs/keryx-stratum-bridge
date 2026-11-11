//! Creates public testnet delegation metadata from two fresh test-only key files.
//! Generate payout.key and escrow.key in an isolated directory; never use wallet keys.
use keryx_addresses::{Address, Prefix, Version};
use keryx_consensus_core::collateral::escrow_delegation_message;
use secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(std::env::args().nth(1).ok_or("test directory required")?);
    let key = |name| -> Result<Keypair, Box<dyn std::error::Error>> {
        let bytes = hex::decode(fs::read_to_string(dir.join(name))?.trim())?;
        Ok(Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&bytes)?,
        ))
    };
    let payout = key("payout.key")?;
    let escrow = key("escrow.key")?;
    let pubkey = escrow.x_only_public_key().0.serialize();
    let address = Address::new(
        Prefix::Testnet,
        Version::PubKey,
        &payout.x_only_public_key().0.serialize(),
    );
    let cert = SECP256K1.sign_schnorr_no_aux_rand(
        &Message::from_digest(escrow_delegation_message(&pubkey)),
        &payout,
    );
    let metadata = serde_json::json!({"network":"testnet", "payout":address.to_string(),
        "pubkey":hex::encode(pubkey), "cert":cert.to_string()});
    fs::write(
        dir.join("identity.json"),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    println!("Created public testnet identity metadata; private keys were not displayed.");
    Ok(())
}
