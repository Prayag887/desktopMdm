//! Owner tool: generate an Ed25519 unlock keypair. Run ONCE, OFFLINE.
//!
//!   cargo run --example keygen -p emi-core
//!
//! Keep the printed SIGNING key secret and off every managed device. Embed the
//! PUBLIC key in the device app (`OWNER_PUBLIC_KEY_HEX`). Anyone who has the
//! signing key can unlock devices; anyone with only the public key cannot.

use core::fmt::Write as _;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write hex");
    }
    out
}

fn main() {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    println!(
        "SIGNING KEY (keep secret, offline): {}",
        hex(&signing.to_bytes())
    );
    println!(
        "PUBLIC  KEY (embed in the app):      {}",
        hex(&verifying.to_bytes())
    );
    eprintln!();
    eprintln!("Store the signing key in a password manager / offline vault.");
    eprintln!("Losing it only means you fall back to admin / WinRE recovery.");
}
