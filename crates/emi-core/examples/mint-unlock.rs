//! Owner tool: mint a signed unlock token for one device. Run OFFLINE with your
//! signing key. The device's id is shown on its restriction screen.
//!
//!   cargo run --example mint-unlock -p emi-core -- \
//!       <signing-key-hex> <device-uuid> <counter> <ttl-minutes>
//!
//! `counter` must be strictly greater than any value already used for that
//! device (the device rejects reused / rolled-back counters). Pick a short
//! `ttl-minutes` so a leaked token stops working quickly.

use std::process::ExitCode;

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use emi_core::recovery::UnlockToken;
use uuid::Uuid;

fn signing_key_from_hex(hex: &str) -> Option<SigningKey> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(SigningKey::from_bytes(&bytes))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key_hex, device, counter, ttl] = args.as_slice() else {
        eprintln!("usage: mint-unlock <signing-key-hex> <device-uuid> <counter> <ttl-minutes>");
        return ExitCode::FAILURE;
    };

    let Some(signing) = signing_key_from_hex(key_hex.trim()) else {
        eprintln!("signing key must be 64 hex characters");
        return ExitCode::FAILURE;
    };
    let Ok(device_id) = Uuid::parse_str(device.trim()) else {
        eprintln!("device id must be a UUID");
        return ExitCode::FAILURE;
    };
    let (Ok(counter), Ok(ttl_minutes)) = (counter.parse::<u64>(), ttl.parse::<i64>()) else {
        eprintln!("counter must be a u64 and ttl-minutes an integer");
        return ExitCode::FAILURE;
    };

    let token = UnlockToken {
        device_id,
        counter,
        expires_unix: (Utc::now() + Duration::minutes(ttl_minutes)).timestamp(),
    };
    println!("{}", token.sign_to_string(&signing));
    eprintln!(
        "device={device_id} counter={counter} expires in {ttl_minutes} min — paste this into the device's recovery field"
    );
    ExitCode::SUCCESS
}
