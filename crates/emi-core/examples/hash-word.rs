//! Owner tool: produce the Argon2id encoded hash of an unlock word, to embed in
//! the app as `UNLOCK_WORD_HASH`. Run OFFLINE. The plaintext word is never stored
//! in the binary — only this hash.
//!
//!   cargo run --example hash-word -p emi-core -- <word>

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use rand::rngs::OsRng;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(word) = std::env::args().nth(1) else {
        eprintln!("usage: hash-word <word>");
        return ExitCode::FAILURE;
    };
    let salt = SaltString::generate(&mut OsRng);
    match Argon2::default().hash_password(word.as_bytes(), &salt) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("hashing failed: {error}");
            ExitCode::FAILURE
        }
    }
}
