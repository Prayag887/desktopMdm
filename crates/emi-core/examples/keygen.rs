//! Generate an owner recovery key into a new private file, never into stdout.
//! Run off-device: cargo run --example keygen -p emi-core -- /secure/recovery.key
#[cfg(not(windows))]
use ed25519_dalek::SigningKey;
#[cfg(not(windows))]
use rand::rngs::OsRng;
#[cfg(not(windows))]
use std::{fs::OpenOptions, io::Write as _, path::PathBuf};
#[cfg(not(windows))]
use zeroize::Zeroizing;

#[cfg(not(windows))]
fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;
    let mut output = String::new();
    for byte in bytes {
        write!(output, "{byte:02x}")?;
    }
    Ok(output)
}

#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or("usage: keygen <new-private-key-file>")?,
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(windows))]
    {
        let mut file = options.open(&path)?;
        let signing = SigningKey::generate(&mut OsRng);
        let secret = Zeroizing::new(hex(&signing.to_bytes())?);
        file.write_all(secret.as_bytes())?;
        file.sync_all()?;
        let public = hex(&signing.verifying_key().to_bytes())?;
        println!("{public}");
        eprintln!(
            "Private key saved to {}. Back it up in your offline vault; never deploy it to managed devices.",
            path.display()
        );
        Ok(())
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err(
        "Generate owner keys on an offline Unix workstation with owner-only file permissions"
            .into(),
    )
}
