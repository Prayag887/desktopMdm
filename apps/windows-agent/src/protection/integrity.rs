//! Streaming hashes from a publisher-authenticated manifest, never mutable state.
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path},
};

pub const REQUIRED: &[&str] = &[
    "emi-device-agent.exe",
    "emi-device-ui.exe",
    "emi-device-watchdog.exe",
    "emi-device-updater.exe",
    "Get-DeviceProtection.ps1",
    "Protection-Acl.ps1",
    "Protection-Integrity.ps1",
    "Get-SecurityPosture.ps1",
    "Provision-BitLocker.ps1",
    "Maintain-Protection.ps1",
    "Set-EmiStateAcl.ps1",
    "Protection-Transaction.ps1",
    "Protection-Package.ps1",
    "Install-PublisherTrust.ps1",
    "emi-publisher.cer",
    "install.ps1",
    "uninstall.ps1",
];

#[derive(Debug, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub verified: bool,
    pub failures: Vec<String>,
}

/// Validate required entries and constrain names to the installation root.
///
/// # Errors
/// Returns an error for missing entries, unsafe paths or malformed hashes.
pub fn validate_manifest(manifest: &BTreeMap<String, String>) -> anyhow::Result<()> {
    for name in REQUIRED {
        if !manifest.contains_key(*name) {
            bail!("manifest omits {name}");
        }
    }
    for (name, hash) in manifest {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || name.contains(['\\', ':'])
            || hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("invalid manifest entry {name}");
        }
    }
    Ok(())
}

/// Hash immutable files and collect individual missing/corrupt file diagnostics.
///
/// # Errors
/// Returns an error if the manifest structure is invalid.
pub fn verify_hashes(
    directory: &Path,
    manifest: &BTreeMap<String, String>,
) -> anyhow::Result<IntegrityReport> {
    validate_manifest(manifest)?;
    let mut failures = Vec::new();
    for (name, expected) in manifest {
        let result = (|| -> anyhow::Result<String> {
            let path = directory.join(name);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("not a regular file");
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    bail!("reparse point");
                }
            }
            let mut file = fs::File::open(path)?;
            let mut hash = Sha256::new();
            let mut buffer = vec![0u8; 65536];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            Ok(format!("{:x}", hash.finalize()))
        })();
        match result {
            Ok(actual) if actual.eq_ignore_ascii_case(expected) => {}
            Ok(_) => failures.push(format!("{name}: SHA-256 mismatch")),
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    Ok(IntegrityReport {
        verified: failures.is_empty(),
        failures,
    })
}

/// Authenticate the release manifest before hashing any trusted installation file.
///
/// # Errors
/// Returns an error for unavailable Windows APIs, untrusted signatures or malformed manifests.
pub fn verify_installation(directory: &Path) -> anyhow::Result<IntegrityReport> {
    // Validate Authenticode without executing the manifest. Trust matches the
    // running, validly signed component; standard users cannot rewrite either.
    let manifest_path = directory.join("protection-manifest.ps1");
    let command = format!(
        "$ErrorActionPreference='Stop'; $m=Get-AuthenticodeSignature {}; $a=Get-AuthenticodeSignature {}; if($m.Status -ne 'Valid' -or $a.Status -ne 'Valid' -or $m.SignerCertificate.Thumbprint -ne $a.SignerCertificate.Thumbprint){{throw 'Untrusted manifest publisher'}}",
        super::windows::quote(&manifest_path),
        super::windows::quote(&std::env::current_exe()?)
    );
    super::windows::powershell(&command, &[])?;
    let contents = fs::read_to_string(manifest_path)?;
    let json = contents
        .lines()
        .next()
        .context("empty integrity manifest")?
        .trim_start_matches('\u{feff}')
        .strip_prefix("# EMI-MANIFEST ")
        .context("invalid manifest header")?;
    let manifest = serde_json::from_str(json)?;
    verify_hashes(directory, &manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_entries_and_traversal() {
        assert!(validate_manifest(&BTreeMap::new()).is_err());
        let mut manifest: BTreeMap<_, _> = REQUIRED
            .iter()
            .map(|n| ((*n).into(), "a".repeat(64)))
            .collect();
        assert!(validate_manifest(&manifest).is_ok());
        for name in ["../evil", "C:\\evil", "a/b", "a\\b", "/evil"] {
            manifest.insert(name.into(), "a".repeat(64));
            assert!(validate_manifest(&manifest).is_err());
            manifest.remove(name);
        }
    }
    #[test]
    fn detects_missing_and_corrupt_files() {
        let directory = tempfile::tempdir().unwrap();
        let mut manifest = BTreeMap::new();
        for name in REQUIRED {
            fs::write(directory.path().join(name), b"trusted").unwrap();
            manifest.insert((*name).into(), format!("{:x}", Sha256::digest(b"trusted")));
        }
        assert!(verify_hashes(directory.path(), &manifest).unwrap().verified);
        fs::write(directory.path().join(REQUIRED[0]), b"tampered").unwrap();
        fs::remove_file(directory.path().join(REQUIRED[1])).unwrap();
        assert_eq!(
            verify_hashes(directory.path(), &manifest)
                .unwrap()
                .failures
                .len(),
            2
        );
    }
}
