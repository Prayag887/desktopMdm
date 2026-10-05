//! Trusted repair dispatch. A separate elevated updater lets SCM stop the watchdog cleanly.
use super::{acl, integrity, windows};
use anyhow::{Context, bail};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Authenticate a protected repair cache and launch its signed updater without waiting.
///
/// # Errors
/// Returns an error for missing caches, unsafe paths, invalid ACLs/signatures or launch failure.
pub fn dispatch(installation: &Path, state: &Path) -> anyhow::Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join("repair-source.json"))?)?;
    let source = PathBuf::from(
        value["package"]
            .as_str()
            .context("missing repair package")?,
    );
    let root = PathBuf::from(std::env::var_os("PROGRAMDATA").context("ProgramData missing")?)
        .join("EmiDeviceAgentRepair");
    if source.parent() != Some(root.as_path())
        || !source.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
        })
    {
        bail!("repair cache is outside the fixed protected cache root");
    }
    if !acl::verify_protection_acl(&root)?.verified
        || !integrity::verify_installation(&source)?.verified
    {
        bail!("untrusted repair package");
    }
    let ledger_path = state.join("repair-attempts.json");
    let mut ledger = read_ledger(&ledger_path)?;
    let now = chrono::Utc::now();
    if ledger.attempts >= 5 || ledger.next_attempt.is_some_and(|next| next > now) {
        bail!("cached repair retry limit/cooldown active; administrator review required");
    }
    ledger.next_attempt = Some(now + chrono::Duration::seconds(300 * (1 << ledger.attempts)));
    ledger.attempts += 1;
    ledger.healthy_since = None;
    crate::state_store::write_json(&ledger_path, &ledger, false)?;
    let mut command = Command::new(source.join("emi-device-updater.exe"));
    command
        .arg("repair")
        .arg(installation)
        .arg(&source)
        .current_dir(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.spawn()?;
    tracing::warn!("watchdog recovery action: authenticated cached repair dispatched");
    Ok(())
}

/// Execute a previously trusted installer under an elevated Windows token.
///
/// # Errors
/// Returns an error for unauthorized tokens, untrusted packages or failed installation.
pub fn run(installation: &Path, package: &Path) -> anyhow::Result<()> {
    windows::powershell(
        "$ErrorActionPreference='Stop'; $p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated administrator required'}",
        &[],
    )?;
    let root = PathBuf::from(std::env::var_os("ProgramFiles").context("ProgramFiles missing")?);
    if !installation.is_absolute()
        || !installation.starts_with(&root)
        || installation == root
        || installation
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("repair target must be under Program Files");
    }
    if !acl::verify_protection_acl(package)?.verified
        || !integrity::verify_installation(package)?.verified
    {
        bail!("repair package authentication failed");
    }
    let command = format!(
        "$ErrorActionPreference='Stop'; & {} -InstallDir {} -SkipWingetBootstrap -SkipUiLaunch; if($LASTEXITCODE -ne 0){{throw 'Trusted repair failed'}}",
        windows::quote(&package.join("install.ps1")),
        windows::quote(installation)
    );
    windows::powershell_with_timeout(&command, &[], std::time::Duration::from_secs(900))?;
    Ok(())
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct RepairLedger {
    attempts: u32,
    next_attempt: Option<chrono::DateTime<chrono::Utc>>,
    healthy_since: Option<chrono::DateTime<chrono::Utc>>,
}
fn read_ledger(path: &Path) -> anyhow::Result<RepairLedger> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(RepairLedger::default()),
        Err(error) => Err(error.into()),
    }
}

/// Clear the persistent repair retry budget only after five minutes of verified health.
///
/// # Errors
/// Returns an error if the durable recovery ledger cannot be read or updated.
pub fn observe_healthy(state: &Path) -> anyhow::Result<()> {
    let path = state.join("repair-attempts.json");
    if !path.exists() {
        return Ok(());
    }
    let mut ledger = read_ledger(&path)?;
    let now = chrono::Utc::now();
    match ledger.healthy_since {
        Some(since) if now.signed_duration_since(since).num_seconds() >= 300 => {
            std::fs::remove_file(path)?;
        }
        None => {
            ledger.healthy_since = Some(now);
            crate::state_store::write_json(&path, &ledger, false)?;
        }
        _ => {}
    }
    Ok(())
}

/// Reset the healthy observation on an outage without resetting attempt counts.
///
/// # Errors
/// Returns an error for unreadable or unwritable recovery ledgers.
pub fn observe_unhealthy(state: &Path) -> anyhow::Result<()> {
    let path = state.join("repair-attempts.json");
    if !path.exists() {
        return Ok(());
    }
    let mut ledger = read_ledger(&path)?;
    if ledger.healthy_since.take().is_some() {
        crate::state_store::write_json(&path, &ledger, false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persistent_budget_requires_uninterrupted_health() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("repair-attempts.json");
        let ledger = RepairLedger {
            attempts: 5,
            next_attempt: None,
            healthy_since: Some(chrono::Utc::now() - chrono::Duration::seconds(301)),
        };
        crate::state_store::write_json(&path, &ledger, false).unwrap();
        observe_unhealthy(directory.path()).unwrap();
        observe_healthy(directory.path()).unwrap();
        assert_eq!(read_ledger(&path).unwrap().attempts, 5);
        assert!(path.exists());
        crate::state_store::write_json(&path, &ledger, false).unwrap();
        observe_healthy(directory.path()).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn malformed_repair_ledger_does_not_rearm_repair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("repair-attempts.json");
        std::fs::write(&path, b"invalid").unwrap();
        assert!(observe_healthy(directory.path()).is_err());
        assert!(observe_unhealthy(directory.path()).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"invalid");
    }
}
