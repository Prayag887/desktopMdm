//! Compiled-in .NET/native Windows ACL operations; never load code from a damaged install.
use super::windows;
use serde::Deserialize;
use std::path::Path;

const IMPLEMENTATION: &str = include_str!("../../../../packaging/windows/Protection-Acl.ps1");
const STATE_IMPLEMENTATION: &str =
    include_str!("../../../../packaging/windows/Set-EmiStateAcl.ps1");

#[derive(Debug, Deserialize)]
pub struct AclReport {
    pub path: String,
    pub verified: bool,
    pub failures: Vec<String>,
    pub strategy: String,
}

/// Verify every owner and protected DACL against the exact protection policy.
///
/// # Errors
/// Returns an error for unavailable Windows APIs, reparse points or failed queries.
pub fn verify_protection_acl(path: &Path) -> anyhow::Result<AclReport> {
    operation(path, "Verify-ProtectionAcl", None)
}

/// Back up current ACLs when requested, apply exact permissions and verify the result.
///
/// # Errors
/// Returns an error for failed backups, unsafe paths or failed ACL operations.
pub fn apply_protection_acl(path: &Path, backup: Option<&Path>) -> anyhow::Result<AclReport> {
    operation(path, "Apply-ProtectionAcl", backup)
}

/// Restore the expected policy and log a repair only when it was needed.
///
/// # Errors
/// Returns an error if the tree cannot be inspected, secured or verified.
pub fn repair_protection_acl(path: &Path, backup: Option<&Path>) -> anyhow::Result<AclReport> {
    let report = verify_protection_acl(path)?;
    if report.verified {
        return Ok(report);
    }
    let report = apply_protection_acl(path, backup)?;
    tracing::warn!(path=%path.display(), "ACL repaired");
    Ok(report)
}

fn operation(path: &Path, action: &str, backup: Option<&Path>) -> anyhow::Result<AclReport> {
    let backup = backup.map_or_else(String::new, windows::quote);
    let command = format!(
        "$ErrorActionPreference='Stop'; {IMPLEMENTATION}\n{action} {} {backup} | ConvertTo-Json -Depth 5 -Compress",
        windows::quote(path)
    );
    Ok(serde_json::from_slice(&windows::powershell(
        &command,
        &[],
    )?)?)
}

/// Verify or repair state while preserving private credentials and the recovery mailbox.
///
/// # Errors
/// Returns an error for invalid state trees or failed Windows ACL operations.
pub fn state_acl(repair: bool) -> anyhow::Result<()> {
    let command = format!(
        "$ErrorActionPreference='Stop'; {STATE_IMPLEMENTATION}\n$d=Join-Path $env:ProgramData 'EmiDeviceAgent'; $r=Test-EmiStateAcl $d; if(-not $r.verified){{ {} }}",
        if repair {
            "Repair-EmiStateAcl $d; Write-Output 'repaired'"
        } else {
            "throw 'State ACL verification failed'"
        }
    );
    let result = windows::powershell(&command, &[])?;
    if !result.is_empty() {
        tracing::warn!("State ACL repaired");
    }
    Ok(())
}
