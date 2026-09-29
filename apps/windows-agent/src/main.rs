mod agent;

use agent::config::{initialize, trust_command_key};
use agent::enrollment::enroll;
use agent::health::bootstrap;
use agent::runner::run;
use agent::service::service_entry;
use agent::storage::data_dir;
use clap::{Parser, Subcommand};
use emi_device_agent::agent_api::DEFAULT_API_BASE;
use emi_device_agent::command_security::normalize_public_key;

#[derive(Parser)]
#[command(version, about = "Windows EMI device agent")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Initialize this PC's local identity and state directory.
    Init,
    /// Enroll this PC after an administrator creates its pending device agent.
    Enroll {
        #[arg(long, default_value = DEFAULT_API_BASE)]
        server: String,
    },
    /// Refresh the local health snapshot.
    Run {
        #[arg(long)]
        once: bool,
        /// Check enrollment before the one-shot health and API synchronization.
        ///
        /// The Windows desktop UI uses this at launch so a newly installed
        /// agent does not wait for the five-minute service retry interval.
        #[arg(long)]
        auto_enroll: bool,
    },
    /// Install `WinGet` when it is missing (Windows only).
    Bootstrap,
    /// Show this PC's local identity.
    Status,
    /// Trust an admin command-signing key after validating its Ed25519 encoding.
    TrustCommandKey {
        #[arg(long)]
        key_id: u64,
        #[arg(long)]
        public_key: String,
    },
    /// Validate deployment public keys without changing any local state.
    ValidatePublicKeys {
        #[arg(long)]
        command_public_key: Option<String>,
        #[arg(long)]
        recovery_public_key_hex: Option<String>,
    },
    /// Provision the offline recovery public key; no built-in recovery secret.
    TrustRecoveryKey {
        #[arg(long)]
        public_key_hex: String,
    },
    #[command(hide = true)]
    Service,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        AgentCommand::Init => {
            initialize()?;
            Ok(())
        }
        AgentCommand::Enroll { server } => enroll(&server),
        AgentCommand::Run { once, auto_enroll } => run(once, auto_enroll),
        AgentCommand::Bootstrap => bootstrap(),
        AgentCommand::Status => {
            let config = initialize()?;
            println!(
                "local device {} ({})",
                config.device_id,
                if config.agent_token.is_some() {
                    "local credentials stored; verify server enrollment with check-enroll"
                } else {
                    "no local enrollment credentials"
                }
            );
            Ok(())
        }
        AgentCommand::TrustCommandKey { key_id, public_key } => {
            trust_command_key(key_id, &public_key)
        }
        AgentCommand::ValidatePublicKeys {
            command_public_key,
            recovery_public_key_hex,
        } => {
            if let Some(key) = command_public_key {
                normalize_public_key(&key)?;
            }
            if let Some(key) = recovery_public_key_hex {
                emi_device_agent::recovery_service::validate_public_key(&key)?;
            }
            Ok(())
        }
        AgentCommand::TrustRecoveryKey { public_key_hex } => {
            emi_device_agent::recovery_service::provision(&data_dir()?, &public_key_hex)
        }
        AgentCommand::Service => service_entry(),
    }
}
