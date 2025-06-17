//! Command implementations for the Fractus CLI

mod info;
mod recover;
mod split;

pub use info::InfoCommand;
pub use recover::RecoverCommand;
pub use split::SplitCommand;

use crate::config::Config;
use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Split a secret into shares
    Split(SplitCommand),

    /// Recover a secret from shares
    Recover(RecoverCommand),

    /// Display information about shares
    Info(InfoCommand),
}

impl Commands {
    pub fn execute(&self, config: &Config) -> Result<()> {
        match self {
            Commands::Split(cmd) => cmd.execute(config),
            Commands::Recover(cmd) => cmd.execute(config),
            Commands::Info(cmd) => cmd.execute(config),
        }
    }
}
