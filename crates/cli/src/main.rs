//! Fractus CLI - Command-line interface for Shamir's Secret Sharing
//!
//! This tool provides a comprehensive interface for splitting secrets into shares
//! and recovering them using Shamir's Secret Sharing scheme.

mod commands;
mod config;
mod error;
mod formats;
mod utils;

use anyhow::Result;
use clap::Parser;
use commands::Commands;
use config::Config;

#[derive(Parser)]
#[command(
    name = "fractus",
    version,
    author = "Fractus Team",
    about = "Fractus - Shamir's Secret Sharing CLI Tool",
    long_about = "A command-line tool for splitting secrets into shares using Shamir's Secret Sharing \
                  and recovering them. Supports various input/output formats for maximum flexibility."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<std::path::PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Quiet mode (suppress non-error output)
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging based on verbosity
    init_logging(cli.verbose, cli.quiet);

    // Load configuration
    let config = Config::load(cli.config.as_deref())?;

    // Execute the command
    match cli.command.execute(&config) {
        Ok(()) => Ok(()),
        Err(e) => {
            if !cli.quiet {
                eprintln!("Error: {}", e);

                // Print chain of errors if verbose
                if cli.verbose {
                    let mut source = e.source();
                    while let Some(err) = source {
                        eprintln!("  Caused by: {}", err);
                        source = err.source();
                    }
                }
            }
            std::process::exit(1);
        }
    }
}

fn init_logging(verbose: bool, quiet: bool) {
    if quiet {
        return;
    }

    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(level)
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false)
        .init();
}
