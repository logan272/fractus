//! Split command implementation

use anyhow::{bail, Context, Result};
use clap::Args;
use fractus_shamir::{Shamir, Share};
use rand_chacha::rand_core::SeedableRng;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::formats::{OutputFormat, ShareData};

#[derive(Args)]
pub struct SplitCommand {
    /// Number of shares to generate
    #[arg(short = 'n', long, value_name = "COUNT")]
    pub shares: u8,

    /// Minimum threshold of shares required for recovery
    #[arg(short = 'k', long, value_name = "THRESHOLD")]
    pub threshold: u8,

    /// Input file (use '-' for stdin)
    #[arg(short, long, value_name = "FILE", default_value = "-")]
    pub input: String,

    /// Output directory for share files
    #[arg(short, long, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Output format
    #[arg(short = 'f', long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Base name for output files
    #[arg(long, value_name = "NAME", default_value = "share")]
    pub base_name: String,

    /// Print shares to stdout instead of files
    #[arg(long)]
    pub stdout: bool,

    /// Read secret from environment variable
    #[arg(long, value_name = "VAR")]
    pub env_var: Option<String>,

    /// Prompt for secret interactively (hidden input)
    #[arg(long)]
    pub interactive: bool,

    /// Custom seed for deterministic share generation (hex encoded)
    #[arg(long, value_name = "HEX")]
    pub seed: Option<String>,

    /// Include metadata in output
    #[arg(long)]
    pub include_metadata: bool,
}

impl SplitCommand {
    pub fn execute(&self, _config: &Config) -> Result<()> {
        // Validate arguments
        self.validate()?;

        // Read the secret
        let secret = self.read_secret()?;

        // Create Shamir instance
        let shamir = Shamir::new(self.threshold).context("Failed to create Shamir instance")?;

        // Generate shares
        let shares = if let Some(seed_hex) = &self.seed {
            let seed_bytes = hex::decode(seed_hex).context("Invalid hex seed")?;
            if seed_bytes.len() != 32 {
                bail!("Seed must be exactly 32 bytes (64 hex characters)");
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

            shamir
                .split_with_rng(&secret, &mut rng)?
                .take(self.shares as usize)
                .collect::<Vec<Share>>()
        } else {
            shamir
                .split(&secret)?
                .take(self.shares as usize)
                .collect::<Vec<Share>>()
        };

        // Output shares
        if self.stdout {
            self.output_to_stdout(&shares)?;
        } else {
            self.output_to_files(&shares)?;
        }

        if !self.stdout {
            println!(
                "✅ Successfully generated {} shares with threshold {}",
                self.shares, self.threshold
            );
            if let Some(dir) = &self.output_dir {
                println!("Shares saved to: {}", dir.display());
            }
        }

        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.threshold == 0 {
            bail!("Threshold must be at least 1");
        }

        if self.shares < self.threshold {
            bail!(
                "Number of shares ({}) must be at least the threshold ({})",
                self.shares,
                self.threshold
            );
        }

        // Check for conflicting input options
        let input_methods = [self.env_var.is_some(), self.interactive, self.input != "-"];
        if input_methods.iter().filter(|&&x| x).count() > 1 {
            bail!("Only one input method can be specified");
        }

        Ok(())
    }

    fn read_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        let secret = if let Some(env_var) = &self.env_var {
            // Read from environment variable
            std::env::var(env_var)
                .with_context(|| format!("Environment variable '{}' not found", env_var))?
                .into_bytes()
        } else if self.interactive {
            // Interactive input (hidden)
            let password = rpassword::prompt_password("Enter secret: ")
                .context("Failed to read secret from stdin")?;
            password.into_bytes()
        } else if self.input == "-" {
            // Read from stdin
            let mut buffer = Vec::new();
            io::stdin()
                .read_to_end(&mut buffer)
                .context("Failed to read from stdin")?;
            buffer
        } else {
            // Read from file
            fs::read(&self.input).with_context(|| format!("Failed to read file: {}", self.input))?
        };

        if secret.is_empty() {
            bail!("Secret cannot be empty");
        }

        Ok(Zeroizing::new(secret))
    }

    fn output_to_stdout(&self, shares: &[Share]) -> Result<()> {
        for (i, share) in shares.iter().enumerate() {
            let share_data = ShareData::new(
                share.clone(),
                i + 1,
                self.shares,
                self.threshold,
                self.include_metadata,
            );

            match self.format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&share_data)?);
                }
                OutputFormat::Hex => {
                    println!("{}", share_data.to_hex());
                }
                OutputFormat::Base64 => {
                    println!("{}", share_data.to_base64());
                }
                OutputFormat::Binary => {
                    let bytes = share_data.to_bytes();
                    io::stdout().write_all(&bytes)?;
                }
            }
        }
        Ok(())
    }

    fn output_to_files(&self, shares: &[Share]) -> Result<()> {
        let output_dir = self
            .output_dir
            .as_ref()
            .map(|p| p.clone())
            .unwrap_or_else(|| PathBuf::from("."));

        // Create output directory if it doesn't exist
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("Failed to create directory: {}", output_dir.display()))?;
        }

        for (i, share) in shares.iter().enumerate() {
            let share_data = ShareData::new(
                share.clone(),
                i + 1,
                self.shares,
                self.threshold,
                self.include_metadata,
            );

            let filename = format!(
                "{}-{:03}.{}",
                self.base_name,
                i + 1,
                self.format.extension()
            );
            let filepath = output_dir.join(filename);

            match self.format {
                OutputFormat::Json => {
                    let content = serde_json::to_string_pretty(&share_data)?;
                    fs::write(&filepath, content)?;
                }
                OutputFormat::Hex => {
                    fs::write(&filepath, share_data.to_hex())?;
                }
                OutputFormat::Base64 => {
                    fs::write(&filepath, share_data.to_base64())?;
                }
                OutputFormat::Binary => {
                    fs::write(&filepath, share_data.to_bytes())?;
                }
            }
        }

        Ok(())
    }
}
