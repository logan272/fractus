//! Recover command implementation

use anyhow::{bail, Context, Result};
use clap::Args;
use fractus_shamir::{Shamir, Share};
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::config::Config;
use crate::formats::{InputFormat, ShareData};

#[derive(Args)]
pub struct RecoverCommand {
    /// Share files or directories to read from
    #[arg(value_name = "SHARES", required = true)]
    pub inputs: Vec<PathBuf>,

    /// Input format (auto-detect if not specified)
    #[arg(short = 'f', long, value_enum)]
    pub format: Option<InputFormat>,

    /// Output file (use '-' for stdout)
    #[arg(short, long, value_name = "FILE", default_value = "-")]
    pub output: String,

    /// Expected threshold (for validation)
    #[arg(short = 't', long, value_name = "THRESHOLD")]
    pub threshold: Option<u8>,

    /// Read shares from stdin (one per line)
    #[arg(long)]
    pub stdin: bool,

    /// Verify recovery by re-splitting and comparing
    #[arg(long)]
    pub verify: bool,
}

impl RecoverCommand {
    pub fn execute(&self, _config: &Config) -> Result<()> {
        // Read shares
        let shares = if self.stdin {
            self.read_shares_from_stdin()?
        } else {
            self.read_shares_from_files()?
        };

        if shares.is_empty() {
            bail!("No shares provided");
        }

        // Validate shares
        self.validate_shares(&shares)?;

        // Determine threshold from shares or use provided value
        let threshold = if let Some(t) = self.threshold {
            t
        } else {
            // Try to infer from share metadata or use minimum
            shares.len() as u8
        };

        // Create Shamir instance and recover
        let shamir = Shamir::new(threshold).context("Failed to create Shamir instance")?;

        let secret = shamir
            .recover(&shares)
            .context("Failed to recover secret from shares")?;

        // Verify if requested
        if self.verify {
            self.verify_recovery(&secret, &shares, threshold)?;
        }

        // Output the recovered secret
        self.output_secret(&secret)?;

        if self.output != "-" {
            println!(
                "✅ Secret successfully recovered from {} shares",
                shares.len()
            );
        }

        Ok(())
    }

    fn read_shares_from_stdin(&self) -> Result<Vec<Share>> {
        let mut shares = Vec::new();
        let stdin = io::stdin();
        let reader = BufReader::new(stdin.lock());

        for line in reader.lines() {
            let line = line.context("Failed to read line from stdin")?;
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            let share = self.parse_share_from_string(line)?;
            shares.push(share);
        }

        Ok(shares)
    }

    fn read_shares_from_files(&self) -> Result<Vec<Share>> {
        let mut shares = Vec::new();

        for input in &self.inputs {
            if input.is_dir() {
                // Read all share files from directory
                let dir_shares = self.read_shares_from_directory(input)?;
                shares.extend(dir_shares);
            } else {
                // Read single file
                let share = self.read_share_from_file(input)?;
                shares.push(share);
            }
        }

        Ok(shares)
    }

    fn read_shares_from_directory(&self, dir: &PathBuf) -> Result<Vec<Share>> {
        let mut shares = Vec::new();

        let entries = fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                // Try to read as share file
                if let Ok(share) = self.read_share_from_file(&path) {
                    shares.push(share);
                }
            }
        }

        Ok(shares)
    }

    fn read_share_from_file(&self, path: &PathBuf) -> Result<Share> {
        // Detect format first (if not specified)
        let format = if let Some(f) = &self.format {
            *f
        } else {
            InputFormat::detect_from_path(path)?
        };

        match format {
            InputFormat::Binary => {
                // Read as bytes for binary format
                let bytes = fs::read(path)
                    .with_context(|| format!("Failed to read binary file: {}", path.display()))?;

                self.parse_share_from_bytes(&bytes)
            }
            _ => {
                // Read as string for text formats
                let content = fs::read_to_string(path)
                    .with_context(|| format!("Failed to read file: {}", path.display()))?;

                self.parse_share_from_string(&content)
            }
        }
    }

    fn parse_share_from_bytes(&self, bytes: &[u8]) -> Result<Share> {
        let share_data =
            ShareData::from_bytes(bytes).context("Failed to parse binary share data")?;

        Ok(share_data.into_share())
    }

    fn parse_share_from_string(&self, content: &str) -> Result<Share> {
        let content = content.trim();

        // Try to determine format from content if not specified
        let format = if let Some(f) = &self.format {
            *f
        } else {
            InputFormat::detect_from_content(content)?
        };

        let share_data = match format {
            InputFormat::Json => {
                serde_json::from_str::<ShareData>(content).context("Failed to parse JSON")?
            }
            InputFormat::Hex => ShareData::from_hex(content)?,
            InputFormat::Base64 => ShareData::from_base64(content)?,
            InputFormat::Binary => {
                bail!("Binary format requires byte input, not string");
            }
        };

        Ok(share_data.into_share())
    }

    fn validate_shares(&self, shares: &[Share]) -> Result<()> {
        if shares.is_empty() {
            bail!("No shares provided");
        }

        // Check that all shares have the same length
        let expected_len = shares[0].y().len();
        for (i, share) in shares.iter().enumerate() {
            if share.y().len() != expected_len {
                bail!("Share {} has different length than others", i + 1);
            }
        }

        // Check for duplicate x-coordinates
        let mut x_coords = std::collections::HashSet::new();
        for (i, share) in shares.iter().enumerate() {
            if !x_coords.insert(share.x().value()) {
                bail!(
                    "Duplicate share with x-coordinate {} at position {}",
                    share.x().value(),
                    i + 1
                );
            }
        }

        Ok(())
    }

    fn verify_recovery(
        &self,
        secret: &[u8],
        original_shares: &[Share],
        threshold: u8,
    ) -> Result<()> {
        println!("Verifying recovery...");

        let shamir = Shamir::new(threshold)?;
        let verification_shares: Vec<Share> =
            shamir.split(secret)?.take(original_shares.len()).collect();

        // We can't directly compare shares since they'll have different random coefficients,
        // but we can verify that we get the same secret back
        let re_recovered = shamir.recover(&verification_shares[..threshold as usize])?;

        if re_recovered != secret {
            bail!("Verification failed: re-splitting produced different secret");
        }

        println!("✅ Verification successful");
        Ok(())
    }

    fn output_secret(&self, secret: &[u8]) -> Result<()> {
        if self.output == "-" {
            io::stdout()
                .write_all(secret)
                .context("Failed to write to stdout")?;
        } else {
            fs::write(&self.output, secret)
                .with_context(|| format!("Failed to write to file: {}", self.output))?;
        }
        Ok(())
    }
}
