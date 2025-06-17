//! Info command implementation

use anyhow::{Context, Result};
use clap::Args;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::config::Config;
use crate::formats::{InputFormat, ShareData};

#[derive(Args)]
pub struct InfoCommand {
    /// Share files or directories to analyze
    #[arg(value_name = "SHARES", required = true)]
    pub inputs: Vec<PathBuf>,

    /// Input format (auto-detect if not specified)
    #[arg(short = 'f', long, value_enum)]
    pub format: Option<InputFormat>,

    /// Show detailed information
    #[arg(short, long)]
    pub detailed: bool,

    /// Output format for information
    #[arg(long, value_enum, default_value = "table")]
    pub output_format: InfoOutputFormat,
}

#[derive(clap::ValueEnum, Clone)]
pub enum InfoOutputFormat {
    Table,
    Json,
    Yaml,
}

#[derive(Debug, serde::Serialize)]
struct ShareInfo {
    id: u8,
    x_coordinate: u8,
    y_length: usize,
    threshold: Option<u8>,
    total_shares: Option<u8>,
    format: String,
    file_path: Option<PathBuf>,
}

#[derive(Debug, serde::Serialize)]
struct ShareSetInfo {
    total_shares: usize,
    unique_x_coordinates: usize,
    y_length: Option<usize>,
    inferred_threshold: Option<u8>,
    shares: Vec<ShareInfo>,
    consistency_issues: Vec<String>,
}

impl InfoCommand {
    pub fn execute(&self, _config: &Config) -> Result<()> {
        let mut all_shares = Vec::new();
        let mut share_infos = Vec::new();

        // Collect all shares and their metadata
        for input in &self.inputs {
            if input.is_dir() {
                let (shares, infos) = self.analyze_directory(input)?;
                all_shares.extend(shares);
                share_infos.extend(infos);
            } else {
                let (share, info) = self.analyze_file(input)?;
                all_shares.push(share);
                share_infos.push(info);
            }
        }

        // Analyze the complete set
        let set_info = self.analyze_share_set(all_shares, share_infos);

        // Output the information
        self.output_info(&set_info)?;

        Ok(())
    }

    fn analyze_directory(
        &self,
        dir: &PathBuf,
    ) -> Result<(Vec<fractus_shamir::Share>, Vec<ShareInfo>)> {
        let mut shares = Vec::new();
        let mut infos = Vec::new();

        let entries = fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Ok((share, info)) = self.analyze_file(&path) {
                    shares.push(share);
                    infos.push(info);
                }
            }
        }

        Ok((shares, infos))
    }

    fn analyze_file(&self, path: &PathBuf) -> Result<(fractus_shamir::Share, ShareInfo)> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        let format = if let Some(f) = &self.format {
            *f
        } else {
            InputFormat::detect(&content)?
        };

        let share_data = match format {
            InputFormat::Json => {
                serde_json::from_str::<ShareData>(&content).context("Failed to parse JSON")?
            }
            InputFormat::Hex => ShareData::from_hex(&content)?,
            InputFormat::Base64 => ShareData::from_base64(&content)?,
            InputFormat::Binary => {
                let bytes = fs::read(path)?;
                ShareData::from_bytes(&bytes)?
            }
        };

        let share = share_data.clone().into_share();

        let info = ShareInfo {
            id: share_data.id.unwrap_or(0),
            x_coordinate: share.x().value(),
            y_length: share.y().len(),
            threshold: share_data.threshold,
            total_shares: share_data.total_shares,
            format: format!("{:?}", format),
            file_path: Some(path.clone()),
        };

        Ok((share, info))
    }

    fn analyze_share_set(
        &self,
        shares: Vec<fractus_shamir::Share>,
        infos: Vec<ShareInfo>,
    ) -> ShareSetInfo {
        let mut consistency_issues = Vec::new();

        // Check y-length consistency
        let y_lengths: Vec<usize> = shares.iter().map(|s| s.y().len()).collect();
        let y_length = if y_lengths.is_empty() {
            None
        } else if y_lengths.iter().all(|&len| len == y_lengths[0]) {
            Some(y_lengths[0])
        } else {
            consistency_issues.push("Shares have different y-vector lengths".to_string());
            None
        };

        // Check for duplicate x-coordinates
        let mut x_coord_counts = HashMap::new();
        for share in &shares {
            *x_coord_counts.entry(share.x().value()).or_insert(0) += 1;
        }

        let unique_x_coordinates = x_coord_counts.len();
        for (x, count) in x_coord_counts {
            if count > 1 {
                consistency_issues.push(format!(
                    "Duplicate x-coordinate: {} (appears {} times)",
                    x, count
                ));
            }
        }

        // Infer threshold from metadata or number of shares
        let inferred_threshold = infos
            .iter()
            .find_map(|info| info.threshold)
            .or_else(|| Some(shares.len() as u8));

        ShareSetInfo {
            total_shares: shares.len(),
            unique_x_coordinates,
            y_length,
            inferred_threshold,
            shares: infos,
            consistency_issues,
        }
    }

    fn output_info(&self, info: &ShareSetInfo) -> Result<()> {
        match self.output_format {
            InfoOutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(info)?);
            }
            InfoOutputFormat::Yaml => {
                println!("{}", serde_yaml::to_string(info)?);
            }
            InfoOutputFormat::Table => {
                self.output_table(info);
            }
        }
        Ok(())
    }

    fn output_table(&self, info: &ShareSetInfo) {
        println!("Share Set Information");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━");

        println!("Total shares: {}", info.total_shares);
        println!("Unique x-coordinates: {}", info.unique_x_coordinates);

        if let Some(length) = info.y_length {
            println!("Y-vector length: {} bytes", length);
        } else {
            println!("Y-vector length: ⚠️  Inconsistent");
        }

        if let Some(threshold) = info.inferred_threshold {
            println!("Inferred threshold: {}", threshold);
        }

        if !info.consistency_issues.is_empty() {
            println!("\n⚠️  Consistency Issues:");
            for issue in &info.consistency_issues {
                println!("  • {}", issue);
            }
        }

        if self.detailed && !info.shares.is_empty() {
            println!("\nIndividual Shares:");
            println!("┌─────┬─────────────┬──────────┬───────────┬─────────────┬──────────┐");
            println!("│ ID  │ X-Coord     │ Y-Length │ Threshold │ Total       │ Format   │");
            println!("├─────┼─────────────┼──────────┼───────────┼─────────────┼──────────┤");

            for share in &info.shares {
                println!(
                    "│ {:<3} │ {:<11} │ {:<8} │ {:<9} │ {:<11} │ {:<8} │",
                    share.id,
                    share.x_coordinate,
                    share.y_length,
                    share.threshold.map_or("?".to_string(), |t| t.to_string()),
                    share
                        .total_shares
                        .map_or("?".to_string(), |t| t.to_string()),
                    share.format
                );
            }
            println!("└─────┴─────────────┴──────────┴───────────┴─────────────┴──────────┘");
        }

        // Recovery status
        println!("\nRecovery Status:");
        if let Some(threshold) = info.inferred_threshold {
            if info.unique_x_coordinates >= threshold as usize {
                println!(
                    "✅ Sufficient shares for recovery ({} >= {})",
                    info.unique_x_coordinates, threshold
                );
            } else {
                println!(
                    "❌ Insufficient shares for recovery ({} < {})",
                    info.unique_x_coordinates, threshold
                );
            }
        } else {
            println!("❓ Cannot determine recovery status (unknown threshold)");
        }
    }
}
