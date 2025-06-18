//! Input/Output format handling

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use fractus_shamir::Share;
use serde::{Deserialize, Serialize};

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum OutputFormat {
    Json,
    Hex,
    Base64,
    Binary,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum InputFormat {
    Json,
    Hex,
    Base64,
    Binary,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Hex => "hex",
            Self::Base64 => "b64",
            Self::Binary => "bin",
        }
    }
}

impl InputFormat {
    // Detect format from file path/extension
    pub fn detect_from_path(path: &PathBuf) -> Result<Self> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Ok(InputFormat::Json),
            Some("hex") => Ok(InputFormat::Hex),
            Some("b64") | Some("base64") => Ok(InputFormat::Base64),
            Some("bin") | Some("binary") => Ok(InputFormat::Binary),
            _ => {
                // If we can't detect from extension, try reading a small sample
                Self::detect_from_file_content(path)
            }
        }
    }

    // Detect format by examining file content
    fn detect_from_file_content(path: &PathBuf) -> Result<Self> {
        // Read first few bytes to detect format
        let mut file = fs::File::open(path).with_context(|| {
            format!(
                "Failed to open file for format detection: {}",
                path.display()
            )
        })?;

        let mut buffer = [0u8; 64]; // Read first 64 bytes
        let bytes_read = std::io::Read::read(&mut file, &mut buffer)
            .with_context(|| "Failed to read file for format detection")?;

        if bytes_read == 0 {
            bail!("File is empty");
        }

        let sample = &buffer[..bytes_read];

        // Check if it's valid UTF-8 first
        if let Ok(text) = std::str::from_utf8(sample) {
            Self::detect_from_content(text)
        } else {
            // Not valid UTF-8, assume binary
            Ok(InputFormat::Binary)
        }
    }

    // Detect format from string content (for text formats)
    pub fn detect_from_content(content: &str) -> Result<Self> {
        let content = content.trim();

        if content.is_empty() {
            bail!("Empty content");
        }

        // JSON detection
        if content.starts_with('{') && content.ends_with('}') {
            return Ok(InputFormat::Json);
        }

        // Hex detection (only hex characters)
        if content.len() % 2 == 0 && content.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(InputFormat::Hex);
        }

        // Base64 detection
        if Self::is_likely_base64(content) {
            return Ok(InputFormat::Base64);
        }

        // Default to JSON if we can't determine
        Ok(InputFormat::Json)
    }

    fn is_likely_base64(content: &str) -> bool {
        let content = content.replace(['\n', '\r', ' '], ""); // Remove whitespace

        // Check if length is valid for base64
        if content.len() % 4 != 0 {
            return false;
        }

        // Check if all characters are valid base64
        content
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareData {
    /// Share ID (1-based index)
    pub id: Option<u8>,

    /// X-coordinate of the share
    pub x: u8,

    /// Y-coordinates (the actual share data)
    pub y: Vec<u8>,

    /// Metadata (only included if requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_shares: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ShareData {
    pub fn new(
        share: Share,
        id: usize,
        total_shares: u8,
        threshold: u8,
        include_metadata: bool,
    ) -> Self {
        Self {
            id: if include_metadata {
                Some(id as u8)
            } else {
                None
            },
            x: share.x().value(),
            y: share.y().iter().map(|gf| gf.value()).collect(),
            threshold: if include_metadata {
                Some(threshold)
            } else {
                None
            },
            total_shares: if include_metadata {
                Some(total_shares)
            } else {
                None
            },
            created_at: if include_metadata {
                Some(chrono::Utc::now().to_rfc3339())
            } else {
                None
            },
            description: None,
        }
    }

    pub fn into_share(self) -> Share {
        let x = fractus_shamir::gf256::GF256::new(self.x);
        let y = self
            .y
            .into_iter()
            .map(fractus_shamir::gf256::GF256::new)
            .collect();
        Share::new(x, y)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let share = self.clone().into_share();
        share.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let share = Share::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse share from bytes: {}", e))?;

        Ok(Self {
            id: None,
            x: share.x().value(),
            y: share.y().iter().map(|gf| gf.value()).collect(),
            threshold: None,
            total_shares: None,
            created_at: None,
            description: None,
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim()).context("Invalid hex encoding")?;
        Self::from_bytes(&bytes)
    }

    pub fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }

    pub fn from_base64(b64_str: &str) -> Result<Self> {
        let bytes = base64::decode(b64_str.trim()).context("Invalid base64 encoding")?;
        Self::from_bytes(&bytes)
    }
}
