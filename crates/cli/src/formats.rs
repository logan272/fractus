//! Input/Output format handling

use crate::utils;
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
    pub fn detect(content: &str) -> Result<Self> {
        let content = content.trim();

        if content.starts_with('{') && content.ends_with('}') {
            Ok(Self::Json)
        } else if content
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_whitespace())
        {
            Ok(Self::Hex)
        } else if utils::is_base64(content) {
            Ok(Self::Base64)
        } else {
            bail!("Cannot detect format from content")
        }
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
