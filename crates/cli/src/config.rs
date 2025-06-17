//! Configuration management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    #[serde(default)]
    pub defaults: Defaults,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Defaults {
    #[serde(default = "default_threshold")]
    pub threshold: u8,

    #[serde(default = "default_shares")]
    pub shares: u8,

    #[serde(default = "default_format")]
    pub format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            defaults: Defaults::default(),
        }
    }
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            shares: default_shares(),
            format: default_format(),
        }
    }
}

fn default_threshold() -> u8 {
    3
}
fn default_shares() -> u8 {
    5
}
fn default_format() -> String {
    "json".to_string()
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        if let Some(config_path) = path {
            Self::load_from_file(config_path)
        } else {
            Self::load_default()
        }
    }

    fn load_default() -> Result<Self> {
        // Try to load from standard locations
        let config_dirs = [
            dirs::config_dir().map(|d| d.join("fractus").join("config.toml")),
            Some(PathBuf::from("fractus.toml")),
            Some(PathBuf::from(".fractus.toml")),
        ];

        for config_path in config_dirs.into_iter().flatten() {
            if config_path.exists() {
                return Self::load_from_file(&config_path);
            }
        }

        // No config file found, use defaults
        Ok(Self::default())
    }

    fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config")?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))
    }
}
