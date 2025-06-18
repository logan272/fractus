//! Utility functions

use anyhow::Result;

/// Check if a string is valid base64
pub fn is_base64(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c.is_whitespace()
        })
        && base64::decode(s.trim()).is_ok()
}

/// Format bytes as human-readable size
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Validate that a threshold and share count are reasonable
pub fn validate_sharing_params(threshold: u8, shares: u8) -> Result<()> {
    if threshold == 0 {
        anyhow::bail!("Threshold must be at least 1");
    }
    if shares < threshold {
        anyhow::bail!("Number of shares must be at least the threshold");
    }
    Ok(())
}
