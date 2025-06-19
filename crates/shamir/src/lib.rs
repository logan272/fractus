//! A robust implementation of Shamir's Secret Sharing over GF(256).
//!
//! This crate provides cryptographically secure secret sharing with integrity
//! verification through CRC32 checksums.

pub mod gf256;
pub mod poly;
mod share;

use gf256::GF256;
use hashbrown::HashSet;
pub use share::Share;

/// Errors that can occur during secret sharing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Threshold must be between 1 and 255
    InvalidThreshold,
    /// Not enough shares provided to recover the secret
    InsufficientShares { required: u8, provided: usize },
    /// Shares have inconsistent lengths
    InconsistentShareLength,
    /// Duplicate shares detected (same x-coordinate)
    DuplicateShares(u8),
    /// Checksum verification failed - data may be corrupted
    ChecksumMismatch,
    /// Empty input provided
    EmptyInput,
}

impl std::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidThreshold => write!(f, "Threshold must be between 1 and 255"),
            Self::InsufficientShares { required, provided } => {
                write!(
                    f,
                    "Need at least {} shares, but only {} provided",
                    required, provided
                )
            }
            Self::InconsistentShareLength => write!(f, "All shares must have the same length"),
            Self::DuplicateShares(x) => write!(f, "Duplicate share with x-coordinate: {}", x),
            Self::ChecksumMismatch => {
                write!(f, "Checksum verification failed - data may be corrupted")
            }
            Self::EmptyInput => write!(f, "Cannot process empty input"),
        }
    }
}

impl std::error::Error for ShamirError {}

pub type Result<T> = std::result::Result<T, ShamirError>;

/// Implements Shamir's Secret Sharing over GF(256).
///
/// This struct provides methods to split secrets into shares and recover them
/// with a configurable threshold. Each secret is protected with a CRC32 checksum
/// for integrity verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shamir {
    threshold: u8,
}

impl Shamir {
    /// Creates a new Shamir instance with the specified threshold.
    ///
    /// # Arguments
    /// * `threshold` - Minimum number of shares required to recover the secret (1-255)
    ///
    /// # Errors
    /// Returns `ShamirError::InvalidThreshold` if threshold is 0 or greater than 255.
    ///
    /// # Examples
    /// ```
    /// use fractus_shamir::Shamir;
    /// let shamir = Shamir::new(3).unwrap();
    /// assert_eq!(shamir.threshold(), 3);
    /// ```
    pub fn new(threshold: u8) -> Result<Self> {
        if threshold == 0 {
            return Err(ShamirError::InvalidThreshold);
        }
        Ok(Self { threshold })
    }

    /// Returns the minimum number of shares required to recover the secret.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Maximum number of shares that can be generated (255).
    pub const MAX_SHARES: u8 = 255;

    /// Splits a secret into shares using the provided random number generator.
    ///
    /// This is the core method for generating shares. It appends a CRC32 checksum
    /// to the secret for integrity verification during recovery.
    ///
    /// # Arguments
    /// * `secret` - The secret to split into shares
    /// * `rng` - Random number generator for polynomial coefficients
    ///
    /// # Returns
    /// An iterator yielding up to 255 shares
    ///
    /// # Errors
    /// Returns `ShamirError::EmptyInput` if the secret is empty.
    ///
    /// # Examples
    /// ```
    /// use fractus_shamir::Shamir;
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let shamir = Shamir::new(3).unwrap();
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let shares: Vec<_> = shamir.split_with_rng(b"Hello world!", &mut rng)
    ///     .unwrap()
    ///     .take(5)
    ///     .collect();
    /// assert_eq!(shares.len(), 5);
    /// ```
    pub fn split_with_rng<R: rand::Rng>(
        &self,
        secret: &[u8],
        rng: &mut R,
    ) -> Result<impl Iterator<Item = Share> + use<R>> {
        if secret.is_empty() {
            return Err(ShamirError::EmptyInput);
        }

        let checksum = crc32fast::hash(secret).to_be_bytes();
        let secret_with_checksum = [secret, &checksum].concat();

        // Generate a random polynomial for each byte in the secret+checksum
        let polys: Vec<_> = secret_with_checksum
            .into_iter()
            .map(|byte| poly::random_polynomial(GF256(byte), self.threshold, rng))
            .collect();

        Ok(poly::evaluator(polys))
    }

    /// Splits a secret into shares using the thread-local random number generator.
    ///
    /// This is a convenience method that uses `rand::thread_rng()` internally.
    /// For deterministic behavior or when `std` is not available, use `split_with_rng`.
    ///
    /// # Examples
    /// ```
    /// use fractus_shamir::Shamir;
    ///
    /// let shamir = Shamir::new(3).unwrap();
    /// let shares: Vec<_> = shamir.split(b"Hello world!")
    ///     .unwrap()
    ///     .take(5)
    ///     .collect();
    /// assert_eq!(shares.len(), 5);
    /// ```
    #[cfg(feature = "std")]
    pub fn split(&self, secret: &[u8]) -> Result<impl Iterator<Item = Share> + use<>> {
        let mut rng = rand::thread_rng();
        self.split_with_rng(secret, &mut rng)
    }

    /// Recovers the original secret from a collection of shares.
    ///
    /// The shares are verified for consistency and integrity before recovery.
    /// The recovered secret is validated against its embedded CRC32 checksum.
    ///
    /// # Arguments
    /// * `shares` - Collection of shares to use for recovery
    ///
    /// # Returns
    /// The original secret if recovery is successful
    ///
    /// # Errors
    /// * `ShamirError::InsufficientShares` - Not enough shares provided
    /// * `ShamirError::InconsistentShareLength` - Shares have different lengths
    /// * `ShamirError::DuplicateShares` - Multiple shares with same x-coordinate
    /// * `ShamirError::ChecksumMismatch` - Recovered data fails integrity check
    ///
    /// # Examples
    /// ```
    /// use fractus_shamir::Shamir;
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let shamir = Shamir::new(3).unwrap();
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let shares: Vec<_> = shamir.split_with_rng(b"Hello world!", &mut rng)
    ///     .unwrap()
    ///     .take(3)
    ///     .collect();
    ///
    /// let recovered = shamir.recover(&shares).unwrap();
    /// assert_eq!(&recovered, b"Hello world!");
    /// ```
    pub fn recover<'a, T>(&self, shares: T) -> Result<Vec<u8>>
    where
        T: IntoIterator<Item = &'a Share>,
        T::IntoIter: Iterator<Item = &'a Share>,
    {
        let shares: Vec<&Share> = shares.into_iter().collect();

        if shares.is_empty() {
            return Err(ShamirError::InsufficientShares {
                required: self.threshold,
                provided: 0,
            });
        }

        // Validate share consistency
        let expected_len = shares[0].y.len();
        let mut unique_x_coords = HashSet::new();

        for share in &shares {
            // Check length consistency
            if share.y.len() != expected_len {
                return Err(ShamirError::InconsistentShareLength);
            }

            // Check for duplicates
            if !unique_x_coords.insert(share.x.0) {
                return Err(ShamirError::DuplicateShares(share.x.0));
            }
        }

        // Check if we have enough shares
        if shares.len() < self.threshold as usize {
            return Err(ShamirError::InsufficientShares {
                required: self.threshold,
                provided: shares.len(),
            });
        }

        // Take only the required number of shares for efficiency
        let shares_for_recovery: Vec<Share> = shares
            .into_iter()
            .take(self.threshold as usize)
            .cloned()
            .collect();

        // Perform polynomial interpolation
        let mut recovered_with_checksum = poly::interpolate(&shares_for_recovery);

        // Verify we have enough bytes for the checksum
        if recovered_with_checksum.len() < 4 {
            return Err(ShamirError::ChecksumMismatch);
        }

        // Split the recovered data and checksum
        let checksum_bytes = recovered_with_checksum.split_off(recovered_with_checksum.len() - 4);
        let secret = recovered_with_checksum;

        // Verify checksum
        let expected_checksum = crc32fast::hash(&secret).to_be_bytes();
        if checksum_bytes != expected_checksum {
            return Err(ShamirError::ChecksumMismatch);
        }

        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use std::collections::HashSet;

    #[test]
    fn test_threshold_validation() {
        assert!(Shamir::new(0).is_err());
        assert!(Shamir::new(1).is_ok());
        assert!(Shamir::new(255).is_ok());
    }

    #[test]
    fn test_empty_secret() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
        assert!(shamir.split_with_rng(&[], &mut rng).is_err());
    }

    #[test]
    fn test_basic_split_and_recover() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
        let secret = b"Hello, Shamir!";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        let recovered = shamir.recover(&shares[..3]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);

        let shares: Vec<_> = shamir
            .split_with_rng(b"test", &mut rng)
            .unwrap()
            .take(2)
            .collect();

        let result = shamir.recover(&shares);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares {
                required: 3,
                provided: 2
            })
        ));
    }

    #[test]
    fn test_duplicate_shares() {
        let shamir = Shamir::new(2).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);

        let mut shares: Vec<_> = shamir
            .split_with_rng(b"test", &mut rng)
            .unwrap()
            .take(2)
            .collect();

        shares.push(shares[0].clone()); // Add duplicate

        let result = shamir.recover(&shares);
        assert!(matches!(result, Err(ShamirError::DuplicateShares(_))));
    }

    #[test]
    fn test_threshold_getter() {
        let shamir = Shamir::new(7).unwrap();
        assert_eq!(shamir.threshold(), 7);
    }

    #[test]
    fn test_single_byte_secret() {
        let shamir = Shamir::new(2).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1; 32]);
        let secret = b"X";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(3)
            .collect();

        let recovered = shamir.recover(&shares[..2]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_large_secret() {
        let shamir = Shamir::new(5).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([2; 32]);

        // Create a 1KB secret
        let secret: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();

        let shares: Vec<_> = shamir
            .split_with_rng(&secret, &mut rng)
            .unwrap()
            .take(7)
            .collect();

        let recovered = shamir.recover(&shares[..5]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_very_large_secret() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([3; 32]);

        // Create a 10KB secret with random-ish data
        let secret: Vec<u8> = (0..10240).map(|i| ((i * 7 + i / 13) % 256) as u8).collect();

        let shares: Vec<_> = shamir
            .split_with_rng(&secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        let recovered = shamir.recover(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_possible_byte_values() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([4; 32]);

        // Test with all possible byte values
        let secret: Vec<u8> = (0..=255).collect();

        let shares: Vec<_> = shamir
            .split_with_rng(&secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        let recovered = shamir.recover(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_minimum_threshold() {
        let shamir = Shamir::new(1).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([5; 32]);
        let secret = b"threshold one";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(3)
            .collect();

        // Should be able to recover with just one share
        let recovered = shamir.recover(&shares[..1]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_maximum_threshold() {
        let shamir = Shamir::new(255).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([6; 32]);
        let secret = b"max threshold";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(255)
            .collect();

        assert_eq!(shares.len(), 255);

        // Need all 255 shares to recover
        let recovered = shamir.recover(&shares).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_exact_threshold_shares() {
        let shamir = Shamir::new(4).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([7; 32]);
        let secret = b"exactly four shares needed";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(4)
            .collect();

        // Should work with exactly the threshold number
        let recovered = shamir.recover(&shares).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_more_than_needed_shares() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([8; 32]);
        let secret = b"more shares than needed";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(10)
            .collect();

        // Should work with more shares than threshold
        let recovered = shamir.recover(&shares).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_share_uniqueness() {
        let shamir = Shamir::new(2).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([10; 32]);
        let secret = b"unique shares test";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(10)
            .collect();

        // All x-coordinates should be unique
        let x_coords: HashSet<u8> = shares.iter().map(|s| s.x().value()).collect();
        assert_eq!(x_coords.len(), shares.len());

        // All x-coordinates should be non-zero
        assert!(!x_coords.contains(&0));
    }

    #[test]
    fn test_share_structure() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([11; 32]);
        let secret = b"structure test";

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        for share in &shares {
            // Y-vector should have the same length as secret + CRC
            assert_eq!(share.y().len(), secret.len() + 4); // +4 for CRC32

            // X-coordinate should be non-zero
            assert_ne!(share.x().value(), 0);
        }
    }

    #[test]
    fn test_no_shares_provided() {
        let shamir = Shamir::new(3).unwrap();
        let empty_shares: Vec<Share> = vec![];

        let result = shamir.recover(&empty_shares);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares {
                required: 3,
                provided: 0
            })
        ));
    }

    #[test]
    fn test_random_vs_deterministic() {
        let shamir = Shamir::new(3).unwrap();
        let secret = b"deterministic test";

        // Generate shares with default RNG (should be different each time)
        let shares1: Vec<_> = shamir.split(secret).unwrap().take(5).collect();
        let shares2: Vec<_> = shamir.split(secret).unwrap().take(5).collect();

        // Shares should be different (different random polynomials)
        assert_ne!(shares1[0].y(), shares2[0].y());

        // But both should recover the same secret
        let recovered1 = shamir.recover(&shares1[..3]).unwrap();
        let recovered2 = shamir.recover(&shares2[..3]).unwrap();
        assert_eq!(recovered1, recovered2);
        assert_eq!(&recovered1, secret);
    }

    #[test]
    fn test_deterministic_with_same_seed() {
        let shamir = Shamir::new(2).unwrap();
        let secret = b"seed test";

        // Same seed should produce identical shares
        let mut rng1 = rand_chacha::ChaCha8Rng::from_seed([42; 32]);
        let mut rng2 = rand_chacha::ChaCha8Rng::from_seed([42; 32]);

        let shares1: Vec<_> = shamir
            .split_with_rng(secret, &mut rng1)
            .unwrap()
            .take(3)
            .collect();

        let shares2: Vec<_> = shamir
            .split_with_rng(secret, &mut rng2)
            .unwrap()
            .take(3)
            .collect();

        // Should be identical
        assert_eq!(shares1.len(), shares2.len());
        for (s1, s2) in shares1.iter().zip(shares2.iter()) {
            assert_eq!(s1.x(), s2.x());
            assert_eq!(s1.y(), s2.y());
        }
    }

    #[test]
    fn test_binary_data() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([14; 32]);

        // Test with binary data including null bytes
        let secret = vec![0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x00, 0x00];

        let shares: Vec<_> = shamir
            .split_with_rng(&secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        let recovered = shamir.recover(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_edge_case_thresholds() {
        // Test various threshold values
        for threshold in [1, 2, 10, 50, 100, 200, 255] {
            let shamir = Shamir::new(threshold).unwrap();
            let mut rng = rand_chacha::ChaCha8Rng::from_seed([threshold as u8; 32]);
            let secret = format!("threshold {}", threshold).into_bytes();

            let shares: Vec<_> = shamir
                .split_with_rng(&secret, &mut rng)
                .unwrap()
                .take(threshold as usize)
                .collect();

            let recovered = shamir.recover(&shares).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn test_multiple_duplicate_shares() {
        let shamir = Shamir::new(2).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([15; 32]);

        let shares: Vec<_> = shamir
            .split_with_rng(b"duplicate test", &mut rng)
            .unwrap()
            .take(2)
            .collect();

        // Create multiple duplicates
        let duplicated_shares = vec![
            shares[0].clone(),
            shares[1].clone(),
            shares[0].clone(), // Duplicate of first
            shares[1].clone(), // Duplicate of second
        ];

        let result = shamir.recover(&duplicated_shares);
        assert!(matches!(result, Err(ShamirError::DuplicateShares(_))));
    }

    #[test]
    fn test_share_serialization_roundtrip() {
        let shamir = Shamir::new(2).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([16; 32]);
        let secret = b"serialization test";

        let original_shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(3)
            .collect();

        // Serialize and deserialize each share
        let mut restored_shares = Vec::new();
        for share in &original_shares {
            let bytes = share.to_bytes();
            let restored = Share::from_bytes(&bytes).unwrap();
            restored_shares.push(restored);
        }

        // Should be able to recover with restored shares
        let recovered = shamir.recover(&restored_shares[..2]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_stress_many_shares() {
        let shamir = Shamir::new(10).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([18; 32]);
        let secret = b"stress test with many shares";

        // Generate many shares
        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(200)
            .collect();

        assert_eq!(shares.len(), 200);

        // All x-coordinates should be unique
        let x_coords: HashSet<u8> = shares.iter().map(|s| s.x().value()).collect();
        assert_eq!(x_coords.len(), 200);

        // Should be able to recover with any subset of 10 shares
        let recovered = shamir.recover(&shares[50..60]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_unicode_data() {
        let shamir = Shamir::new(3).unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([19; 32]);

        // Test with UTF-8 encoded Unicode data
        let secret = "Hello 世界! 🚀".as_bytes();

        let shares: Vec<_> = shamir
            .split_with_rng(secret, &mut rng)
            .unwrap()
            .take(5)
            .collect();

        let recovered = shamir.recover(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);

        // Verify it's still valid UTF-8
        let recovered_string = String::from_utf8(recovered).unwrap();
        assert_eq!(recovered_string, "Hello 世界! 🚀");
    }
}
