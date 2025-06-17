//! A robust implementation of Shamir's Secret Sharing over GF(256).
//!
//! This crate provides cryptographically secure secret sharing with integrity
//! verification through CRC32 checksums.

mod gf256;
mod poly;
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
    /// use shamir::Shamir;
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
    /// use shamir::Shamir;
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
    ) -> Result<impl Iterator<Item = Share>> {
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
    /// use shamir::Shamir;
    ///
    /// let shamir = Shamir::new(3).unwrap();
    /// let shares: Vec<_> = shamir.split(b"Hello world!")
    ///     .unwrap()
    ///     .take(5)
    ///     .collect();
    /// assert_eq!(shares.len(), 5);
    /// ```
    #[cfg(feature = "std")]
    pub fn split(&self, secret: &[u8]) -> Result<impl Iterator<Item = Share>> {
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
    /// use shamir::Shamir;
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
}
