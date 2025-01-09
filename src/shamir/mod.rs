mod field;
mod poly;
mod share;

use hashbrown::HashSet;

use field::GF256;
pub use share::Share;

/// Tuple struct which implements methods to generate shares and recover secrets over a 256 bits Galois Field.
/// Its only parameter is the minimum shares threshold.
pub struct Shamir(pub u8);

impl Shamir {
    /// This method is useful when `std` is not available. For typical usage
    /// see the `dealer` method.
    ///
    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    /// A random number generator has to be provided.
    ///
    /// Example:
    /// ```
    /// use shamir::{Shamir, Share};
    /// use rand_chacha::rand_core::SeedableRng;
    /// let shamir = Shamir(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let dealer = shamir.dealer_rng(&[1, 2], &mut rng);
    /// // Get 3 shares
    /// let shares: Vec<Share> = dealer.take(3).collect();
    /// ```
    pub fn dealer_rng<R: rand::Rng>(
        &self,
        secret: &[u8],
        rng: &mut R,
    ) -> impl Iterator<Item = Share> {
        let mut polys = Vec::with_capacity(secret.len());

        // Generate a random polynomial for each byte chunk in the secret
        for chunk in secret {
            polys.push(poly::random_polynomial(GF256(*chunk), self.0, rng))
        }

        poly::evaluator(polys)
    }

    /// Given a `secret` byte slice, returns an `Iterator` along new shares.
    /// The maximum number of shares that can be generated is 256.
    ///
    /// Example:
    /// ```
    /// use shamir::{Shamir, Share};
    /// let shamir = Shamir(3);
    /// // Obtain an iterator over the shares for secret [1, 2]
    /// let dealer = shamir.dealer(&[1, 2]);
    /// // Get 3 shares
    /// let shares: Vec<Share> = dealer.take(3).collect();
    /// ```
    #[cfg(feature = "std")]
    pub fn dealer(&self, secret: &[u8]) -> impl Iterator<Item = Share> {
        let mut rng = rand::thread_rng();
        self.dealer_rng(secret, &mut rng)
    }

    /// Given an iterable collection of shares, recovers the original secret.
    /// If the number of distinct shares is less than the minimum threshold an `Err` is returned,
    /// otherwise an `Ok` containing the secret.
    ///
    /// Example:
    /// ```
    /// use shamir::{Shamir, Share};
    /// use rand_chacha::rand_core::SeedableRng;
    /// let shamir = Shamir(3);
    /// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x90; 32]);
    /// let mut shares: Vec<Share> = shamir.dealer_rng(&[1], &mut rng).take(3).collect();
    /// // Recover original secret from shares
    /// let mut secret = shamir.recover(&shares);
    /// // Secret correctly recovered
    /// assert!(secret.is_ok());
    /// // Remove shares for demonstration purposes
    /// shares.clear();
    /// secret = shamir.recover(&shares);
    /// // Not enough shares to recover secret
    /// assert!(secret.is_err());
    /// ```
    pub fn recover<'a, T>(&self, shares: T) -> Result<Vec<u8>, &str>
    where
        T: IntoIterator<Item = &'a Share>,
        T::IntoIter: Iterator<Item = &'a Share>,
    {
        let mut len: Option<usize> = None;
        let mut keys: HashSet<u8> = HashSet::new();
        let mut values: Vec<Share> = Vec::new();

        for share in shares.into_iter() {
            if len.is_none() {
                len = Some(share.y.len());
            }

            if Some(share.y.len()) != len {
                return Err("All shares must have the same length");
            } else {
                keys.insert(share.x.0);
                values.push(share.clone());
            }
        }

        if keys.is_empty() || (keys.len() < self.0 as usize) {
            Err("Not enough shares to recover original secret")
        } else {
            Ok(poly::interpolate(values.as_slice()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Shamir, Share};

    impl Shamir {
        #[cfg(not(feature = "std"))]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item = Share> {
            use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

            let mut rng = ChaCha8Rng::from_seed([0x90; 32]);
            self.dealer_rng(secret, &mut rng)
        }

        #[cfg(feature = "std")]
        fn make_shares(&self, secret: &[u8]) -> impl Iterator<Item = Share> {
            self.dealer(secret)
        }
    }

    #[test]
    fn test_insufficient_shares_err() {
        let shamir = Shamir(255);
        let shares: Vec<Share> = shamir.make_shares(&[1]).take(254).collect();
        let secret = shamir.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_duplicate_shares_err() {
        let shamir = Shamir(255);
        let mut shares: Vec<Share> = shamir.make_shares(&[1]).take(255).collect();
        shares[1] = Share {
            x: shares[0].x.clone(),
            y: shares[0].y.clone(),
        };
        let secret = shamir.recover(&shares);
        assert!(secret.is_err());
    }

    #[test]
    fn test_integration_works() {
        let shamir = Shamir(255);
        let shares: Vec<Share> = shamir.make_shares(&[1, 2, 3, 4]).take(255).collect();
        let secret = shamir.recover(&shares).unwrap();
        assert_eq!(secret, vec![1, 2, 3, 4]);
    }
}
