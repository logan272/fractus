//! Polynomial operations for Shamir's Secret Sharing.
//!
//! This module provides functions for generating random polynomials,
//! evaluating them at different points, and performing Lagrange interpolation
//! to recover the original secret.

use rand::distributions::{Distribution, Uniform};

use super::gf256::GF256;
use super::share::Share;

/// Performs Lagrange interpolation to recover the secret from shares.
///
/// This function implements the [Lagrange interpolation formula](https://en.wikipedia.org/wiki/Lagrange_polynomial)
/// to find the polynomial that passes through all the given points, then evaluates
/// it at x=0 to recover the original secret.
///
/// # Arguments
/// * `shares` - A slice of shares to use for interpolation
///
/// # Returns
/// A vector of bytes representing the recovered secret with checksum
///
/// # Examples
/// ```
/// use fractus_shamir::{Share, gf256::GF256};
/// use fractus_shamir::poly::interpolate;
///
/// let shares = vec![
///     Share::new(GF256(1), vec![GF256(10)]),
///     Share::new(GF256(2), vec![GF256(20)]),
/// ];
/// let result = interpolate(&shares);
/// ```
pub fn interpolate(shares: &[Share]) -> Vec<u8> {
    if shares.is_empty() {
        return Vec::new();
    }

    let secret_len = shares[0].y.len();
    let mut result = Vec::with_capacity(secret_len);

    // For each byte position in the secret
    for byte_index in 0..secret_len {
        let recovered_byte = lagrange_interpolate_at_zero(shares, byte_index);
        result.push(recovered_byte.0);
    }

    result
}

/// Performs Lagrange interpolation for a specific byte position and evaluates at x=0.
///
/// This is the core of the secret recovery process. For each byte position,
/// we have a polynomial where the shares represent points on that polynomial.
/// We use Lagrange interpolation to find the value at x=0, which is the original secret byte.
///
/// The Lagrange interpolation formula is:
/// f(0) = Σ(j=0 to k-1) y_j * Π(i=0 to k-1, i≠j) (0 - x_i) / (x_j - x_i)
///
/// Since we're evaluating at x=0, this simplifies to:
/// f(0) = Σ(j=0 to k-1) y_j * Π(i=0 to k-1, i≠j) (-x_i) / (x_j - x_i)
/// f(0) = Σ(j=0 to k-1) y_j * Π(i=0 to k-1, i≠j) x_i / (x_j - x_i)
fn lagrange_interpolate_at_zero(shares: &[Share], byte_index: usize) -> GF256 {
    shares
        .iter()
        .map(|share_j| {
            // Calculate the Lagrange basis polynomial for share_j evaluated at x=0
            let basis = shares
                .iter()
                .filter(|share_i| share_i.x != share_j.x)
                .map(|share_i| {
                    // For Lagrange basis: (0 - x_i) / (x_j - x_i) = x_i / (x_j - x_i)
                    share_i.x / (share_j.x - share_i.x)
                })
                .product::<GF256>();

            // Multiply by the y-value for this share and byte position
            basis * share_j.y[byte_index]
        })
        .sum::<GF256>()
}

/// Generates a random polynomial of degree `threshold - 1` with the given constant term.
///
/// The polynomial is represented as a vector of coefficients in descending order of degree:
/// [a_{k-1}, a_{k-2}, ..., a_1, a_0] where a_0 is the secret and a_i are random coefficients.
///
/// For a polynomial f(x) = a_{k-1}*x^{k-1} + ... + a_1*x + a_0, the secret is a_0.
///
/// # Arguments
/// * `secret_byte` - The constant term of the polynomial (the secret byte)
/// * `threshold` - The minimum number of shares needed to recover the secret
/// * `rng` - Random number generator for generating coefficients
///
/// # Returns
/// A vector of coefficients representing the polynomial
///
/// # Examples
/// ```
/// use fractus_shamir::gf256::GF256;
/// use fractus_shamir::poly::random_polynomial;
/// use rand_chacha::rand_core::SeedableRng;
///
/// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
/// let poly = random_polynomial(GF256(42), 3, &mut rng);
/// assert_eq!(poly.len(), 3); // degree 2 polynomial has 3 coefficients
/// assert_eq!(poly[2], GF256(42)); // secret is the constant term
/// ```
pub fn random_polynomial<R: rand::Rng>(
    secret_byte: GF256,
    threshold: u8,
    rng: &mut R,
) -> Vec<GF256> {
    let degree = threshold as usize;
    let mut coefficients = Vec::with_capacity(degree);

    // Generate random coefficients for x^{k-1}, x^{k-2}, ..., x^1
    // We exclude 0 from the random range to ensure the polynomial has the expected degree
    let coefficient_dist = Uniform::new_inclusive(1u8, 255u8);

    for _ in 1..degree {
        let random_coeff = coefficient_dist.sample(rng);
        coefficients.push(GF256(random_coeff));
    }

    // Add the secret as the constant term (coefficient of x^0)
    coefficients.push(secret_byte);

    coefficients
}

/// Returns an iterator that evaluates polynomials at successive x-values.
///
/// This function creates an iterator that evaluates each polynomial in `polys`
/// at x-values from 1 to 255, producing shares. Each polynomial corresponds to
/// one byte of the secret (plus checksum).
///
/// # Arguments
/// * `polys` - Vector of polynomials, where each polynomial represents one byte of the secret
///
/// # Returns
/// An iterator yielding `Share` objects with x-coordinates from 1 to 255
///
/// # Examples
/// ```
/// use fractus_shamir::gf256::GF256;
/// use fractus_shamir::poly::{random_polynomial, evaluator};
/// use rand_chacha::rand_core::SeedableRng;
///
/// let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
/// let poly1 = random_polynomial(GF256(10), 3, &mut rng);
/// let poly2 = random_polynomial(GF256(20), 3, &mut rng);
///
/// let shares: Vec<_> = evaluator(vec![poly1, poly2]).take(5).collect();
/// assert_eq!(shares.len(), 5);
/// assert_eq!(shares[0].y.len(), 2); // 2 bytes in the secret
/// ```
pub fn evaluator(polys: Vec<Vec<GF256>>) -> impl Iterator<Item = Share> {
    (1..=u8::MAX).map(GF256).map(move |x| {
        let y_values: Vec<GF256> = polys
            .iter()
            .map(|polynomial| evaluate_polynomial(polynomial, x))
            .collect();

        Share::new(x, y_values)
    })
}

/// Evaluates a polynomial at a given x-value using Horner's method.
///
/// This function efficiently evaluates a polynomial represented as a coefficient vector
/// using [Horner's method](https://en.wikipedia.org/wiki/Horner%27s_method), which
/// minimizes the number of multiplications required.
///
/// For a polynomial f(x) = a_n*x^n + a_{n-1}*x^{n-1} + ... + a_1*x + a_0
/// represented as [a_n, a_{n-1}, ..., a_1, a_0], Horner's method computes:
/// f(x) = ((a_n * x + a_{n-1}) * x + a_{n-2}) * x + ... + a_0
///
/// # Arguments
/// * `coefficients` - Polynomial coefficients in descending order of degree
/// * `x` - The x-value at which to evaluate the polynomial
///
/// # Returns
/// The value of the polynomial at the given x-coordinate
///
/// # Examples
/// ```
/// use fractus_shamir::gf256::GF256;
/// use fractus_shamir::poly::evaluate_polynomial;
///
/// // Polynomial: 2x^2 + 3x + 5
/// let coeffs = vec![GF256(2), GF256(3), GF256(5)];
/// let result = evaluate_polynomial(&coeffs, GF256(2));
/// // 2*4 + 3*2 + 5 = 8 + 6 + 5 = 19 (in GF256: 2*4 ⊕ 3*2 ⊕ 5)
/// ```
pub fn evaluate_polynomial(coefficients: &[GF256], x: GF256) -> GF256 {
    // Use Horner's method for efficient polynomial evaluation
    // Start with the highest degree coefficient and work down
    coefficients
        .iter()
        .fold(GF256::ZERO, |accumulator, &coefficient| {
            accumulator * x + coefficient
        })
}

/// Validates that a set of polynomials are consistent for secret sharing.
///
/// This function checks that all polynomials have the same degree, which is
/// required for proper secret sharing operation.
///
/// # Arguments
/// * `polys` - The polynomials to validate
/// * `expected_threshold` - The expected threshold (degree + 1)
///
/// # Returns
/// `Ok(())` if valid, or an error message if invalid
pub fn validate_polynomials(polys: &[Vec<GF256>], expected_threshold: u8) -> Result<(), String> {
    if polys.is_empty() {
        return Err("No polynomials provided".to_string());
    }

    let expected_degree = expected_threshold as usize;

    for (i, poly) in polys.iter().enumerate() {
        if poly.len() != expected_degree {
            return Err(format!(
                "Polynomial {} has degree {} but expected degree {}",
                i,
                poly.len(),
                expected_degree
            ));
        }

        // Check that the polynomial actually has the expected degree
        // (highest coefficient should be non-zero)
        if poly.len() > 1 && poly[0].is_zero() {
            return Err(format!("Polynomial {} has zero leading coefficient", i));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_polynomial_evaluation() {
        // Test polynomial: 2x^2 + 3x + 5
        let coeffs = vec![GF256(2), GF256(3), GF256(5)];

        // At x=0: should give constant term (5)
        assert_eq!(evaluate_polynomial(&coeffs, GF256(0)), GF256(5));

        // At x=1: 2*1 + 3*1 + 5 = 2 + 3 + 5 = 4 (in GF256: 2 ⊕ 3 ⊕ 5)
        assert_eq!(evaluate_polynomial(&coeffs, GF256(1)), GF256(4));
    }

    #[test]
    fn test_random_polynomial_structure() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
        let secret = GF256(42);
        let threshold = 3;

        let poly = random_polynomial(secret, threshold, &mut rng);

        // Should have correct length
        assert_eq!(poly.len(), threshold as usize);

        // Secret should be the constant term (last coefficient)
        assert_eq!(poly[poly.len() - 1], secret);

        // All other coefficients should be non-zero (except in extremely rare cases)
        for &coeff in &poly[..poly.len() - 1] {
            assert_ne!(coeff, GF256::ZERO);
        }
    }

    #[test]
    fn test_interpolation_simple() {
        // Create a simple polynomial: f(x) = 5 (constant)
        let shares = vec![
            Share::new(GF256(1), vec![GF256(5)]),
            Share::new(GF256(2), vec![GF256(5)]),
        ];

        let result = interpolate(&shares);
        assert_eq!(result, vec![5]);
    }

    #[test]
    fn test_interpolation_linear() {
        // Test with known polynomial values in GF(256)
        // Let's use a simpler case where we can verify the math

        // Create shares from a known linear polynomial: f(x) = 1x + 5 = x ⊕ 5
        // f(1) = 1 ⊕ 5 = 4
        // f(2) = 2 ⊕ 5 = 7
        let shares = vec![
            Share::new(GF256(1), vec![GF256(4)]),
            Share::new(GF256(2), vec![GF256(7)]),
        ];

        let result = interpolate(&shares);
        // f(0) = 0 ⊕ 5 = 5
        assert_eq!(result, vec![5]);
    }

    #[test]
    fn test_evaluator_consistency() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0; 32]);
        let secret_bytes = vec![GF256(10), GF256(20)];
        let threshold = 3;

        let polys: Vec<_> = secret_bytes
            .iter()
            .map(|&byte| random_polynomial(byte, threshold, &mut rng))
            .collect();

        let shares: Vec<_> = evaluator(polys).take(threshold as usize).collect();

        // All shares should have the same y-vector length
        assert!(shares.iter().all(|s| s.y.len() == secret_bytes.len()));

        // All shares should have different x-coordinates
        let x_coords: std::collections::HashSet<_> = shares.iter().map(|s| s.x.0).collect();
        assert_eq!(x_coords.len(), shares.len());
    }

    #[test]
    fn test_round_trip_secret_sharing() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([42; 32]);
        let original_secret = vec![GF256(100), GF256(200), GF256(50)];
        let threshold = 3;

        // Generate polynomials for each byte
        let polys: Vec<_> = original_secret
            .iter()
            .map(|&byte| random_polynomial(byte, threshold, &mut rng))
            .collect();

        // Generate shares
        let shares: Vec<_> = evaluator(polys).take(threshold as usize).collect();

        // Recover secret
        let recovered_bytes = interpolate(&shares);
        let recovered_secret: Vec<_> = recovered_bytes.into_iter().map(GF256).collect();

        assert_eq!(recovered_secret, original_secret);
    }

    #[test]
    fn test_polynomial_validation() {
        let valid_polys = vec![
            vec![GF256(1), GF256(2), GF256(3)], // degree 2
            vec![GF256(4), GF256(5), GF256(6)], // degree 2
        ];

        assert!(validate_polynomials(&valid_polys, 3).is_ok());

        let invalid_polys = vec![
            vec![GF256(1), GF256(2)],           // degree 1
            vec![GF256(4), GF256(5), GF256(6)], // degree 2
        ];

        assert!(validate_polynomials(&invalid_polys, 3).is_err());
    }

    #[test]
    fn test_empty_input_handling() {
        let empty_shares: Vec<Share> = vec![];
        let result = interpolate(&empty_shares);
        assert!(result.is_empty());

        assert!(validate_polynomials(&[], 3).is_err());
    }

    #[test]
    fn test_horners_method_correctness() {
        // Test that our Horner's method implementation is correct
        // Polynomial: 3x^3 + 2x^2 + x + 5
        let coeffs = vec![GF256(3), GF256(2), GF256(1), GF256(5)];
        let x = GF256(2);

        // Manual calculation in GF256:
        // 3*8 + 2*4 + 1*2 + 5 = 24 + 8 + 2 + 5 = 39
        // But in GF256: 3*8 ⊕ 2*4 ⊕ 1*2 ⊕ 5
        let expected = GF256(3) * (GF256(2) * GF256(2) * GF256(2))
            + GF256(2) * (GF256(2) * GF256(2))
            + GF256(1) * GF256(2)
            + GF256(5);

        assert_eq!(evaluate_polynomial(&coeffs, x), expected);
    }
}
