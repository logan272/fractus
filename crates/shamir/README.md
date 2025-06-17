# Fractus-Shamir

[[Crates.io](https://img.shields.io/crates/v/fractus-shamir.svg)](https://crates.io/crates/fractus-shamir)
[[Documentation](https://docs.rs/fractus-shamir/badge.svg)](https://docs.rs/fractus-shamir)
[[License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/logan272/fractus)
[[Build Status](https://github.com/logan272/fractus/workflows/CI/badge.svg)](https://github.com/logan272/fractus/actions)

A robust, secure, and efficient implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) in Rust.

**Fractus-Shamir** allows you to split a secret into multiple shares, where any threshold number of shares can reconstruct the original secret, but fewer shares reveal nothing about the secret.

## 🚀 Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
fractus-shamir = "0.1"
```

### Basic Usage

```rust
use fractus_shamir::{Shamir, Share};

// Create a Shamir instance with threshold 3
let shamir = Shamir::new(3)?;

// Split a secret into shares
let secret = b"Hello, World!";
let shares: Vec<Share> = shamir.split(secret)?
    .take(5) // Generate 5 shares
    .collect();

// Recover the secret using any 3 shares
let recovered = shamir.recover(&shares[0..3])?;
assert_eq!(recovered, secret);
```

### Advanced Usage with Custom RNG

```rust
use fractus_shamir::{Shamir, Share};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};

let shamir = Shamir::new(2)?;
let mut rng = ChaCha8Rng::from_seed([42; 32]);

let shares: Vec<Share> = shamir.split_with_rng(b"secret data", &mut rng)?
    .take(3)
    .collect();

let recovered = shamir.recover(&shares[0..2])?;
assert_eq!(recovered, b"secret data");
```

## Examples

### Basic Secret Sharing

```rust
use fractus_shamir::Shamir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shamir = Shamir::new(3)?;

    // Split a password
    let password = b"super_secret_password";
    let shares: Vec<_> = shamir.split(password)?.take(5).collect();

    println!("Generated {} shares", shares.len());

    // Simulate storing shares in different locations
    let stored_shares = &shares[1..4]; // Use shares 2, 3, 4

    // Recover the password
    let recovered = shamir.recover(stored_shares)?;
    assert_eq!(recovered, password);

    println!("Password recovered successfully!");
    Ok(())
}
```

### Large File Splitting

```rust
use fractus_shamir::Shamir;
use std::fs;

fn split_file() -> Result<(), Box<dyn std::error::Error>> {
    let shamir = Shamir::new(5)?; // Need 5 of 8 shares

    // Read large file
    let file_data = fs::read("large_document.pdf")?;
    println!("File size: {} bytes", file_data.len());

    // Split into shares
    let shares: Vec<_> = shamir.split(&file_data)?.take(8).collect();

    // Save shares to different files
    for (i, share) in shares.iter().enumerate() {
        let filename = format!("share_{}.bin", i + 1);
        fs::write(filename, share.to_bytes())?;
    }

    println!("File split into 8 shares successfully!");
    Ok(())
}
```

### Custom Threshold Scheme

```rust
use fractus_shamir::Shamir;

fn corporate_secret_sharing() -> Result<(), Box<dyn std::error::Error>> {
    // Require 3 out of 5 executives to access the master key
    let shamir = Shamir::new(3)?;

    let master_key = b"master_encryption_key_2024";
    let executive_shares: Vec<_> = shamir.split(master_key)?.take(5).collect();

    // Distribute to executives
    let executives = ["CEO", "CTO", "CFO", "COO", "CISO"];
    for (exec, share) in executives.iter().zip(executive_shares.iter()) {
        println!("Share for {}: {} bytes", exec, share.to_bytes().len());
        // In practice, securely transmit to each executive
    }

    // Later: any 3 executives can recover the key
    let available_shares = &executive_shares[0..3]; // CEO, CTO, CFO present
    let recovered_key = shamir.recover(available_shares)?;
    assert_eq!(recovered_key, master_key);

    println!("Master key recovered by executive consensus!");
    Ok(())
}
```

## Mathematical Background

Shamir's Secret Sharing is based on polynomial interpolation over finite fields:

1. **Secret Encoding**: The secret becomes the constant term of a polynomial
2. **Polynomial Construction**: Generate a random polynomial of degree `threshold - 1`
3. **Share Generation**: Evaluate the polynomial at distinct non-zero points
4. **Secret Recovery**: Use Lagrange interpolation to reconstruct the polynomial and extract the constant term

## References
- [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
- [Finite Field Arithmetic](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
- [Lagrange Interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial)
