//! Share representation and serialization for Shamir's Secret Sharing.
use super::gf256::GF256;

/// A single share in Shamir's Secret Sharing scheme.
///
/// Each share consists of an x-coordinate (evaluation point) and a vector
/// of y-coordinates (polynomial evaluations for each byte of the secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// The x-coordinate (evaluation point) for this share
    pub x: GF256,
    /// The y-coordinates (polynomial evaluations for each byte)
    pub y: Vec<GF256>,
}

impl Share {
    /// Creates a new share with the given x-coordinate and y-values.
    pub fn new(x: GF256, y: Vec<GF256>) -> Self {
        Self { x, y }
    }

    /// Returns the x-coordinate of this share.
    pub fn x(&self) -> GF256 {
        self.x
    }

    /// Returns a reference to the y-coordinates of this share.
    pub fn y(&self) -> &[GF256] {
        &self.y
    }

    /// Returns the length of this share (number of y-coordinates + 1 for x).
    pub fn len(&self) -> usize {
        self.y.len() + 1
    }

    /// Returns true if this share has no y-coordinates.
    pub fn is_empty(&self) -> bool {
        self.y.is_empty()
    }

    /// Serializes this share to a byte vector.
    ///
    /// The format is: [x_byte, y1_byte, y2_byte, ...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len());
        bytes.push(self.x.0);
        bytes.extend(self.y.iter().map(|gf| gf.0));
        bytes
    }

    /// Deserializes a share from a byte slice.
    ///
    /// # Errors
    /// Returns an error if the input is too short (less than 2 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 2 {
            return Err("A Share must be at least 2 bytes long");
        }

        let x = GF256(bytes[0]);
        let y = bytes[1..].iter().map(|&b| GF256(b)).collect();
        Ok(Self { x, y })
    }
}

impl std::fmt::Display for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share(x={}, y=[", self.x)?;
        for (i, y_val) in self.y.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", y_val)?;
        }
        write!(f, "])")
    }
}

impl core::convert::TryFrom<&[u8]> for Share {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Share, Self::Error> {
        Share::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_creation() {
        let x = GF256(5);
        let y = vec![GF256(10), GF256(20), GF256(30)];
        let share = Share::new(x, y.clone());

        assert_eq!(share.x(), x);
        assert_eq!(share.y(), &y);
        assert_eq!(share.len(), 4); // 1 x + 3 y values
        assert!(!share.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let original = Share::new(GF256(42), vec![GF256(100), GF256(200), GF256(50)]);

        let bytes = original.to_bytes();
        let recovered = Share::from_bytes(&bytes).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_invalid_deserialization() {
        assert!(Share::from_bytes(&[]).is_err());
        assert!(Share::from_bytes(&[42]).is_err());
        assert!(Share::from_bytes(&[42, 100]).is_ok());
    }

    #[test]
    fn test_display() {
        let share = Share::new(GF256(1), vec![GF256(2), GF256(3)]);
        let display = format!("{}", share);
        assert_eq!(display, "Share(x=1, y=[2, 3])");
    }
}
