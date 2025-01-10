use super::gf256::GF256;

#[derive(Clone, Debug)]
pub struct Share {
    pub x: GF256,
    pub y: Vec<GF256>,
}

impl From<&Share> for Vec<u8> {
    fn from(s: &Share) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(s.y.len() + 1);
        bytes.push(s.x.0);
        bytes.extend(s.y.iter().map(|p| p.0));
        bytes
    }
}

impl core::convert::TryFrom<&[u8]> for Share {
    type Error = &'static str;

    fn try_from(s: &[u8]) -> Result<Share, Self::Error> {
        if s.len() < 2 {
            Err("A Share must be at least 2 bytes long")
        } else {
            let x = GF256(s[0]);
            let y = s[1..].iter().map(|p| GF256(*p)).collect();
            Ok(Share { x, y })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Share, GF256};
    use core::convert::TryFrom;

    #[test]
    fn vec_from_share_works() {
        let share = Share {
            x: GF256(1),
            y: vec![GF256(2), GF256(3)],
        };
        let bytes = Vec::from(&share);
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn share_from_u8_slice_works() {
        let bytes = [1, 2, 3];
        let share = Share::try_from(&bytes[..]).unwrap();
        assert_eq!(share.x, GF256(1));
        assert_eq!(share.y, vec![GF256(2), GF256(3)]);
    }
}
