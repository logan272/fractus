mod shamir;

use shamir::{Shamir, Share};

fn main() {
    let shamir = Shamir(4);
    let dealer = shamir.dealer(b"Hello world!");
    let shares: Vec<Share> = dealer.take(4).collect();
    let secret = shamir.recover(shares.as_slice()).unwrap();
    assert_eq!(
        unsafe { String::from_utf8_unchecked(secret) },
        "Hello world!"
    );
}
