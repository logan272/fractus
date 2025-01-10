use shamir::{Shamir, Share};

fn main() {
    let shamir = Shamir::new(4);
    let dealer = shamir.dealer(b"Hello world!");
    let shares: Vec<Share> = dealer.take(4).collect();
    let secret = shamir.recover(&shares).unwrap();
    assert_eq!(&secret, b"Hello world!");
}
