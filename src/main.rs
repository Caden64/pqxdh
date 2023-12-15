use rand::rngs::OsRng;
use xeddsa::{CalculateKeyPair, Sign, Verify};
use xeddsa::xed25519::{PrivateKey, PublicKey};

const XEDDSA_KEY_LEN: usize = 32;
const XEDDSA_SIG_LEN: usize = 64;
fn main() {
    let priv_in: [u8; XEDDSA_KEY_LEN] = rand::random();
    let priv_key = PrivateKey::from(&priv_in);
    let pub_key = PublicKey::from(&x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_in)));
    let priv_in: [u8; XEDDSA_KEY_LEN] = rand::random();
    let priv_spk = PrivateKey::from(&priv_in);
    let pub_spk = PublicKey::from(&x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_in)));
    let pub_spk_sig: [u8; XEDDSA_SIG_LEN] = priv_key.sign(&pub_spk.0, OsRng);
    let bundle = PreKeyBundle{pub_curve_ik: pub_key.0, pub_signed_curve_pk: pub_spk.0, sig_signed_curve_pk: pub_spk_sig };
    println!("Bundle {:?}", bundle)
}

#[derive(Debug)]
struct PreKeyBundle {
    pub_curve_ik: [u8; XEDDSA_KEY_LEN],
    pub_signed_curve_pk: [u8; XEDDSA_KEY_LEN],
    sig_signed_curve_pk: [u8; XEDDSA_SIG_LEN]
}

/*
    let sig: [u8; XEDDSA_SIG_LEN] = priv_key.sign("Test".as_bytes(), OsRng);
    let valid = pub_key.verify("Test".as_bytes(), &sig);
    println!("seed:{:?}\nkey:{:?}\npub:{:?}\nsig:{:?}\nvalid:{:?}", priv_in, priv_key.0, pub_key.0, sig, valid)
 */