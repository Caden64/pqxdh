use rand::rngs::OsRng;
use xeddsa::Sign;
use xeddsa::xed25519::{PrivateKey, PublicKey};
use pqc_kyber::Keypair;
use pqc_kyber::PublicKey as pqcPublicKey;

const XEDDSA_KEY_LEN: usize = 32;
const XEDDSA_SIG_LEN: usize = 64;
fn main() {
    let bundle = PreKeyBundle::new();
    println!("Bundle {:?}", bundle)
}

#[derive(Debug)]
struct PreKeyBundle {
    pub_curve_ik: [u8; XEDDSA_KEY_LEN],
    pub_signed_curve_pk: [u8; XEDDSA_KEY_LEN],
    sig_signed_curve_pk: [u8; XEDDSA_SIG_LEN],
    pqkem: pqcPublicKey,
    sig_signed_pqc_pk: [u8; XEDDSA_SIG_LEN],
    pub_curve_opk_pk: [u8; XEDDSA_KEY_LEN]
}

#[derive(Debug)]
struct PrivateKeyBundle {
    priv_curve_ik: [u8; XEDDSA_KEY_LEN],
    priv_signed_curve: [u8; XEDDSA_KEY_LEN],
    pqkem: Keypair,
    priv_curve_opk: [u8; XEDDSA_KEY_LEN]
}

impl PreKeyBundle {
    fn new() -> (PreKeyBundle, PrivateKeyBundle) {
        let priv_in: [u8; XEDDSA_KEY_LEN] = rand::random();
        let priv_key = PrivateKey::from(&priv_in);
        let pub_key = PublicKey::from(&x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_in)));
        let priv_in: [u8; XEDDSA_KEY_LEN] = rand::random();
        let priv_spk = PrivateKey::from(&priv_in);
        let pub_spk = PublicKey::from(&x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_in)));
        let pub_spk_sig: [u8; XEDDSA_SIG_LEN] = priv_key.sign(&pub_spk.0, OsRng);
        let mut rng = rand::thread_rng();
        let pqc_keys = Keypair::generate(&mut rng).unwrap();
        let pqc_sig: [u8; XEDDSA_SIG_LEN] = priv_key.sign(pqc_keys.public.as_slice(), OsRng);
        let priv_in: [u8; XEDDSA_KEY_LEN] = rand::random();
        let priv_opk = PrivateKey::from(&priv_in);
        let pub_opk = PublicKey::from(&x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(priv_in)));
        (PreKeyBundle{pub_curve_ik: pub_key.0, pub_signed_curve_pk: pub_spk.0, sig_signed_curve_pk: pub_spk_sig, pqkem: pqc_keys.public, sig_signed_pqc_pk: pqc_sig, pub_curve_opk_pk: pub_opk.0 }, 
         PrivateKeyBundle{priv_curve_ik: priv_key.0, priv_signed_curve: priv_spk.0, pqkem: pqc_keys, priv_curve_opk: priv_opk.0 })

    }
}