use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::PublicKey;
use ed25519_compact::x25519::KeyPair as xK;
use pqc_kyber::{keypair, Keypair};

fn main() {
    println!("{:?}", PrekeyBundle::new())
}

#[derive(Debug)]
struct PrekeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: Keypair,
    pqkem_sig: Signature
}

impl PrekeyBundle {
    fn new() -> PrekeyBundle {
        let bob_ik = KeyPair::generate();
        let bob_spk = xK::generate();
        let bob_opk = xK::generate();
        let spk_sig = bob_ik.sk.sign(bob_spk.pk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.pk.as_ref(), Some(Noise::default()));
        let mut rng = rand::thread_rng();
        let bob_pqkem = keypair(&mut rng).unwrap();
        let pqkem_sig = bob_ik.sk.sign(bob_pqkem.public.as_ref(), Some(Noise::default()));
        PrekeyBundle{ ik: bob_ik.pk, spk: bob_spk.pk, opk: bob_opk.pk, spk_sig, opk_sig, pqkem: bob_pqkem, pqkem_sig }
    }
}