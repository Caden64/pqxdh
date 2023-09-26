use argon2::Version;
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use ed25519_compact::x25519::KeyPair as xK;
use pqc_kyber::{keypair, Keypair, KyberError};
use pqc_kyber::PublicKey as pqcPublicKey;

fn main() {
    let pkb = PreKeyBundle::new().unwrap();
    println!("{:?}", pkb.0.ik)
}

#[derive(Debug)]
struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: pqcPublicKey,
    pqkem_sig: Signature
}

#[derive(Debug)]
struct PrivateKeyBundle {
    ik: SecretKey,
    spk: ed25519_compact::x25519::SecretKey,
    opk: ed25519_compact::x25519::SecretKey,
    pqkem: Keypair
}

impl PreKeyBundle {
    fn new() -> Result<(PreKeyBundle, PrivateKeyBundle), KyberError> {
        let bob_ik = KeyPair::generate();
        let bob_spk = xK::generate();
        let bob_opk = xK::generate();
        let spk_sig = bob_ik.sk.sign(bob_spk.pk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.pk.as_ref(), Some(Noise::default()));
        let mut rng = rand::thread_rng();
        let bob_pqkem = keypair(&mut rng)?;
        let pqkem_sig = bob_ik.sk.sign(bob_pqkem.public.as_ref(), Some(Noise::default()));
        Ok((PreKeyBundle {
            ik: bob_ik.pk,
            spk: bob_spk.pk,
            opk: bob_opk.pk,
            spk_sig: spk_sig,
            opk_sig: opk_sig,
            pqkem: bob_pqkem.public,
            pqkem_sig
        }, PrivateKeyBundle {
            ik: bob_ik.sk,
            spk: bob_spk.sk,
            opk: bob_opk.sk,
            pqkem: bob_pqkem,
        }))
    }
}

#[derive(Debug)]
struct InitialMessage<'a> {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: pqc_kyber::Encapsulated,
    ect: argon2::Argon2<'a>,
}