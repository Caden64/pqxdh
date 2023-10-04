use sha2::Sha256;
use hkdf::Hkdf;
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use ed25519_compact::x25519::KeyPair as xK;
use pqc_kyber::{keypair, Keypair, KyberError, encapsulate};
use pqc_kyber::PublicKey as pqcPublicKey;
use libaes::Cipher;
use rand::Rng;

fn main() {
    let pkb = PreKeyBundle::new().unwrap();
    let im = InitialMessage::alice_handle_pre_key(&pkb.0);
    bob_handle_initial_message(&im, &pkb.1, &pkb.0)
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
            spk_sig,
            opk_sig,
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
struct InitialMessage {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: [u8; 1568],
    ect: Vec<u8>,
}

impl InitialMessage {
    pub fn alice_handle_pre_key(pkb: &PreKeyBundle) -> InitialMessage{
        if let Err(e) = pkb.ik.verify(pkb.spk.as_ref(), &pkb.spk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.opk.as_ref(), &pkb.opk_sig) {
            panic!("Error: {}", e)
        }
        if let Err(e) = pkb.ik.verify(pkb.pqkem.as_ref(), &pkb.pqkem_sig) {
            panic!("Error: {}", e)
        }
        let mut rng = rand::thread_rng();
        let (ct, ss) = encapsulate(&pkb.pqkem, &mut rng).unwrap();
        let ct: [u8; 1568] = ct;
        let bob_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&pkb.ik).unwrap();
        let alice_ed_ik = KeyPair::generate();
        let alice_ik = ed25519_compact::x25519::SecretKey::from_ed25519(&alice_ed_ik.sk).unwrap();
        let alice_ek = xK::generate();
        let dh1 = pkb.spk.dh(&alice_ik).unwrap();
        let dh2 = bob_ik_x25519.dh(&alice_ek.sk).unwrap();
        let dh3 = pkb.spk.dh(&alice_ek.sk).unwrap();
        let dh4 = pkb.opk.dh(&alice_ek.sk).unwrap();
        let sum = [dh1.as_ref(), dh2.as_ref(), dh3.as_ref(), dh4.as_ref(), ss.as_slice()].concat();
        let sk = Hkdf::<Sha256>::new(None, sum.as_slice());
        let data = "alice".as_bytes();
        let mut okm: [u8; 42] = [0; 42];
        sk.expand(data, &mut okm).unwrap();
        let ad = [pkb.ik.as_slice(),alice_ed_ik.pk.as_slice()].concat();
        let key: [u8; 32] = rng.gen::<[u8; 32]>();
        println!("{:?}", &key);
        let cipher = Cipher::new_256(&key);
        let encrypted = cipher.cbc_encrypt([ad.as_slice(), sum.as_slice()].concat().as_slice(), &okm);
        InitialMessage{
            ik: alice_ed_ik.pk,
            ed: alice_ek.pk,
            ct,
            ect: encrypted,
        }
    }
}

fn bob_handle_initial_message(im: &InitialMessage, skb: &PrivateKeyBundle, pkb: &PreKeyBundle) {
    let alice_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&im.ik).unwrap();
    // need to convert private key bundle to have the ed25519 keys and not x25519 keys
}