use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use ed25519_compact::x25519::KeyPair as xK;
use ed25519_compact::{KeyPair, Noise, Signature};
use ed25519_compact::{PublicKey, SecretKey};
use hkdf::Hkdf;
use pqc_kyber::PublicKey as pqcPublicKey;
use pqc_kyber::{decapsulate, encapsulate, keypair, Keypair, KyberError};
use sha2::Sha256;

fn main() {
    let pkb = PreKeyBundle::new().unwrap();
    let im = InitialMessage::alice_handle_pre_key(&pkb.0);
    bob_handle_initial_message(&im, &pkb.1)
}

#[derive(Debug)]
struct PreKeyBundle {
    ik: PublicKey,
    spk: ed25519_compact::x25519::PublicKey,
    opk: ed25519_compact::x25519::PublicKey,
    spk_sig: Signature,
    opk_sig: Signature,
    pqkem: pqcPublicKey,
    pqkem_sig: Signature,
}

#[derive(Debug)]
struct PrivateKeyBundle {
    ik: SecretKey,
    spk: SecretKey,
    opk: SecretKey,
    pqkem: Keypair,
}

impl PreKeyBundle {
    fn new() -> Result<(PreKeyBundle, PrivateKeyBundle), KyberError> {
        let bob_ik = KeyPair::generate();
        let bob_spk_ed25519 = KeyPair::generate();
        let bob_opk_ed25519 = KeyPair::generate();
        let bob_spk =
            ed25519_compact::x25519::PublicKey::from_ed25519(&bob_spk_ed25519.pk).unwrap();
        let bob_opk =
            ed25519_compact::x25519::PublicKey::from_ed25519(&bob_opk_ed25519.pk).unwrap();
        let spk_sig = bob_ik.sk.sign(bob_spk.as_ref(), Some(Noise::default()));
        let opk_sig = bob_ik.sk.sign(bob_opk.as_ref(), Some(Noise::default()));
        let mut rng = rand::thread_rng();
        let bob_pqkem = keypair(&mut rng)?;
        let pqkem_sig = bob_ik
            .sk
            .sign(bob_pqkem.public.as_ref(), Some(Noise::default()));
        Ok((
            PreKeyBundle {
                ik: bob_ik.pk,
                spk: bob_spk,
                opk: bob_opk,
                spk_sig,
                opk_sig,
                pqkem: bob_pqkem.public,
                pqkem_sig,
            },
            PrivateKeyBundle {
                ik: bob_ik.sk,
                spk: bob_spk_ed25519.sk,
                opk: bob_opk_ed25519.sk,
                pqkem: bob_pqkem,
            },
        ))
    }
}

#[derive(Debug)]
struct InitialMessage {
    ik: PublicKey,
    ed: ed25519_compact::x25519::PublicKey,
    ct: [u8; 1568],
    ect: Vec<u8>,
    nonce: Nonce<Aes256Gcm>
}

impl InitialMessage {
    pub fn alice_handle_pre_key(pkb: &PreKeyBundle) -> InitialMessage {
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
        println!("{:?}", ss);
        let ct: [u8; 1568] = ct;
        let bob_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&pkb.ik).unwrap();
        let alice_ed_ik = KeyPair::generate();
        let alice_ik = ed25519_compact::x25519::SecretKey::from_ed25519(&alice_ed_ik.sk).unwrap();
        let alice_ek = xK::generate();
        let dh1 = pkb.spk.dh(&alice_ik).unwrap();
        let dh2 = bob_ik_x25519.dh(&alice_ek.sk).unwrap();
        let dh3 = pkb.spk.dh(&alice_ek.sk).unwrap();
        let dh4 = pkb.opk.dh(&alice_ek.sk).unwrap();
        let sum = [
            dh1.as_slice(),
            dh2.as_slice(),
            dh3.as_slice(),
            dh4.as_slice(),
            ss.as_slice(),
        ]
        .concat();
        let sk = Hkdf::<Sha256>::new(None, sum.as_slice());
        let data = "alice".as_bytes();

        // AES starts
        let mut key: [u8; 32] = [0; 32];
        sk.expand(data, &mut key).unwrap();
        let key: &[u8; 32] = &key;
        let key: &Key<Aes256Gcm> = key.into();
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let ciphertext = cipher.encrypt(&nonce, b"totally secret".as_ref()).unwrap();
        InitialMessage {
            ik: alice_ed_ik.pk,
            ed: alice_ek.pk,
            ct,
            ect: ciphertext,
            nonce
        }
    }
}

fn bob_handle_initial_message(im: &InitialMessage, skb: &PrivateKeyBundle) {
    let alice_ik_x25519 = ed25519_compact::x25519::PublicKey::from_ed25519(&im.ik).unwrap();
    let bob_ik_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.ik).unwrap();
    let bob_opk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.opk).unwrap();
    let bob_spk_x25519 = ed25519_compact::x25519::SecretKey::from_ed25519(&skb.spk).unwrap();
    let ss = decapsulate(&im.ct, &skb.pqkem.secret).unwrap();
    let dh1 = alice_ik_x25519.dh(&bob_spk_x25519).unwrap();
    let dh2 = im.ed.dh(&bob_ik_x25519).unwrap();
    let dh3 = im.ed.dh(&bob_spk_x25519).unwrap();
    let dh4 = im.ed.dh(&bob_opk_x25519).unwrap();
    let sum = [
        dh1.as_slice(),
        dh2.as_slice(),
        dh3.as_slice(),
        dh4.as_slice(),
        ss.as_slice(),
    ]
    .concat();
    let sk = Hkdf::<Sha256>::new(None, sum.as_slice());
    let mut key: [u8; 32] = [0; 32];
    let data = "alice".as_ref();
    sk.expand(data, &mut key).unwrap();
    let key: &[u8; 32] = &key;
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(&im.nonce, im.ect.as_ref()).unwrap();
    let plaintext = String::from_utf8(plaintext).unwrap();
    println!("{}", plaintext)
}
