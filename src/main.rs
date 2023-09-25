// use std::io::Read;
use ed25519_compact::{KeyPair, Noise};
use ed25519_compact::x25519::KeyPair as xK;
// use pqc_kyber::keypair;

fn main() {
    let bob_ik = KeyPair::generate();
    let bob_spk = xK::generate();
    // let bob_OPK = xK::generate();
    let mut rng = rand::thread_rng();
    // let bob_PQKEM = keypair(&mut rng).unwrap();
    let spk_sig = bob_ik.sk.sign(bob_spk.pk.as_ref(), Some(Noise::default()));
    let x = bob_ik.pk.verify(bob_spk.pk.as_ref(), &spk_sig);
    if x.is_err() {
        println!("Could not verify signature")
    } else {
        println!("Signature verified")
    }
}
