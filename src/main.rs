use sc_keystore::LocalKeystore;
use sp_application_crypto::{CryptoTypePublicPair, KeyTypeId, Pair as _,};
use sp_core::sr25519::CRYPTO_ID as SR25519;

// I know the docs say I should start with the async version, but I want to be
// sure I can copy code from Aura, so I'm starting with sync.
use sp_keystore::SyncCryptoStore;

// This is all it takes to use app_crypto. But it seems the module is necessary
//TODO retry removing the module. I found a duplicate definition that may have triggered the error.
mod app_sr25519 {
    use crate::COMMS;
    use sp_application_crypto::{app_crypto, sr25519};
    app_crypto!(sr25519, COMMS);
}

use app_sr25519::{Signature, Pair};

fn main() {
    // Create a place to store my keys.
    let keystore = LocalKeystore::in_memory();

    // Generate a key.
    // Hypothesis: when using app_crypto you can't rely on the keystore to generate for you.
    let (key_pair, phrase, raw_public_key) = app_sr25519::Pair::generate_with_phrase(None);

    // Put that key in the keystore
    // You have to provide the phrase so it can derive the private key and do signing
    // You have to put the raw public key because the keystore doesn't know the internals of the cryptography.
    // Wait, is this right? Can the keystore even sign when it doesn't knwo the details fo the crypto???
    keystore.insert_unknown(COMMS, &phrase, &raw_public_key);

    println!("My public key is: {:?}", raw_public_key);

    // Sign a message with my new key
    //TODO can the keystore eve sign when it doesn't know the crypto type?
    // Am I supposed to get the keys themselves out to sign with? Doesn't seem like the keystore should be giving the keys out.
    let message = "send the money to Alice".as_bytes();
    let signature_bytes = keystore
        .sign_with(
            COMMS,
            //TODO I'm pretty sure the SR25519 has to change. Or maybe it should change but wil work because I'm using the same crypto
            &CryptoTypePublicPair(SR25519, raw_public_key.to_vec()),
            message,
        )
        .unwrap();
    println!("Signature bytes are {:?}", signature_bytes);

    // Convert the signature bytes into a structured signature. First make sure it's the right length.
    if signature_bytes.len() != 64 {
        panic!(
            "signature was the wrong length. Expected 64 bytes, got {}",
            signature_bytes.len()
        );
    }
    let signature = Signature::from(signature_bytes);

    // Verify that signature.
    let successful = Pair::verify(&signature, message, &key_pair.public());
    if successful {
        println!("Signature was good");
    } else {
        println!("Signature was bogus");
    }
}

// More learning ideas

// Some of my friends only communicare with ed25519, so I'll generate a key with that crypto too.

// Sign a message with _both_ of my comms keys

// I should have 4 total keys

// I should have one comms key

// I should have 3 ed25519 keys

// Create some key types for my three pretend use cases
// https://github.com/paritytech/substrate/blob/70ef0afc86cdef0cba09336acffb08bff08540aa/primitives/core/src/crypto.rs#L1156-L1182
pub const COMMS: KeyTypeId = KeyTypeId(*b"comm");
pub const POLKADOT: KeyTypeId = KeyTypeId(*b"pdot");
pub const PHYSICAL_LOCKS: KeyTypeId = KeyTypeId(*b"loks");
