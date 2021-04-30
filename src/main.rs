use sc_keystore::LocalKeystore;
use sp_application_crypto::{CryptoTypePublicPair, KeyTypeId, Pair as _, Public as _};

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

use app_sr25519::{Signature, Pair, Public};

fn main() {
    // Create a place to store my keys.
    let keystore = LocalKeystore::in_memory();

    // Generate a key.
    // Hypothesis: when using app_crypto you can't rely on the keystore to generate for you.
    // TODO figure out where Aura generates them. (In the runtime API I guess)
    let (key_pair, phrase, raw_public_key) = Pair::generate_with_phrase(None);

    println!("Raw        public key: {:?}", raw_public_key);

    let structured_public = Public::from_slice(&raw_public_key);
    println!("Structured public key: {:?}", structured_public.as_slice());
    println!("Structured public key: {:?}", structured_public);
    
    // This line is pretty much copied from Aura.
    let public_type_pair = structured_public.to_public_crypto_pair();

    // Put that key in the keystore
    // You have to provide the phrase so it can derive the private key and do signing
    // You have to put the raw public key because the keystore doesn't know the internals of the cryptography.
    // Aura uses insert_unknown to insert keys when passed in via RPC https://github.com/paritytech/substrate/blob/master/client/rpc/src/author/mod.rs#L97-L109
    keystore.insert_unknown(COMMS, &phrase, &raw_public_key).map_err(|e|panic!("Failed to insert key: {:?}", e)).unwrap();

    // Let's see whether the keystore has the key now that we've inserted it.
    // It doesn't have the key, so that explains why it couldn't sign.
    let found_key = keystore.has_keys(&[(raw_public_key.to_vec(), COMMS)]);
    println!("Does the keystore have the key? {}", found_key);

    // Sign a message with my new key
    //TODO can the keystore even sign when it doesn't know the crypto type?
    // Am I supposed to get the keys themselves out to sign with? Doesn't seem like the keystore should be giving the keys out.
    let message = "send the money to Alice".as_bytes();
    let signature_bytes = keystore
        .sign_with(
            COMMS,
            &public_type_pair,
            message,
        )
        .map_err(|e| panic!("failed to generate a signature: {:?}", e)).unwrap();
    println!("Signature bytes are {:?}", signature_bytes);

    // Convert the signature bytes into a structured signature. First make sure it's the right length.
    if signature_bytes.len() != 64 {
        panic!(
            "signature was the wrong length. Expected 64 bytes, got {}",
            signature_bytes.len()
        );
    }

    use sp_application_crypto::TryFrom;
    let signature = Signature::try_from(signature_bytes).unwrap();


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
