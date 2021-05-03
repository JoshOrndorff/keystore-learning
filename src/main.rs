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
use sp_core::crypto::SecretString;

fn main() {
    let keystore_path = "/tmp/joshy-keystore";
    
    // Here is a password we can use, but I don't think the password is the problem. We never even have to supply the password later.
    // I get the same InvalidPassword error later regardless whether I use a password.
    let _password = Some(SecretString::new("hello".into()));

    // Create a place to store my keys.
    let keystore = LocalKeystore::open(keystore_path, None).expect("failed to create local fs keystore");

    // Generate a key.
    // Hypothesis: when using app_crypto you can't rely on the keystore to generate for you.
    // TODO Based on Basti's comments in element, I think you can generate in the keystore. But how?
    // Aura generates these in the runtime by calling the `generate` method on the thing defined by `imple_opaque_keys!`
    let (key_pair, phrase, seed) = Pair::generate_with_phrase(None);

    println!("My phrase is: {:?}", phrase);
    println!("Raw seed: {:?}", seed);

    let structured_public = key_pair.public();
    println!("Structured public key: {:?}", structured_public.as_slice());
    println!("Structured public key: {:?}", structured_public);
    
    // Create a CryptoTypePublicPair
    // This line is pretty much copied from Aura.
    let public_type_pair = structured_public.to_public_crypto_pair();
    println!("{:?}", public_type_pair.0); // CryptoTypeId([115, 114, 50, 53]) (sr25)
    println!("{:?}", public_type_pair.1); // Same key as above

    // Put that key in the keystore
    // You have to provide the phrase so it can derive the private key and do signing
    // You have to put the raw public key because the keystore doesn't know the internals of the cryptography.
    // Aura uses insert_unknown to insert keys when passed in via RPC https://github.com/paritytech/substrate/blob/master/client/rpc/src/author/mod.rs#L97-L109
    keystore.insert_unknown(COMMS, &phrase, structured_public.as_slice()).map_err(|e|panic!("Failed to insert key: {:?}", e)).unwrap();

    // Let's see whether the keystore has the key now that we've inserted it.
    let found_key = keystore.has_keys(&[(structured_public.to_raw_vec(), COMMS)]);
    println!("Does the keystore have the key? {}", found_key);

    // Let's see what all keys we do have for type COMMS
    // This doesn't return any keys (an empty vec)
    let all_keys = keystore.keys(COMMS).expect("keystore should return the keys it has");
    for key in all_keys {
        println!("Have key {:?}", key);
    }

    // Sign a message with my new key
    //TODO can the keystore even sign when it doesn't know the crypto type?
    // I guess it should. Why else would I bother to put my keys there?
    let message = "send the money to Alice".as_bytes();

    // This signing fails. It prints the line:
    // thread 'main' panicked at 'failed to generate a signature: ValidationError("Invalid password")'
    //
    // I've traced the call stack. to https://github.com/paritytech/substrate/blob/master/client/keystore/src/local.rs#L187-L193
    // It matches the correct crypto type (sr25519) and fetches the correct public key bytes
    // Then I traced it to https://github.com/paritytech/substrate/blob/master/client/keystore/src/local.rs#L444
    // It fetches the correct seed phrase, but then generates the wrong pair. The public keys don't match, so it returns the
    // InvalidPassword error which is propogated all the way back to this `main()` function.
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
// pub const POLKADOT: KeyTypeId = KeyTypeId(*b"pdot");
// pub const PHYSICAL_LOCKS: KeyTypeId = KeyTypeId(*b"loks");
