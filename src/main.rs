use sc_keystore::LocalKeystore;
use sp_application_crypto::{TryFrom, KeyTypeId, Pair as _, Public as _};

// I know the docs say I should start with the async version, but I want to be
// sure I can copy code from Aura, so I'm starting with sync.
use sp_keystore::SyncCryptoStore;

mod custom_crypto;

use custom_crypto::{Signature as CustomSignature, Pair as CustomPair/*, Public as CustomPublic*/};
use sp_core::sr25519::{Signature as SrSignature, Pair as SrPair/*, Public as SrPublic*/};
use sp_core::ed25519::{Signature as EdSignature, Pair as EdPair/*, Public as EdPublic*/};

// Create some key types for my three pretend use cases
// https://github.com/paritytech/substrate/blob/70ef0afc86cdef0cba09336acffb08bff08540aa/primitives/core/src/crypto.rs#L1156-L1182
pub const COMMS: KeyTypeId = KeyTypeId(*b"comm");
pub const POLKADOT: KeyTypeId = KeyTypeId(*b"pdot");
pub const PHYSICAL_LOCKS: KeyTypeId = KeyTypeId(*b"loks");

/// The example message that well sign in every case. No real need to have a wide variety of messages
/// for this simple example.
const MESSAGE: [u8;23] = *b"send the money to Alice";

fn main() {

    // Create a place to store my keys.
    // This is a filesystem-backed local keystore; same as the one used in Moonbeam.
    let temp_dir = tempfile::tempdir().expect("tempfile gives a good path");
    let keystore_path= temp_dir.path();
    let keystore = LocalKeystore::open(keystore_path, None).expect("failed to create local fs keystore");
    println!("The keystore path is {:?}", keystore_path);

    // Generate three keys. One for each of my pretend usecases. I prefer sr25519 so I'll use that.
    let polkadot_sr_public = keystore.sr25519_generate_new(POLKADOT, None).unwrap();
    let comms_sr_public = keystore.sr25519_generate_new(COMMS, None).unwrap();
    let locks_sr_public = keystore.sr25519_generate_new(PHYSICAL_LOCKS, None).unwrap();

    // Let's sign with our Polkadot key
    let signature_bytes = keystore
        .sign_with(
            POLKADOT,
            &polkadot_sr_public.to_public_crypto_pair(),
            &MESSAGE,
        )
        .unwrap();
    println!("Signature bytes are {:?}", signature_bytes);

    // Convert the signature bytes into a structured signature. First make sure it's the right length.
    if signature_bytes.len() != 64 {
        panic!("signature was the wrong length. Expected 64 bytes, got {}", signature_bytes.len());
    }
    let signature = SrSignature::from_slice(&signature_bytes);

    // Verify that signature.
    let successful = SrPair::verify(&signature, &MESSAGE, &polkadot_sr_public);
    if successful {
        println!("Signature was good");
    } else {
        println!("Signature was bogus");
    }

    // Exercise: Construct and verify a signature with each of the other two key types

    // Exercise: Does the signature generated with your polkadot key verify with your comms key?

    // Now a new friend wants to communicate securely with you, but she only uses ed25519.
    // So let's create a comms key to communicate with her, and make sure it works.
    let comms_ed_public = keystore.ed25519_generate_new(COMMS, None).unwrap();

    // Let's sign with our Polkadot key
    let signature_bytes = keystore
        .sign_with(
            COMMS,
            &comms_ed_public.to_public_crypto_pair(),
            &MESSAGE,
        )
        .unwrap();
    let signature = EdSignature::from_slice(&signature_bytes);

    // Verify that signature.
    assert!(EdPair::verify(&signature, &MESSAGE, &comms_ed_public));

    // Exercise: Does the comms ed signature verify with the sr key?

    // Let's see what all keys we have for type COMMS
    let all_keys = keystore.keys(COMMS).expect("keystore should return the keys it has");
    for key in all_keys {
        println!("Found COMMS key: {:?}", key);
    }

    // Now imagine you have a new friend who only communicated with a specific custom type of cryptography.

    // TODO Figure out if we can generate custom crypto types directly in the keystore.
    // Aura generates these in the runtime by calling the `generate` method on the thing defined by `imple_opaque_keys!`
    let (key_pair, phrase, _seed) = CustomPair::generate_with_phrase(None);

    // Calculate some other data about the key that was not directly given back
    let public = key_pair.public();
    let public_type_pair = public.to_public_crypto_pair();
    // println!("{:?}", public_type_pair.0); // CryptoTypeId([115, 114, 50, 53]) (sr25)
    // println!("{:?}", public_type_pair.1);

    // Put that key in the keystore
    // You have to provide the phrase so it can derive the private key and do signing
    // You have to put the raw public key because the keystore doesn't know the internals of the cryptography.
    // Aura uses insert_unknown to insert keys when passed in via RPC https://github.com/paritytech/substrate/blob/master/client/rpc/src/author/mod.rs#L97-L109
    keystore.insert_unknown(COMMS, &phrase, public.as_slice()).map_err(|e|panic!("Failed to insert key: {:?}", e)).unwrap();

    // Let's see whether the keystore has the key now that we've inserted it.
    let found_key = keystore.has_keys(&[(public.to_raw_vec(), COMMS)]);
    println!("Does the keystore have the key? {}", found_key);

    // Let's see what all keys we do have for type COMMS
    // Pay attention, there may be more than you were expecting.
    let all_keys = keystore.keys(COMMS).expect("keystore should return the keys it has");
    for key in all_keys {
        println!("Found COMMS key: {:?}", key);
    }

    // Sign a message with my new key
    let signature_bytes = keystore
        .sign_with(
            COMMS,
            &public_type_pair,
            &MESSAGE,
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
    let signature = CustomSignature::try_from(signature_bytes).unwrap();

    // Verify that signature.
    assert!(CustomPair::verify(&signature, &MESSAGE, &key_pair.public()));

    // Exercise: Switch to the async keystore.
}

