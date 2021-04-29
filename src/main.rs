use sc_keystore::LocalKeystore;
use sp_application_crypto::{CryptoTypePublicPair, KeyTypeId, Pair};
use sp_core::sr25519::{CRYPTO_ID as SR25519, Pair as SrPair, Signature as SrSignature};

// I know the docs say I should start with the async version, but I want to be
// sure I can copy code from Aura, so I'm starting with sync.
use sp_keystore::SyncCryptoStore;

fn main() {
    // Create a place to store my keys.
    let keystore = LocalKeystore::in_memory();

    // Generate a key. I'll use sr25519
    let my_public_key = keystore.sr25519_generate_new(COMMS, None).unwrap();

    println!("My public key is: {}", my_public_key);

    // Sign a message with my new key
    let message = "send the money to Alice".as_bytes();
    let signature_bytes = keystore
        .sign_with(
            COMMS,
            &CryptoTypePublicPair(SR25519, my_public_key.0.to_vec()),
            message,
        )
        .unwrap();
    println!("Signature bytes are {:?}", signature_bytes);

    // Convert the signature bytes into a structured signature. First make sure it's the right length.
    if signature_bytes.len() != 64 {
        panic!("signature was the wrong length. Expected 64 bytes, got {}", signature_bytes.len());
    }
    let signature = SrSignature::from_slice(&signature_bytes);

    // Verify that signature.
    let successful = SrPair::verify(&signature, message, &my_public_key);
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
