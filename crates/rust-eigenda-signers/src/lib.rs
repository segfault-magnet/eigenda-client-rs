use async_trait::async_trait;
// Re-export key types from secp256k1
pub use secp256k1::ecdsa;
pub use secp256k1::ecdsa::RecoverableSignature;
pub use secp256k1::{Error as SecpError, Message, PublicKey};

// Restore necessary internal import for the trait signature
use std::error::Error;

#[cfg(feature = "private-key-signer")]
pub mod local;
#[cfg(feature = "private-key-signer")]
pub use local::PrivateKeySigner;
// Conditionally re-export SecretKey
#[cfg(feature = "private-key-signer")]
pub use secp256k1::SecretKey;

/// Represents a potential error during the signing process.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Signer-specific implementation error")]
    SignerSpecific(#[source] Box<dyn Error + Send + Sync>),
}

trait Sealed {}

impl Sealed for RecoverableSignature {}

#[allow(private_bounds)]
pub trait Encode: Sealed {
    fn encode(&self) -> [u8; 65];
}

impl Encode for RecoverableSignature {
    // TODO: segfault find better name
    fn encode(&self) -> [u8; 65] {
        let (recovery_id, sig) = self.serialize_compact();

        let mut signature = [0u8; 65];
        signature.copy_from_slice(&sig);
        signature[64] = recovery_id.to_i32() as u8;
        signature
    }
}

/// A trait for signing messages using different key management strategies.
#[async_trait]
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// Signs a digest using the signer's key.
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, SignerError>;

    /// Returns the public key associated with this signer.
    fn public_key(&self) -> PublicKey;

    /// TODO: segfault maybe H160
    /// Returns the Ethereum address associated with this signer.
    fn address(&self) -> [u8; 20] {
        let public_key = self.public_key().serialize_uncompressed();
        // Ethereum address is the last 20 bytes of the Keccak256 hash of the uncompressed public key (excluding the prefix 0x04)
        let hash = keccak256(&public_key[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }
}

// Helper function to compute Keccak256 hash.
fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}
