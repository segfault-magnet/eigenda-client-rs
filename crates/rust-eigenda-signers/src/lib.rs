use ::secp256k1::{Message, PublicKey};
use async_trait::async_trait;
// Re-export key types from secp256k1
pub mod secp256k1 {
    pub use ::secp256k1::ecdsa;
    pub use ::secp256k1::ecdsa::RecoverableSignature;
    #[cfg(feature = "private-key-signer")]
    pub use ::secp256k1::SecretKey;
    pub use ::secp256k1::{Error as SecpError, Message, PublicKey};
}

use std::error::Error;

#[cfg(feature = "private-key-signer")]
pub mod local;
#[cfg(feature = "private-key-signer")]
pub use local::PrivateKeySigner;

/// Represents a potential error during the signing process.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Signer-specific implementation error")]
    SignerSpecific(#[source] Box<dyn Error + Send + Sync>),
}

pub struct RecoverableSignature(pub secp256k1::ecdsa::RecoverableSignature);
impl From<secp256k1::ecdsa::RecoverableSignature> for RecoverableSignature {
    fn from(sig: secp256k1::ecdsa::RecoverableSignature) -> Self {
        RecoverableSignature(sig)
    }
}

impl RecoverableSignature {
    pub fn encode(&self) -> Vec<u8> {
        let (recovery_id, sig) = self.0.serialize_compact();

        let mut signature = vec![0u8; 65];
        signature[0..64].copy_from_slice(&sig);
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

    hasher.update(input);

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);

    output
}
