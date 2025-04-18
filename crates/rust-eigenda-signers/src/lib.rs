use ::secp256k1::Message;
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
use std::ops::Deref;
use std::convert::AsRef;

#[cfg(feature = "private-key-signer")]
pub mod local;
#[cfg(feature = "private-key-signer")]
pub use local::PrivateKeySigner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverableSignature(pub secp256k1::ecdsa::RecoverableSignature);
impl From<secp256k1::ecdsa::RecoverableSignature> for RecoverableSignature {
    fn from(sig: secp256k1::ecdsa::RecoverableSignature) -> Self {
        RecoverableSignature(sig)
    }
}

impl Deref for RecoverableSignature {
    type Target = ::secp256k1::ecdsa::RecoverableSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<::secp256k1::ecdsa::RecoverableSignature> for RecoverableSignature {
    fn as_ref(&self) -> &::secp256k1::ecdsa::RecoverableSignature {
        &self.0
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub ::secp256k1::PublicKey);
impl From<::secp256k1::PublicKey> for PublicKey {
    fn from(key: ::secp256k1::PublicKey) -> Self {
        PublicKey(key)
    }
}

impl Deref for PublicKey {
    type Target = ::secp256k1::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<::secp256k1::PublicKey> for PublicKey {
    fn as_ref(&self) -> &::secp256k1::PublicKey {
        &self.0
    }
}

impl PublicKey {
    /// TODO: segfault maybe H160
    pub fn address(&self) -> [u8; 20] {
        let public_key = self.0.serialize_uncompressed();
        // Ethereum address is the last 20 bytes of the Keccak256 hash of the uncompressed public key (excluding the prefix 0x04)
        let hash = keccak256(&public_key[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }
}

/// A trait for signing messages using different key management strategies.
#[async_trait]
pub trait Signer: Send + Sync + std::fmt::Debug {
    type Error: Error + Send + Sync + 'static;

    /// Signs a digest using the signer's key.
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error>;

    /// Returns the public key associated with this signer.
    fn public_key(&self) -> PublicKey;
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
