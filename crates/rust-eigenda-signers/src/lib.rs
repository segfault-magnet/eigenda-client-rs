use ::secp256k1::Message;
use async_trait::async_trait;
// Re-export key types from secp256k1
pub mod secp256k1 {
    pub use ::secp256k1::ecdsa;
    pub use ::secp256k1::ecdsa::RecoverableSignature;
    #[cfg(feature = "private-key-signer")]
    pub use ::secp256k1::SecretKey;
    pub use ::secp256k1::{Message, PublicKey};
}

use std::error::Error;

// Declare modules
mod public_key;
mod signature;

// Re-export the newtype structs
pub use public_key::PublicKey;
pub use signature::RecoverableSignature;

#[cfg(feature = "private-key-signer")]
pub mod local;
#[cfg(feature = "private-key-signer")]
pub use local::PrivateKeySigner;

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
