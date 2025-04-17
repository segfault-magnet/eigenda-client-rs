use async_trait::async_trait;
use secp256k1::{ecdsa::RecoverableSignature, Error as SecpError, Message, PublicKey};
use std::error::Error;

#[cfg(feature = "local-signer")]
pub mod local;
#[cfg(feature = "local-signer")]
pub use local::LocalSigner;

/// Represents a potential error during the signing process.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Secp256k1 library error")]
    Secp(#[from] SecpError),
    #[error("Signer-specific implementation error")]
    SignerSpecific(#[source] Box<dyn Error + Send + Sync>),
}

/// A trait for signing messages using different key management strategies.
#[async_trait]
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// Signs a 32-byte digest and returns a recoverable signature.
    ///
    /// # Arguments
    ///
    /// * `digest` - The 32-byte digest to sign.
    ///
    /// # Returns
    ///
    /// A `Result` containing the 65-byte recoverable signature `[R || S || V]` on success,
    /// or a `SignerError` on failure.
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, SignerError>;

    /// Returns the public key associated with this signer.
    fn public_key(&self) -> PublicKey;

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

// // Helper function (assuming keccak256 is available or defined elsewhere)
fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}
