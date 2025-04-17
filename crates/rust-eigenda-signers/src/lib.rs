use async_trait::async_trait;
use secp256k1::{
    ecdsa::{RecoveryId, Signature},
    Error as SecpError, PublicKey,
};
use std::error::Error;

/// Represents a potential error during the signing process.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("Secp256k1 error")]
    Secp(#[source] SecpError),
    #[error("Underlying signer error")]
    SignerImplementation(#[source] Box<dyn Error + Send + Sync>),
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
    async fn sign_digest(&self, digest: [u8; 32]) -> Result<RecoverableSignature, SignerError>;

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

/// Represents a recoverable ECDSA signature, storing the core
/// signature (R, S) and the calculated recovery ID (V).
/// Can generate the 65-byte [R||S||V] format on demand.
#[derive(Debug, Clone)]
pub struct RecoverableSignature {
    pub signature: Signature,
    pub recovery_id: RecoveryId,
}

impl RecoverableSignature {
    /// Returns the signature component (R, S).
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the recovery ID component (V).
    pub fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// Generates the 65-byte [R||S||V] representation.
    pub fn to_rsv_bytes(&self) -> [u8; 65] {
        let sig_bytes = self.signature.serialize_compact(); // This is [R||S]
        let mut result = [0u8; 65];
        result[..64].copy_from_slice(&sig_bytes);
        // TODO: segfault i32 to u8, fix
        result[64] = self.recovery_id.to_i32() as u8;
        result
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
