use crate::{ecdsa, Signer, SignerError};
use async_trait::async_trait;
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

/// A signer that uses a local private key stored in memory.
#[derive(Clone, Debug)] // Deriving Debug is fine here as SecretKey has a safe Debug impl
pub struct PrivateKeySigner {
    secret_key: SecretKey,
    secp: Secp256k1<secp256k1::All>,
}

impl PrivateKeySigner {
    /// Creates a new signer with a randomly generated private key.
    // TODO: segfault rand source as arg
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        Self { secret_key, secp }
    }

    /// Creates a new signer from an existing secret key.
    pub fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        Self { secret_key, secp }
    }
}

#[async_trait]
impl Signer for PrivateKeySigner {
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<ecdsa::RecoverableSignature, SignerError> {
        let sig = self.secp.sign_ecdsa_recoverable(message, &self.secret_key);
        Ok(sig)
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.secret_key)
    }
}

#[cfg(test)]
mod tests {
    use crate::keccak256;

    use super::*;
    use crate::ecdsa::RecoverableSignature as SecpRecoverableSignature;
    use sha2::{Digest, Sha256};
    use tokio;

    #[tokio::test]
    async fn test_local_signer_sign_and_verify() {
        let signer = PrivateKeySigner::random();
        let public_key = signer.public_key();

        let message_bytes = b"Test message for local signer";
        let digest: [u8; 32] = Sha256::digest(message_bytes).into();
        let message =
            Message::from_slice(&digest).expect("Failed to create Message from digest");

        let recoverable_sig: SecpRecoverableSignature =
            signer.sign_digest(&message).await.expect("Signing failed");

        let secp = Secp256k1::new();
        let recovered_pk = secp
            .recover_ecdsa(&message, &recoverable_sig)
            .expect("Recovery failed");

        assert_eq!(recovered_pk, public_key, "Recovered public key mismatch");
    }

    #[test]
    fn test_local_signer_address() {
        let signer = PrivateKeySigner::random();
        let public_key = signer.public_key();
        let address = signer.address();

        // Calculate expected address manually
        let pk_bytes_uncompressed = public_key.serialize_uncompressed();
        let hash = keccak256(&pk_bytes_uncompressed[1..]); // Skip prefix 0x04
        let mut expected_address = [0u8; 20];
        expected_address.copy_from_slice(&hash[12..]);

        assert_eq!(address, expected_address, "Ethereum address mismatch");
    }
}
