use crate::{RecoverableSignature, Signer, SignerError};
use async_trait::async_trait;
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

/// A signer that uses a local private key stored in memory.
#[derive(Clone, Debug)] // Deriving Debug is fine here as SecretKey has a safe Debug impl
pub struct LocalSigner {
    secret_key: SecretKey,
    secp: Secp256k1<secp256k1::All>,
}

impl LocalSigner {
    /// Creates a new signer with a randomly generated private key.
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        // generate_keypair returns (SecretKey, PublicKey)
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        // No need to extract from KeyPair struct
        // let keypair = secp.generate_keypair(&mut OsRng);
        // let secret_key = SecretKey::from_keypair(&keypair);
        Self { secret_key, secp }
    }

    /// Creates a new signer from an existing secret key.
    pub fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        Self { secret_key, secp }
    }
}

#[async_trait]
impl Signer for LocalSigner {
    async fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<RecoverableSignature, SignerError> {
        let message =
            Message::from_slice(digest.as_slice()).map_err(SignerError::Secp)?;
        let sig = self.secp.sign_ecdsa_recoverable(&message, &self.secret_key);

        // Convert secp256k1::RecoverableSignature to crate::RecoverableSignature
        let (recovery_id, signature_bytes) = sig.serialize_compact();
        let signature = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
            .map_err(SignerError::Secp)?;

        Ok(RecoverableSignature {
            signature,
            recovery_id,
        })
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.secret_key)
    }

    // address() uses the default implementation from the Signer trait
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keccak256; // Use the keccak256 from the parent module
    use sha2::{Digest, Sha256};
    use tokio;

    #[tokio::test]
    async fn test_local_signer_sign_and_verify() {
        let signer = LocalSigner::random();
        let public_key = signer.public_key();

        let message_bytes = b"Test message for local signer";
        let digest: [u8; 32] = Sha256::digest(message_bytes).into();

        let recoverable_sig = signer.sign_digest(digest).await.expect("Signing failed");

        // Verify the signature recovers the correct public key
        let secp = Secp256k1::new();
        let message = Message::from_slice(&digest).unwrap();

        // Reconstruct secp256k1::RecoverableSignature for verification
        let sig_bytes = recoverable_sig.signature.serialize_compact();
        let recovery_id = recoverable_sig.recovery_id;
        let internal_rec_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes, recovery_id)
                .expect("Failed to reconstruct internal recoverable signature");

        let recovered_pk = secp
            .recover_ecdsa(&message, &internal_rec_sig)
            .expect("Recovery failed");

        assert_eq!(recovered_pk, public_key, "Recovered public key mismatch");
    }

    #[test]
    fn test_local_signer_address() {
        let signer = LocalSigner::random();
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

