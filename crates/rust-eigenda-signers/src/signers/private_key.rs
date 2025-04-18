use std::convert::Infallible;

use crate::{PublicKey, RecoverableSignature, Sign};
use async_trait::async_trait;
use secp256k1::{Message, Secp256k1, SecretKey};

/// A signer that uses a local private key stored in memory.
#[derive(Clone, Debug)] // Deriving Debug is fine here as SecretKey has a safe Debug impl
pub struct Signer {
    secret_key: SecretKey,
    secp: Secp256k1<secp256k1::All>,
}

impl Signer {
    /// Creates a new signer with a randomly generated private key.
    pub fn random<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(rng);
        Self { secret_key, secp }
    }

    /// Creates a new signer from an existing secret key.
    pub fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        Self { secret_key, secp }
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key
    }
}

#[async_trait]
impl Sign for Signer {
    type Error = Infallible;

    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<RecoverableSignature, Self::Error> {
        let sig = self.secp.sign_ecdsa_recoverable(message, &self.secret_key);
        Ok(sig.into())
    }

    fn public_key(&self) -> PublicKey {
        secp256k1::PublicKey::from_secret_key(&self.secp, &self.secret_key).into()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rand::thread_rng;
    use sha2::{Digest, Sha256};
    use tokio;

    #[tokio::test]
    async fn test_local_signer_sign_and_verify() {
        // given
        let signer = Signer::random(&mut thread_rng());
        let public_key = signer.public_key();

        let message_bytes = b"Test message for local signer";
        let digest: [u8; 32] = Sha256::digest(message_bytes).into();
        let message =
            Message::from_slice(&digest).expect("Failed to create Message from digest");

        // when
        let recoverable_sig: RecoverableSignature =
            signer.sign_digest(&message).await.expect("Signing failed");

        // then
        let secp = Secp256k1::new();
        let recovered_pk = secp
            .recover_ecdsa(&message, &recoverable_sig.0)
            .expect("Recovery failed");

        assert_eq!(recovered_pk, public_key.0, "Recovered public key mismatch");
    }

    #[test]
    fn test_local_signer_address() {
        // given
        let key = SecretKey::from_str(
            "856f2fd4e3ff354a7f43680d6d9da56390184b43ec63beb06b66c9fd1bc79858",
        )
        .unwrap();
        let signer = Signer::new(key);

        // when
        let address = signer.public_key().address();

        // then

        let expected_address = "0x08AbDA505838eb8929c2c1cABD7E1c26e4BA94e1"
            .parse()
            .unwrap();

        assert_eq!(address, expected_address, "Ethereum address mismatch");
    }
}
