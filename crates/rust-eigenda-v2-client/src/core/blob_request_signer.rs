use ethereum_types::Address;
use rust_eigenda_signers::{
    Message, PrivateKeySigner, RecoverableSignature, Signer, SignerError,
};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use super::eigenda_cert::BlobHeader;

#[async_trait::async_trait]
pub trait BlobRequestSigner {
    async fn sign(
        &self,
        blob_header: BlobHeader,
    ) -> Result<RecoverableSignature, SignerError>;

    async fn sign_payment_state_request(
        &self,
        timestamp: u64,
    ) -> Result<RecoverableSignature, SignerError>;

    fn account_id(&self) -> Address;
}

pub struct LocalBlobRequestSigner {
    signer: PrivateKeySigner,
}

impl LocalBlobRequestSigner {
    pub fn new(private_key: &str) -> Result<Self, SignerError> {
        // Strip "0x" prefix if present
        let clean_hex = private_key.strip_prefix("0x").unwrap_or(private_key);

        // Convert hex string to bytes
        // TODO: segfault
        let private_key_bytes = hex::decode(clean_hex).expect("will soon remove this");

        // Create ECDSA private key
        let private_key = rust_eigenda_signers::SecretKey::from_slice(&private_key_bytes)
            .expect("will soon remove this");
        let signer = PrivateKeySigner::new(private_key);

        Ok(Self { signer })
    }
}

#[async_trait::async_trait]
impl BlobRequestSigner for LocalBlobRequestSigner {
    async fn sign(
        &self,
        blob_header: BlobHeader,
    ) -> Result<RecoverableSignature, SignerError> {
        // TODO: segfault
        let blob_key = blob_header.blob_key().expect("will soon remove this");
        let message =
            rust_eigenda_signers::Message::from_slice(blob_key.to_bytes().as_slice())
                .expect("cannot fail, 32B in size");

        let sig = self.signer.sign_digest(&message).await?;

        Ok(sig)
    }

    async fn sign_payment_state_request(
        &self,
        timestamp: u64,
    ) -> Result<RecoverableSignature, SignerError> {
        let account_id = self.account_id();

        let mut keccak_hash = Keccak::v256();
        keccak_hash.update(
            (account_id.as_bytes().len() as u32)
                .to_be_bytes()
                .as_slice(),
        );
        keccak_hash.update(account_id.as_bytes());
        keccak_hash.update(timestamp.to_be_bytes().as_slice());
        let mut account_id_hash: [u8; 32] = [0u8; 32];
        keccak_hash.finalize(&mut account_id_hash);

        // Hash the account ID bytes with SHA-256
        let hash = Sha256::digest(account_id_hash);

        // Create a secp256k1 message from the hash
        // TODO: segfault
        let message =
            Message::from_slice(hash.as_slice()).expect("will soon remove this");

        // Sign the message using the private key
        let signature = self.signer.sign_digest(&message).await?;

        Ok(signature)
    }

    fn account_id(&self) -> Address {
        let public_key = self.signer.public_key();
        let public_key_uncompressed = public_key.serialize_uncompressed();
        let public_key_bytes = &public_key_uncompressed[1..];
        let mut keccak = Keccak::v256();
        keccak.update(public_key_bytes);
        let mut public_key_hash: [u8; 32] = [0u8; 32];
        keccak.finalize(&mut public_key_hash);
        Address::from_slice(&public_key_hash[12..])
    }
}
