use ethereum_types::Address;
use rust_eigenda_signers::{
    Message, PrivateKeySigner, RecoverableSignature, Signer, SignerError,
};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use super::BlobKey;

#[async_trait::async_trait]
pub trait BlobRequestSigner {
    async fn sign(&self, blob_key: BlobKey) -> Result<RecoverableSignature, SignerError>;

    async fn sign_payment_state_request(
        &self,
        timestamp: PaymentStateRequest,
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
    async fn sign(&self, blob_key: BlobKey) -> Result<RecoverableSignature, SignerError> {
        // TODO: segfault
        let message = Message::from(blob_key);

        let sig = self.signer.sign_digest(&message).await?;

        Ok(sig)
    }

    async fn sign_payment_state_request(
        &self,
        request: PaymentStateRequest,
    ) -> Result<RecoverableSignature, SignerError> {
        let msg = request.prepare_for_signing_by(self.account_id());
        let signature = self.signer.sign_digest(&msg).await?;

        Ok(signature)
    }

    fn account_id(&self) -> Address {
        self.signer.address().into()
    }
}

pub struct PaymentStateRequest {
    pub timestamp: u64,
}

impl PaymentStateRequest {
    pub fn prepare_for_signing_by(&self, account_id: Address) -> Message {
        let mut keccak_hash = Keccak::v256();
        keccak_hash.update(
            (account_id.as_bytes().len() as u32)
                .to_be_bytes()
                .as_slice(),
        );
        keccak_hash.update(account_id.as_bytes());
        keccak_hash.update(self.timestamp.to_be_bytes().as_slice());

        let mut account_id_hash: [u8; 32] = [0u8; 32];
        keccak_hash.finalize(&mut account_id_hash);

        // Hash the account ID bytes with SHA-256
        let hash = Sha256::digest(account_id_hash);

        // TODO: segfault validate 32B req
        Message::from_slice(hash.as_slice()).expect("digest is 32B")
    }
}
