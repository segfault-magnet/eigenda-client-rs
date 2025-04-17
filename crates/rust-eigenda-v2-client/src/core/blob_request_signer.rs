use ethereum_types::Address;
use rust_eigenda_signers::Message;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub struct PaymentStateRequest {
    timestamp: u64,
}

impl PaymentStateRequest {
    pub fn new(timestamp: u64) -> Self {
        Self { timestamp }
    }

    pub fn prepare_for_signing_by(&self, account_id: &Address) -> Message {
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
