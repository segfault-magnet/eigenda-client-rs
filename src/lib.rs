pub const BATCH_ID_TO_METADATA_HASH_FUNCTION_SELECTOR: [u8; 4] = [236, 203, 191, 201];
pub const QUORUM_ADVERSARY_THRESHOLD_PERCENTAGES_FUNCTION_SELECTOR: [u8; 4] = [134, 135, 254, 174];
pub const QUORUM_NUMBERS_REQUIRED_FUNCTION_SELECTOR: [u8; 4] = [225, 82, 52, 255];

pub mod blob_info;
pub mod client;
pub mod config;
pub mod errors;
pub mod eth_client;
pub mod sdk;
pub mod verifier;

pub use self::client::EigenClient;

#[allow(clippy::all)]
pub(crate) mod disperser {
    include!("generated/disperser.rs");
}

#[allow(clippy::all)]
pub(crate) mod common {
    include!("generated/common.rs");
}
