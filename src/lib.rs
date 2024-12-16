pub mod blob_info;
pub mod client;
pub mod client_tests;
pub mod config;
pub mod errors;
pub mod eth_client;
pub mod sdk;
pub mod verifier;
pub mod verifier_tests;

pub use self::client::EigenClient;

#[allow(clippy::all)]
pub(crate) mod disperser {
    include!("generated/disperser.rs");
}

#[allow(clippy::all)]
pub(crate) mod common {
    include!("generated/common.rs");
}
