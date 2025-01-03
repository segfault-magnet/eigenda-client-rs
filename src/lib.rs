pub(crate) mod blob_info;
pub mod client;
pub(crate) mod client_tests;
pub mod config;
pub mod errors;
pub(crate) mod eth_client;
pub(crate) mod sdk;
pub(crate) mod verifier;
pub(crate) mod verifier_tests;

pub use self::client::EigenClient;

#[allow(clippy::all)]
pub(crate) mod disperser {
    include!("generated/disperser.rs");
}

#[allow(clippy::all)]
pub(crate) mod common {
    include!("generated/common.rs");
}
