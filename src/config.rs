use secrecy::{ExposeSecret, Secret};
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq)]
pub enum SRSPointsSource {
    Path(String),
    Link(String),
}

impl Default for SRSPointsSource {
    fn default() -> Self {
        SRSPointsSource::Path("".to_string())
    }
}

/// Configuration for the EigenDA remote disperser client.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct EigenConfig {
    /// URL of the Disperser RPC server
    pub disperser_rpc: String,
    /// URL of the Ethereum RPC server
    pub eth_rpc: String,
    /// Block height needed to reach in order to consider the blob finalized
    /// a value less or equal to 0 means that the disperser will not wait for finalization
    pub settlement_layer_confirmation_depth: i32,
    /// Address of the service manager contract
    pub eigenda_svc_manager_address: String,
    /// Maximun amount of time in milliseconds to wait for a status query response
    pub status_query_timeout_ms: u64,
    /// Interval in milliseconds to query the status of a blob
    pub status_query_interval_ms: u64,
    /// Wait for the blob to be finalized before returning the response
    pub wait_for_finalization: bool,
    /// Authenticated dispersal
    pub authenticated: bool,
    /// Verify the certificate of dispatched blobs
    pub verify_cert: bool,
    /// Path or link to the file containing the points used for KZG
    pub points_source: SRSPointsSource,
    /// Chain ID of the Ethereum network
    pub chain_id: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EigenSecrets {
    pub private_key: PrivateKey,
}

#[derive(Debug, Clone)]
pub struct PrivateKey(pub Secret<String>);

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret().eq(other.0.expose_secret())
    }
}

impl FromStr for PrivateKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PrivateKey(s.parse()?))
    }
}
