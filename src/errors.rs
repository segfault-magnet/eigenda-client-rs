use tokio::sync::mpsc::error::SendError;
use tonic::{transport::Error as TonicError, Status};

use crate::{disperser, eth_client::RpcErrorResponse};

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    EthClient(#[from] EthClientError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error(transparent)]
    Communication(#[from] CommunicationError),
    #[error(transparent)]
    BlobStatus(#[from] BlobStatusError),
    #[error(transparent)]
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Private Key Error")]
    PrivateKey,
    #[error(transparent)]
    Secp(#[from] secp256k1::Error),
    #[error(transparent)]
    Tonic(#[from] TonicError),
}

#[derive(Debug, thiserror::Error)]
pub enum CommunicationError {
    #[error("No response from server")]
    NoResponseFromServer,
    #[error("No payload in response")]
    NoPayloadInResponse,
    #[error("Failed to get blob data")]
    FailedToGetBlobData,
    #[error("Failed to send DisperseBlobRequest: {0}")]
    DisperseBlob(SendError<disperser::AuthenticatedRequest>),
    #[error("Failed to send AuthenticationData: {0}")]
    AuthenticationData(SendError<disperser::AuthenticatedRequest>),
    #[error("Error from server: {0}")]
    ErrorFromServer(String),
    #[error(transparent)]
    Secp(#[from] secp256k1::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    GetBlobData(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, thiserror::Error)]
pub enum BlobStatusError {
    #[error("Blob still processing")]
    BlobStillProcessing,
    #[error("Blob dispatched failed")]
    BlobDispatchedFailed,
    #[error("Insufficient signatures")]
    InsufficientSignatures,
    #[error("No blob header in response")]
    NoBlobHeaderInResponse,
    #[error("Received unknown blob status")]
    ReceivedUnknownBlobStatus,
    #[error(transparent)]
    Prost(#[from] prost::DecodeError),
    #[error(transparent)]
    Status(#[from] Status),
}

/// Errors specific to conversion
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to convert {0}")]
    NotPresent(String),
}

/// Errors for the EthClient
#[derive(Debug, thiserror::Error)]
pub enum EthClientError {
    #[error(transparent)]
    HTTPClient(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJSON(#[from] serde_json::Error),
    #[error("RPC: {0}")]
    RPC(RpcErrorResponse),
}

/// Errors for the Verifier
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Service Manager Error: {0}")]
    ServiceManager(String),
    #[error("Kzg Error: {0}")]
    Kzg(String),
    #[error("Wrong proof")]
    WrongProof,
    #[error("Different commitments")]
    DifferentCommitments,
    #[error("Different roots")]
    DifferentRoots,
    #[error("Empty hashes")]
    EmptyHash,
    #[error("Different hashes")]
    DifferentHashes,
    #[error("Wrong quorum params")]
    WrongQuorumParams,
    #[error("Quorum not confirmed")]
    QuorumNotConfirmed,
    #[error("Commitment not on curve")]
    CommitmentNotOnCurve,
    #[error("Commitment not on correct subgroup")]
    CommitmentNotOnCorrectSubgroup,
    #[error("Link Error: {0}")]
    Link(String),
    #[error("Data Mismatch")]
    DataMismatch
}
