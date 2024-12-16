use tonic::{transport::Error as TonicError, Status};

/// Errors returned by this crate
#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    EthClient(#[from] EthClientError),
    #[error(transparent)]
    Verification(#[from] VerificationError),
    #[error("Private Key Error")]
    PrivateKey,
    #[error(transparent)]
    Secp(#[from] secp256k1::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Tonic(#[from] TonicError),
    #[error(transparent)]
    Status(#[from] Status),
    #[error("No response from server")]
    NoResponseFromServer,
    #[error("No payload in response")]
    NoPayloadInResponse,
    #[error("Unexpected response from server")]
    UnexpectedResponseFromServer,
    #[error("Failed to get blob data")]
    FailedToGetBlobData,
    #[error("Failed to send DisperseBlobRequest: {0}")]
    DisperseBlob(String),
    #[error("Failed to send AuthenticationData: {0}")]
    AuthenticationData(String),
    #[error("Error from server: {0}")]
    ErrorFromServer(String),
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
    Conversion(#[from] ConversionError),
    #[error(transparent)]
    Prost(#[from] prost::DecodeError),
    #[error("Data provided does not match the expected data")]
    DataMismatch,
    #[error("Failed to verify inclusion data")]
    InclusionData,
    #[error("Failed to get blob data")]
    GetBlobData,
    #[error("Failed at get blob function {0}")]
    GetBlobFunction(#[from] Box<dyn std::error::Error + Send + Sync>),
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
    #[error("Failed to serialize request body: {0}")]
    FailedToSerializeRequestBody(String),
    #[error(transparent)]
    HTTPClient(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJSON(#[from] serde_json::Error),
    #[error("RPC: {0}")]
    RPC(String),
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
}
