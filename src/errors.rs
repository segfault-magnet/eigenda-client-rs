use tonic::{transport::Error as TonicError, Status};

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
    Rlp(#[from] rlp::DecoderError),
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
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to convert {0}")]
    NotPresent(String),
}

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
