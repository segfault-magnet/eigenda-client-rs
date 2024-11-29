use tonic::{transport::Error as TonicError, Status};

#[derive(Debug, thiserror::Error)]
pub enum EigenClientError {
    #[error(transparent)]
    EthClientError(#[from] EthClientError),
    #[error(transparent)]
    VerificationError(#[from] VerificationError),
    #[error("Private Key Error")]
    PrivateKeyError,
    #[error(transparent)]
    SecpError(#[from] secp256k1::Error),
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    #[error(transparent)]
    RlpError(#[from] rlp::DecoderError),
    #[error(transparent)]
    TonicError(#[from] TonicError),
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
    DisperseBlobError(String),
    #[error("Failed to send AuthenticationData: {0}")]
    AuthenticationDataError(String),
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
    ConversionError(#[from] ConversionError),
    #[error(transparent)]
    ProstError(#[from] prost::DecodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Failed to convert BlobInfo")]
    NotPresentError,
}

#[derive(Debug, thiserror::Error)]
pub enum EthClientError {
    #[error("Failed to serialize request body: {0}")]
    FailedToSerializeRequestBody(String),
    #[error("reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    SerdeJSONError(#[from] serde_json::Error),
    #[error("{0}")]
    RPCError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("Service Manager Error")]
    ServiceManagerError,
    #[error("Kzg Error")]
    KzgError,
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
    #[error("Link Error")]
    LinkError,
}
