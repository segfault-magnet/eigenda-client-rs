use std::{str::FromStr, sync::Arc, time::Duration};

use super::{
    blob_info::BlobInfo,
    config::EigenConfig,
    disperser::BlobInfo as DisperserBlobInfo,
    eth_client,
    verifier::{Verifier, VerifierConfig},
};
use crate::{
    blob_info,
    disperser::{
        self,
        authenticated_request::Payload::{AuthenticationData, DisperseRequest},
        disperser_client::DisperserClient,
        AuthenticatedReply, BlobAuthHeader,
    },
    errors::EigenClientError,
};
use backon::{ConstantBuilder, Retryable};
use byteorder::{BigEndian, ByteOrder};
use secp256k1::{ecdsa::RecoverableSignature, SecretKey};
use tiny_keccak::{Hasher, Keccak};
use tokio::{
    sync::{mpsc, Mutex},
    time::Instant,
};
use tokio_stream::{wrappers::UnboundedReceiverStream, StreamExt};
use tonic::{
    transport::{Channel, ClientTlsConfig, Endpoint},
    Streaming,
};

#[derive(Debug, Clone)]
pub(crate) struct RawEigenClient {
    client: Arc<Mutex<DisperserClient<Channel>>>,
    private_key: SecretKey,
    pub config: EigenConfig,
    verifier: Verifier,
}

pub(crate) const DATA_CHUNK_SIZE: usize = 32;
pub(crate) const AVG_BLOCK_TIME: u64 = 12;

impl RawEigenClient {
    const BLOB_SIZE_LIMIT: usize = 1024 * 1024 * 2; // 2 MB

    pub async fn new(
        private_key: SecretKey,
        config: EigenConfig,
    ) -> Result<Self, EigenClientError> {
        let endpoint =
            Endpoint::from_str(config.disperser_rpc.as_str())?.tls_config(ClientTlsConfig::new())?;
        let client = Arc::new(Mutex::new(DisperserClient::connect(endpoint).await?));

        let verifier_config = VerifierConfig {
            svc_manager_addr: config.eigenda_svc_manager_address.clone(),
            max_blob_size: Self::BLOB_SIZE_LIMIT as u32,
            points: config.points_source.clone(),
            settlement_layer_confirmation_depth: config.settlement_layer_confirmation_depth.max(0)
                as u32,
        };
        let eth_client = eth_client::EthClient::new(&config.eigenda_eth_rpc);

        let verifier = Verifier::new(verifier_config, eth_client).await?;
        Ok(RawEigenClient {
            client,
            private_key,
            config,
            verifier,
        })
    }

    pub fn blob_size_limit() -> usize {
        Self::BLOB_SIZE_LIMIT
    }

    async fn dispatch_blob_non_authenticated(
        &self,
        data: Vec<u8>,
    ) -> Result<String, EigenClientError> {
        let padded_data = convert_by_padding_empty_byte(&data);
        let request = disperser::DisperseBlobRequest {
            data: padded_data,
            custom_quorum_numbers: vec![],
            account_id: String::default(), // Account Id is not used in non-authenticated mode
        };

        let disperse_reply = self
            .client
            .lock()
            .await
            .disperse_blob(request)
            .await?
            .into_inner();

        Ok(hex::encode(disperse_reply.request_id))
    }

    async fn perform_verification(
        &self,
        blob_info: BlobInfo,
        disperse_elapsed: Duration,
    ) -> Result<(), EigenClientError> {
        (|| async { self.verifier.verify_certificate(blob_info.clone()).await })
            .retry(
                &ConstantBuilder::default()
                    .with_delay(Duration::from_secs(AVG_BLOCK_TIME))
                    .with_max_times(
                        (self.config.status_query_timeout
                            - disperse_elapsed.as_millis() as u64 / AVG_BLOCK_TIME)
                            as usize,
                    ),
            )
            .await
            .map_err(EigenClientError::from)
    }

    async fn dispatch_blob_authenticated(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        let (tx, rx) = mpsc::unbounded_channel();

        // 1. send DisperseBlobRequest
        let padded_data = convert_by_padding_empty_byte(&data);
        self.disperse_data(padded_data, &tx)?;

        // this await is blocked until the first response on the stream, so we only await after sending the `DisperseBlobRequest`
        let mut response_stream = self
            .client
            .clone()
            .lock()
            .await
            .disperse_blob_authenticated(UnboundedReceiverStream::new(rx))
            .await?;
        let response_stream = response_stream.get_mut();

        // 2. receive BlobAuthHeader
        let blob_auth_header = self.receive_blob_auth_header(response_stream).await?;

        // 3. sign and send BlobAuthHeader
        self.submit_authentication_data(blob_auth_header.clone(), &tx)?;

        // 4. receive DisperseBlobReply
        let reply = response_stream
            .next()
            .await
            .ok_or_else(|| EigenClientError::NoResponseFromServer)?
            .unwrap()
            .payload
            .ok_or_else(|| EigenClientError::NoPayloadInResponse)?;

        let disperser::authenticated_reply::Payload::DisperseReply(disperse_reply) = reply else {
            return Err(EigenClientError::UnexpectedResponseFromServer);
        };
        Ok(hex::encode(disperse_reply.request_id))
    }

    pub async fn get_inclusion_data(&self, blob_id: &str) -> Result<String, EigenClientError> {
        let disperse_time = Instant::now();
        let blob_info = self.await_for_inclusion(blob_id.to_string()).await?;

        let blob_info = blob_info::BlobInfo::try_from(blob_info)?;

        let disperse_elapsed = Instant::now() - disperse_time;
        let data = self
            .get_blob_data(&hex::encode(rlp::encode(&blob_info)))
            .await?;
        if data.is_none() {
            return Err(EigenClientError::FailedToGetBlobData);
        }
        self.verifier
            .verify_commitment(blob_info.blob_header.commitment.clone(), data.unwrap())?;

        self.perform_verification(blob_info.clone(), disperse_elapsed)
            .await?;

        Ok(hex::encode(rlp::encode(&blob_info)))
    }

    pub async fn dispatch_blob(&self, data: Vec<u8>) -> Result<String, EigenClientError> {
        if self.config.authenticated {
            self.dispatch_blob_authenticated(data).await
        } else {
            self.dispatch_blob_non_authenticated(data).await
        }
    }

    fn disperse_data(
        &self,
        data: Vec<u8>,
        tx: &mpsc::UnboundedSender<disperser::AuthenticatedRequest>,
    ) -> Result<(), EigenClientError> {
        let req = disperser::AuthenticatedRequest {
            payload: Some(DisperseRequest(disperser::DisperseBlobRequest {
                data,
                custom_quorum_numbers: vec![],
                account_id: get_account_id(&self.private_key),
            })),
        };

        tx.send(req)
            .map_err(|e| EigenClientError::DisperseBlob(format!("{}", e)))
    }

    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }

    fn submit_authentication_data(
        &self,
        blob_auth_header: BlobAuthHeader,
        tx: &mpsc::UnboundedSender<disperser::AuthenticatedRequest>,
    ) -> Result<(), EigenClientError> {
        // TODO: replace challenge_parameter with actual auth header when it is available
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, blob_auth_header.challenge_parameter);
        let digest = self.keccak256(&buf);
        let signature: RecoverableSignature = secp256k1::Secp256k1::signing_only()
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(&digest[..])?,
                &self.private_key,
            );
        let (recovery_id, sig) = signature.serialize_compact();

        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&sig);
        signature.push(recovery_id.to_i32() as u8);

        let req = disperser::AuthenticatedRequest {
            payload: Some(AuthenticationData(disperser::AuthenticationData {
                authentication_data: signature,
            })),
        };

        tx.send(req)
            .map_err(|e| EigenClientError::AuthenticationData(format!("{}", e)))
    }

    async fn receive_blob_auth_header(
        &self,
        response_stream: &mut Streaming<AuthenticatedReply>,
    ) -> Result<disperser::BlobAuthHeader, EigenClientError> {
        let reply = response_stream
            .next()
            .await
            .ok_or_else(|| EigenClientError::NoResponseFromServer)?;

        let Ok(reply) = reply else {
            return Err(EigenClientError::ErrorFromServer(format!("{:?}", reply)));
        };

        let reply = reply
            .payload
            .ok_or_else(|| EigenClientError::NoPayloadInResponse)?;

        if let disperser::authenticated_reply::Payload::BlobAuthHeader(blob_auth_header) = reply {
            Ok(blob_auth_header)
        } else {
            Err(EigenClientError::UnexpectedResponseFromServer)
        }
    }

    async fn await_for_inclusion(
        &self,
        request_id: String,
    ) -> Result<DisperserBlobInfo, EigenClientError> {
        let polling_request = disperser::BlobStatusRequest {
            request_id: hex::decode(request_id)?,
        };

        let blob_info = (|| async {
            let resp = self
                .client
                .lock()
                .await
                .get_blob_status(polling_request.clone())
                .await?
                .into_inner();

            match disperser::BlobStatus::try_from(resp.status)? {
                disperser::BlobStatus::Processing | disperser::BlobStatus::Dispersing => {
                    Err(EigenClientError::BlobStillProcessing)
                }
                disperser::BlobStatus::Failed => Err(EigenClientError::BlobDispatchedFailed),
                disperser::BlobStatus::InsufficientSignatures => {
                    Err(EigenClientError::InsufficientSignatures)
                }
                disperser::BlobStatus::Confirmed => {
                    if !self.config.wait_for_finalization {
                        let blob_info = resp
                            .info
                            .ok_or_else(|| EigenClientError::NoBlobHeaderInResponse)?;
                        return Ok(blob_info);
                    }
                    Err(EigenClientError::BlobStillProcessing)
                }
                disperser::BlobStatus::Finalized => {
                    let blob_info = resp
                        .info
                        .ok_or_else(|| EigenClientError::NoBlobHeaderInResponse)?;
                    Ok(blob_info)
                }

                _ => Err(EigenClientError::ReceivedUnknownBlobStatus),
            }
        })
        .retry(
            &ConstantBuilder::default()
                .with_delay(Duration::from_millis(self.config.status_query_interval))
                .with_max_times(
                    (self.config.status_query_timeout / self.config.status_query_interval) as usize,
                ),
        )
        .when(|e| match e {
            EigenClientError::BlobStillProcessing => true,
            _ => false,
        })
        .await?;

        Ok(blob_info)
    }

    pub async fn get_blob_data(
        &self,
        blob_info: &str,
    ) -> Result<Option<Vec<u8>>, EigenClientError> {
        let commit = hex::decode(blob_info)?;
        let blob_info: BlobInfo = rlp::decode(&commit)?;
        let blob_index = blob_info.blob_verification_proof.blob_index;
        let batch_header_hash = blob_info
            .blob_verification_proof
            .batch_medatada
            .batch_header_hash;
        let get_response = self
            .client
            .lock()
            .await
            .retrieve_blob(disperser::RetrieveBlobRequest {
                batch_header_hash,
                blob_index,
            })
            .await?
            .into_inner();

        if get_response.data.is_empty() {
            return Err(EigenClientError::FailedToGetBlobData);
        }

        let data = remove_empty_byte_from_padded_bytes(&get_response.data);
        Ok(Some(data))
    }
}

fn get_account_id(secret_key: &SecretKey) -> String {
    let public_key =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), secret_key);
    let hex = hex::encode(public_key.serialize_uncompressed());

    format!("0x{}", hex)
}

fn convert_by_padding_empty_byte(data: &[u8]) -> Vec<u8> {
    let parse_size = DATA_CHUNK_SIZE - 1;

    // Calculate the number of chunks
    let data_len = (data.len() + parse_size - 1) / parse_size;

    // Pre-allocate `valid_data` with enough space for all chunks
    let mut valid_data = vec![0u8; data_len * DATA_CHUNK_SIZE];
    let mut valid_end = data_len * DATA_CHUNK_SIZE;

    for (i, chunk) in data.chunks(parse_size).enumerate() {
        let offset = i * DATA_CHUNK_SIZE;
        valid_data[offset] = 0x00; // Set first byte of each chunk to 0x00 for big-endian compliance

        let copy_end = offset + 1 + chunk.len();
        valid_data[offset + 1..copy_end].copy_from_slice(chunk);

        if i == data_len - 1 && chunk.len() < parse_size {
            valid_end = offset + 1 + chunk.len();
        }
    }

    valid_data.truncate(valid_end);
    valid_data
}

fn remove_empty_byte_from_padded_bytes(data: &[u8]) -> Vec<u8> {
    let parse_size = DATA_CHUNK_SIZE;

    // Calculate the number of chunks
    let data_len = (data.len() + parse_size - 1) / parse_size;

    // Pre-allocate `valid_data` with enough space for all chunks
    let mut valid_data = vec![0u8; data_len * (DATA_CHUNK_SIZE - 1)];
    let mut valid_end = data_len * (DATA_CHUNK_SIZE - 1);

    for (i, chunk) in data.chunks(parse_size).enumerate() {
        let offset = i * (DATA_CHUNK_SIZE - 1);

        let copy_end = offset + chunk.len() - 1;
        valid_data[offset..copy_end].copy_from_slice(&chunk[1..]);

        if i == data_len - 1 && chunk.len() < parse_size {
            valid_end = offset + chunk.len() - 1;
        }
    }

    valid_data.truncate(valid_end);
    valid_data
}

#[cfg(test)]
mod test {
    #[test]
    fn test_pad_and_unpad() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }

    #[test]
    fn test_pad_and_unpad_large() {
        let data = vec![1; 1000];
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }

    #[test]
    fn test_pad_and_unpad_empty() {
        let data = Vec::new();
        let padded_data = super::convert_by_padding_empty_byte(&data);
        let unpadded_data = super::remove_empty_byte_from_padded_bytes(&padded_data);
        assert_eq!(data, unpadded_data);
    }
}
