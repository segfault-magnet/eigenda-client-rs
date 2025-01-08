use std::{collections::HashMap, path::Path};

use crate::errors::VerificationError;
use ark_bn254::{Fq, G1Affine};
use bytes::Bytes;
use ethabi::{encode, ParamType, Token};
use ethereum_types::{Address, U256};
use rust_kzg_bn254::{blob::Blob, kzg::Kzg, polynomial::PolynomialFormat};
use tiny_keccak::{Hasher, Keccak};
use tokio::{fs::File, io::AsyncWriteExt};
use url::Url;

use super::{
    blob_info::{BatchHeader, BlobHeader, BlobInfo, G1Commitment},
    errors::EthClientError,
    eth_client::EthClient,
};

/// Trait that defines the methods for the ethclient used by the verifier, needed in order to mock it for tests
#[async_trait::async_trait]
pub(crate) trait VerifierClient: Sync + Send + std::fmt::Debug {
    fn clone_boxed(&self) -> Box<dyn VerifierClient>;

    /// Returns the current block number.
    async fn get_block_number(&self) -> Result<U256, EthClientError>;

    /// Invokes a function on a contract specified by `contract_address` / `contract_abi` using `eth_call`.
    async fn call(
        &self,
        to: Address,
        calldata: Bytes,
        block: Option<u64>,
    ) -> Result<String, EthClientError>;
}

#[async_trait::async_trait]
impl VerifierClient for EthClient {
    fn clone_boxed(&self) -> Box<dyn VerifierClient> {
        Box::new(self.clone())
    }

    async fn get_block_number(&self) -> Result<U256, EthClientError> {
        self.get_block_number().await
    }

    async fn call(
        &self,
        to: Address,
        calldata: Bytes,
        block: Option<u64>,
    ) -> Result<String, EthClientError> {
        self.call(to, calldata, block).await
    }
}

/// Configuration for the verifier used for authenticated dispersals
#[derive(Debug, Clone)]
pub(crate) struct VerifierConfig {
    pub(crate) svc_manager_addr: Address,
    pub(crate) max_blob_size: u32,
    pub(crate) g1_url: Url,
    pub(crate) g2_url: Url,
    pub(crate) settlement_layer_confirmation_depth: u32,
}

/// Verifier used to verify the integrity of the blob info
/// Kzg is used for commitment verification
/// EigenDA service manager is used to connect to the service manager contract
#[derive(Debug)]
pub(crate) struct Verifier {
    kzg: Kzg,
    cfg: VerifierConfig,
    eth_client: Box<dyn VerifierClient>,
}

impl Clone for Verifier {
    fn clone(&self) -> Self {
        Self {
            kzg: self.kzg.clone(),
            cfg: self.cfg.clone(),
            eth_client: self.eth_client.clone_boxed(),
        }
    }
}

impl Verifier {
    pub(crate) const SRSORDER: u32 = 268435456; // 2 ^ 28
    pub(crate) const G1POINT: &'static str = "g1.point";
    pub(crate) const G2POINT: &'static str = "g2.point.powerOf2";
    pub(crate) const POINT_SIZE: u32 = 32;

    async fn save_point(url: Url, point: String) -> Result<(), VerificationError> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| VerificationError::Link(e.to_string()))?;
        if !response.status().is_success() {
            return Err(VerificationError::Link("Failed to get point".to_string()));
        }
        let path = format!("./{}", point);
        let path = Path::new(&path);
        let mut file = File::create(path)
            .await
            .map_err(|e| VerificationError::Link(e.to_string()))?;
        let content = response
            .bytes()
            .await
            .map_err(|e| VerificationError::Link(e.to_string()))?;
        file.write_all(&content)
            .await
            .map_err(|e| VerificationError::Link(e.to_string()))?;
        Ok(())
    }
    async fn save_points(url_g1: Url, url_g2: Url) -> Result<String, VerificationError> {
        Self::save_point(url_g1, Self::G1POINT.to_string()).await?;
        Self::save_point(url_g2, Self::G2POINT.to_string()).await?;

        Ok(".".to_string())
    }
    /// Returns a new Verifier
    pub(crate) async fn new<T: VerifierClient + 'static>(
        cfg: VerifierConfig,
        eth_client: T,
    ) -> Result<Self, VerificationError> {
        let srs_points_to_load = cfg.max_blob_size / Self::POINT_SIZE;
        let path = Self::save_points(cfg.clone().g1_url, cfg.clone().g2_url).await?;
        let kzg_handle = tokio::task::spawn_blocking(move || {
            Kzg::setup(
                &format!("{}/{}", path, Self::G1POINT),
                "",
                &format!("{}/{}", path, Self::G2POINT),
                Self::SRSORDER,
                srs_points_to_load,
                "".to_string(),
            )
        });
        let kzg = kzg_handle
            .await
            .map_err(|e| VerificationError::Kzg(e.to_string()))?
            .map_err(|e| VerificationError::Kzg(e.to_string()))?;

        Ok(Self {
            kzg,
            cfg,
            eth_client: Box::new(eth_client),
        })
    }

    /// Return the commitment from a blob
    fn commit(&self, blob: Vec<u8>) -> Result<G1Affine, VerificationError> {
        let blob = Blob::from_bytes_and_pad(&blob.to_vec());
        self.kzg
            .blob_to_kzg_commitment(&blob, PolynomialFormat::InEvaluationForm)
            .map_err(|e| VerificationError::Kzg(e.to_string()))
    }

    /// Compare the given commitment with the commitment generated with the blob
    pub(crate) fn verify_commitment(
        &self,
        expected_commitment: G1Commitment,
        blob: Vec<u8>,
    ) -> Result<(), VerificationError> {
        let actual_commitment = self.commit(blob)?;
        let expected_commitment = G1Affine::new_unchecked(
            Fq::from(num_bigint::BigUint::from_bytes_be(&expected_commitment.x)),
            Fq::from(num_bigint::BigUint::from_bytes_be(&expected_commitment.y)),
        );
        if !expected_commitment.is_on_curve() {
            return Err(VerificationError::CommitmentNotOnCurve);
        }
        if !expected_commitment.is_in_correct_subgroup_assuming_on_curve() {
            return Err(VerificationError::CommitmentNotOnCorrectSubgroup);
        }
        if actual_commitment != expected_commitment {
            return Err(VerificationError::DifferentCommitments);
        }
        Ok(())
    }

    /// Returns the hashed blob header
    pub(crate) fn hash_encode_blob_header(&self, blob_header: &BlobHeader) -> Vec<u8> {
        let mut blob_quorums = vec![];
        for quorum in &blob_header.blob_quorum_params {
            let quorum = Token::Tuple(vec![
                Token::Uint(ethabi::Uint::from(quorum.quorum_number)),
                Token::Uint(ethabi::Uint::from(quorum.adversary_threshold_percentage)),
                Token::Uint(ethabi::Uint::from(quorum.confirmation_threshold_percentage)),
                Token::Uint(ethabi::Uint::from(quorum.chunk_length)),
            ]);
            blob_quorums.push(quorum);
        }
        let blob_header = Token::Tuple(vec![
            Token::Tuple(vec![
                Token::Uint(ethabi::Uint::from_big_endian(&blob_header.commitment.x)),
                Token::Uint(ethabi::Uint::from_big_endian(&blob_header.commitment.y)),
            ]),
            Token::Uint(ethabi::Uint::from(blob_header.data_length)),
            Token::Array(blob_quorums),
        ]);

        let encoded = encode(&[blob_header]);

        let mut keccak = Keccak::v256();
        keccak.update(&encoded);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        hash.to_vec()
    }

    /// Computes the merkle inclusion proof
    pub(crate) fn process_inclusion_proof(
        &self,
        proof: &[u8],
        leaf: &[u8],
        index: u32,
    ) -> Result<Vec<u8>, VerificationError> {
        let mut index = index;
        if proof.len() % 32 != 0 {
            return Err(VerificationError::WrongProof);
        }
        let mut computed_hash = leaf.to_vec();
        for i in 0..proof.len() / 32 {
            let mut buffer = [0u8; 64];
            if index % 2 == 0 {
                buffer[..32].copy_from_slice(&computed_hash);
                buffer[32..].copy_from_slice(&proof[i * 32..(i + 1) * 32]);
            } else {
                buffer[..32].copy_from_slice(&proof[i * 32..(i + 1) * 32]);
                buffer[32..].copy_from_slice(&computed_hash);
            }
            let mut keccak = Keccak::v256();
            keccak.update(&buffer);
            let mut hash = [0u8; 32];
            keccak.finalize(&mut hash);
            computed_hash = hash.to_vec();
            index /= 2;
        }

        Ok(computed_hash)
    }

    /// Verifies the certificate's batch root
    pub(crate) fn verify_merkle_proof(&self, cert: &BlobInfo) -> Result<(), VerificationError> {
        let inclusion_proof = &cert.blob_verification_proof.inclusion_proof;
        let root = &cert
            .blob_verification_proof
            .batch_medatada
            .batch_header
            .batch_root;
        let blob_index = cert.blob_verification_proof.blob_index;
        let blob_header = &cert.blob_header;

        let blob_header_hash = self.hash_encode_blob_header(blob_header);
        let mut keccak = Keccak::v256();
        keccak.update(&blob_header_hash);
        let mut leaf_hash = [0u8; 32];
        keccak.finalize(&mut leaf_hash);

        let generated_root =
            self.process_inclusion_proof(inclusion_proof, &leaf_hash, blob_index)?;

        if generated_root != *root {
            return Err(VerificationError::DifferentRoots);
        }
        Ok(())
    }

    fn hash_batch_metadata(
        &self,
        batch_header: &BatchHeader,
        signatory_record_hash: &[u8],
        confirmation_block_number: u32,
    ) -> Vec<u8> {
        let batch_header_token = Token::Tuple(vec![
            Token::FixedBytes(batch_header.batch_root.clone()), // Clone only where necessary
            Token::Bytes(batch_header.quorum_numbers.clone()),
            Token::Bytes(batch_header.quorum_signed_percentages.clone()),
            Token::Uint(ethabi::Uint::from(batch_header.reference_block_number)),
        ]);

        let encoded = encode(&[batch_header_token]);

        let mut keccak = Keccak::v256();
        keccak.update(&encoded);
        let mut header_hash = [0u8; 32];
        keccak.finalize(&mut header_hash);

        let hash_token = Token::Tuple(vec![
            Token::FixedBytes(header_hash.to_vec()),
            Token::FixedBytes(signatory_record_hash.to_owned()), // Clone only if required
        ]);

        let mut hash_encoded = encode(&[hash_token]);

        hash_encoded.append(&mut confirmation_block_number.to_be_bytes().to_vec());

        let mut keccak = Keccak::v256();
        keccak.update(&hash_encoded);
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);

        hash.to_vec()
    }

    /// Retrieves the block to make the request to the service manager
    async fn get_context_block(&self) -> Result<u64, VerificationError> {
        let latest = self.eth_client.get_block_number().await.unwrap().as_u64();

        let depth = self
            .cfg
            .settlement_layer_confirmation_depth
            .saturating_sub(1);
        let block_to_return = latest.saturating_sub(depth as u64);
        Ok(block_to_return)
    }
    async fn call_batch_id_to_metadata_hash(
        &self,
        blob_info: &BlobInfo,
    ) -> Result<Vec<u8>, VerificationError> {
        let context_block = self.get_context_block().await?;

        let func_selector =
            ethabi::short_signature("batchIdToBatchMetadataHash", &[ParamType::Uint(32)]);
        let mut data = func_selector.to_vec();
        let mut batch_id_vec = [0u8; 32];
        U256::from(blob_info.blob_verification_proof.batch_id).to_big_endian(&mut batch_id_vec);
        data.append(batch_id_vec.to_vec().as_mut());

        let res = self
            .eth_client
            .call(
                self.cfg.svc_manager_addr,
                bytes::Bytes::copy_from_slice(&data),
                Some(context_block),
            )
            .await
            .map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        let res = res.trim_start_matches("0x");

        let expected_hash =
            hex::decode(res).map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        Ok(expected_hash)
    }

    /// Verifies the certificate batch hash
    pub(crate) async fn verify_batch(&self, blob_info: &BlobInfo) -> Result<(), VerificationError> {
        let expected_hash = self.call_batch_id_to_metadata_hash(blob_info).await?;

        if expected_hash == vec![0u8; 32] {
            return Err(VerificationError::EmptyHash);
        }

        let actual_hash = self.hash_batch_metadata(
            &blob_info
                .blob_verification_proof
                .batch_medatada
                .batch_header,
            &blob_info
                .blob_verification_proof
                .batch_medatada
                .signatory_record_hash,
            blob_info
                .blob_verification_proof
                .batch_medatada
                .confirmation_block_number,
        );

        if expected_hash != actual_hash {
            return Err(VerificationError::DifferentHashes);
        }
        Ok(())
    }

    fn decode_bytes(&self, encoded: Vec<u8>) -> Result<Vec<u8>, VerificationError> {
        let output_type = [ParamType::Bytes];
        let tokens: Vec<Token> = ethabi::decode(&output_type, &encoded)
            .map_err(|e| VerificationError::ServiceManager(e.to_string()))?;
        let token = tokens.first().ok_or(VerificationError::ServiceManager(
            "Incorrect response".to_string(),
        ))?;
        match token {
            Token::Bytes(data) => Ok(data.to_vec()),
            _ => Err(VerificationError::ServiceManager(
                "Incorrect response".to_string(),
            )),
        }
    }

    async fn get_quorum_adversary_threshold(
        &self,
        quorum_number: u32,
    ) -> Result<u8, VerificationError> {
        let func_selector = ethabi::short_signature("quorumAdversaryThresholdPercentages", &[]);
        let data = func_selector.to_vec();

        let res = self
            .eth_client
            .call(
                self.cfg.svc_manager_addr,
                bytes::Bytes::copy_from_slice(&data),
                None,
            )
            .await
            .map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        let res = res.trim_start_matches("0x");

        let percentages_vec =
            hex::decode(res).map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        let percentages = self.decode_bytes(percentages_vec)?;

        if percentages.len() > quorum_number as usize {
            return Ok(percentages[quorum_number as usize]);
        }
        Ok(0)
    }
    async fn call_quorum_numbers_required(&self) -> Result<Vec<u8>, VerificationError> {
        let func_selector = ethabi::short_signature("quorumNumbersRequired", &[]);
        let data = func_selector.to_vec();
        let res = self
            .eth_client
            .call(
                self.cfg.svc_manager_addr,
                bytes::Bytes::copy_from_slice(&data),
                None,
            )
            .await
            .map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        let res = res.trim_start_matches("0x");

        let required_quorums_vec =
            hex::decode(res).map_err(|e| VerificationError::ServiceManager(e.to_string()))?;

        let required_quorums = self.decode_bytes(required_quorums_vec)?;

        Ok(required_quorums)
    }
    /// Verifies that the certificate's blob quorum params are correct
    pub(crate) async fn verify_security_params(
        &self,
        cert: &BlobInfo,
    ) -> Result<(), VerificationError> {
        let blob_header = &cert.blob_header;
        let batch_header = &cert.blob_verification_proof.batch_medatada.batch_header;

        let mut confirmed_quorums: HashMap<u32, bool> = HashMap::new();
        for i in 0..blob_header.blob_quorum_params.len() {
            if batch_header.quorum_numbers[i] as u32
                != blob_header.blob_quorum_params[i].quorum_number
            {
                return Err(VerificationError::WrongQuorumParams);
            }
            if blob_header.blob_quorum_params[i].adversary_threshold_percentage
                > blob_header.blob_quorum_params[i].confirmation_threshold_percentage
            {
                return Err(VerificationError::WrongQuorumParams);
            }
            let quorum_adversary_threshold = self
                .get_quorum_adversary_threshold(blob_header.blob_quorum_params[i].quorum_number)
                .await?;

            if quorum_adversary_threshold > 0
                && blob_header.blob_quorum_params[i].adversary_threshold_percentage
                    < quorum_adversary_threshold as u32
            {
                return Err(VerificationError::WrongQuorumParams);
            }

            if (batch_header.quorum_signed_percentages[i] as u32)
                < blob_header.blob_quorum_params[i].confirmation_threshold_percentage
            {
                return Err(VerificationError::WrongQuorumParams);
            }

            confirmed_quorums.insert(blob_header.blob_quorum_params[i].quorum_number, true);
        }

        let required_quorums = self.call_quorum_numbers_required().await?;

        for quorum in required_quorums {
            if !confirmed_quorums.contains_key(&(quorum as u32)) {
                return Err(VerificationError::QuorumNotConfirmed);
            }
        }
        Ok(())
    }

    /// Verifies that the certificate is valid
    pub(crate) async fn verify_inclusion_data_against_settlement_layer(
        &self,
        cert: BlobInfo,
    ) -> Result<(), VerificationError> {
        self.verify_batch(&cert).await?;
        self.verify_merkle_proof(&cert)?;
        self.verify_security_params(&cert).await?;
        Ok(())
    }
}
