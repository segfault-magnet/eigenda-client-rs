use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{
    config::Credentials,
    primitives::Blob,
    types::{KeySpec, KeyUsageType, Tag},
    Client,
};
use base64::Engine;
use k256::ecdsa::SigningKey;
use k256::SecretKey;
use testcontainers::{core::ContainerPort, runners::AsyncRunner};
use tokio::io::AsyncBufReadExt;

#[derive(Default)]
pub struct Kms {
    show_logs: bool,
}

struct KmsImage;

impl testcontainers::Image for KmsImage {
    fn name(&self) -> &str {
        "localstack/localstack"
    }

    fn tag(&self) -> &str {
        "latest"
    }

    fn ready_conditions(&self) -> Vec<testcontainers::core::WaitFor> {
        vec![testcontainers::core::WaitFor::message_on_stdout("Ready.")]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &const { [ContainerPort::Tcp(4566)] }
    }
}

impl Kms {
    pub fn with_show_logs(mut self, show_logs: bool) -> Self {
        self.show_logs = show_logs;
        self
    }

    pub async fn start(self) -> anyhow::Result<KmsProcess> {
        let container = KmsImage
            .start()
            .await
            .with_context(|| "Failed to start KMS container")?;

        if self.show_logs {
            spawn_log_printer(&container);
        }

        let port = container.get_host_port_ipv4(4566).await?;
        let url = format!("http://localhost:{}", port);

        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                "test",
                "test",
                None,
                None,
                "Static Credentials",
            ))
            .endpoint_url(url.clone())
            .region(Region::new("us-east-1")) // placeholder region for test
            .load()
            .await;

        let client = Client::new(&sdk_config);

        Ok(KmsProcess {
            _container: container,
            client,
            url,
        })
    }
}

fn spawn_log_printer(container: &testcontainers::ContainerAsync<KmsImage>) {
    let stderr = container.stderr(true);
    let stdout = container.stdout(true);
    tokio::spawn(async move {
        let mut stderr_lines = stderr.lines();
        let mut stdout_lines = stdout.lines();

        let mut other_stream_closed = false;
        loop {
            tokio::select! {
                stderr_result = stderr_lines.next_line() => {
                    match stderr_result {
                        Ok(Some(line)) => eprintln!("KMS (stderr): {}", line),
                        Ok(None) if other_stream_closed => break,
                        Ok(None) => other_stream_closed=true,
                        Err(e) => {
                            eprintln!("KMS: Error reading from stderr: {:?}", e);
                            break;
                        }
                    }
                }
                stdout_result = stdout_lines.next_line() => {
                    match stdout_result {
                        Ok(Some(line)) => eprintln!("KMS (stdout): {}", line),
                        Ok(None) if other_stream_closed => break,
                        Ok(None) => other_stream_closed=true,
                        Err(e) => {
                            eprintln!("KMS: Error reading from stdout: {:?}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok::<(), std::io::Error>(())
    });
}

pub struct KmsProcess {
    _container: testcontainers::ContainerAsync<KmsImage>,
    client: Client,
    url: String,
}

impl KmsProcess {
    pub async fn create_key(&self) -> anyhow::Result<KmsKey> {
        let response = self
            .client
            .create_key()
            .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
            .key_spec(aws_sdk_kms::types::KeySpec::EccSecgP256K1)
            .send()
            .await?;

        // use arn as id to closer imitate prod behavior
        let id = response
            .key_metadata
            .and_then(|metadata| metadata.arn)
            .ok_or_else(|| anyhow::anyhow!("key arn missing from response"))?;

        Ok(KmsKey {
            id: id.to_string(),
            url: self.url.clone(),
            client: self.client.clone(),
        })
    }

    /// Injects a secp256k1 private key into LocalStack KMS
    ///
    /// This uses the LocalStack-specific custom tag mechanism to inject the key material
    /// and create a new KMS key that uses the specified private key.
    pub async fn inject_secp256k1_key(
        &self,
        signing_key: &SigningKey,
    ) -> anyhow::Result<KmsKey> {
        // Convert to SecretKey and then to PKCS8 DER format
        let secret_key = SecretKey::from_bytes(&signing_key.to_bytes())
            .context("Failed to convert SigningKey to SecretKey")?;

        // Encode the SecretKey to PKCS8 DER format
        use k256::pkcs8::EncodePrivateKey;
        let pkcs8_der = secret_key
            .to_pkcs8_der()
            .context("Failed to encode key as PKCS8 DER")?;

        // Base64-encode the DER-encoded private key
        let base64_key_material =
            base64::engine::general_purpose::STANDARD.encode(pkcs8_der.as_bytes());

        // Create KMS key with the custom key material tag
        let create_key_resp = self
            .client
            .create_key()
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(KeySpec::EccSecgP256K1)
            .set_tags(Some(vec![Tag::builder()
                .tag_key("_custom_key_material_")
                .tag_value(base64_key_material)
                .build()
                .context("Failed to build tag")?]))
            .send()
            .await
            .context("Failed to create KMS key with injected material")?;

        // Extract key ID/ARN from response
        let key_id = create_key_resp
            .key_metadata
            .map(|m| m.key_id)
            .context("Key ID missing from response")?;

        Ok(KmsKey {
            id: key_id,
            url: self.url.clone(),
            client: self.client.clone(),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Debug, Clone)]
pub struct KmsKey {
    pub id: String,
    pub url: String,
    pub client: Client,
}

impl KmsKey {
    /// Sign a message digest using this KMS key
    pub async fn sign_digest(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sign_response = self
            .client
            .sign()
            .key_id(&self.id)
            .message(Blob::new(digest))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .context("Failed to sign using KMS key")?;

        let signature = sign_response
            .signature
            .context("Signature missing from response")?
            .into_inner();

        Ok(signature)
    }

    /// Get the public key associated with this KMS key
    pub async fn get_public_key(&self) -> anyhow::Result<Vec<u8>> {
        let response = self
            .client
            .get_public_key()
            .key_id(&self.id)
            .send()
            .await
            .context("Failed to get public key")?;

        let public_key = response
            .public_key
            .context("Public key missing from response")?
            .into_inner();

        Ok(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{
        signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey,
    };
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    // --- Helper Functions & Types ---

    /// Represents a recoverable ECDSA signature, storing the core
    /// signature (R, S) and the calculated recovery ID (V).
    /// Can generate the 65-byte [R||S||V] format on demand.
    #[derive(Debug, Clone)]
    struct RecoverableSignature {
        signature: Signature,
        recovery_id: RecoveryId,
    }

    impl RecoverableSignature {
        /// Creates a recoverable signature from KMS DER bytes.
        fn from_kms_der(
            signature_der: &[u8],
            message_hash: &[u8; 32],
            verifying_key: &VerifyingKey,
        ) -> Result<Self> {
            let (signature, recovery_id) =
                parse_der_and_determine_recid(signature_der, message_hash, verifying_key)
                    .context("Failed to parse DER and determine recovery ID")?;
            Ok(Self {
                signature,
                recovery_id,
            })
        }

        /// Creates a recoverable signature from a local k256::Signature.
        fn from_local_signature(
            signature: &Signature,
            message_hash: &[u8; 32],
            verifying_key: &VerifyingKey,
        ) -> Result<Self> {
            let normalized_sig = signature.normalize_s().unwrap_or(*signature);
            let recovery_id =
                determine_recovery_id(&normalized_sig, message_hash, verifying_key)
                    .context("Failed to determine recovery ID for compact signature")?;
            Ok(Self {
                signature: normalized_sig,
                recovery_id,
            })
        }

        /// Returns the signature component (R, S).
        fn signature(&self) -> &Signature {
            &self.signature
        }

        /// Returns the recovery ID component (V).
        fn recovery_id(&self) -> RecoveryId {
            self.recovery_id
        }

        /// Generates the 65-byte [R||S||V] representation.
        fn to_rsv_bytes(&self) -> [u8; 65] {
            let sig_bytes = self.signature.to_bytes(); // This is [R||S]
            let mut result = [0u8; 65];
            result[..64].copy_from_slice(&sig_bytes);
            result[64] = self.recovery_id.to_byte();
            result
        }
    }

    /// Helper function to set up KMS instance and generate keys
    async fn setup_kms_and_keys() -> Result<(KmsProcess, SigningKey, VerifyingKey)> {
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Ok((kms_proc, signing_key, verifying_key))
    }

    /// Parses a DER-encoded signature, normalizes it, and determines the recovery ID.
    /// Returns the normalized signature and the recovery ID.
    fn parse_der_and_determine_recid(
        signature_der: &[u8],
        message_hash: &[u8; 32],
        expected_pubkey: &VerifyingKey,
    ) -> Result<(Signature, RecoveryId)> {
        // Parse the DER signature
        let signature =
            Signature::from_der(signature_der).context("Invalid DER signature")?;

        // Normalize S value (ECDSA allows two valid S values, usually low-S is preferred)
        let normalized_sig = signature.normalize_s().unwrap_or(signature);

        // Determine recovery ID by trying both possibilities
        let recovery_id =
            determine_recovery_id(&normalized_sig, message_hash, expected_pubkey)?;

        Ok((normalized_sig, recovery_id))
    }

    /// Determine the correct recovery ID for a signature by attempting recovery with both
    /// possible IDs (0 and 1) and checking which one yields the expected public key.
    fn determine_recovery_id(
        sig: &Signature,
        message_hash: &[u8; 32],
        expected_pubkey: &VerifyingKey,
    ) -> Result<RecoveryId> {
        let recid_0 = RecoveryId::from_byte(0).context("Bad RecoveryId byte 0")?;
        let recid_1 = RecoveryId::from_byte(1).context("Bad RecoveryId byte 1")?;

        if let Ok(recovered_key) =
            VerifyingKey::recover_from_prehash(message_hash, sig, recid_0)
        {
            if &recovered_key == expected_pubkey {
                return Ok(recid_0);
            }
        }

        if let Ok(recovered_key) =
            VerifyingKey::recover_from_prehash(message_hash, sig, recid_1)
        {
            if &recovered_key == expected_pubkey {
                return Ok(recid_1);
            }
        }

        anyhow::bail!("Could not recover correct public key from signature")
    }

    /// Verify a RecoverableSignature.
    /// Performs both standard verification and recovery verification.
    fn verify_recoverable_signature(
        rec_sig: &RecoverableSignature, // Accept the new type
        message_hash: &[u8; 32],
        expected_verifying_key: &VerifyingKey,
    ) -> Result<()> {
        // 1. Standard Verification using expected key and prehashed message
        expected_verifying_key
            .verify_prehash(message_hash, rec_sig.signature())
            .context("Standard verification failed using prehashed message")?;

        // 2. Recovery Verification
        let recovered_key = VerifyingKey::recover_from_prehash(
            message_hash,
            rec_sig.signature(),
            rec_sig.recovery_id(),
        )
        .context("Failed to recover public key from signature")?;

        if &recovered_key == expected_verifying_key {
            Ok(())
        } else {
            anyhow::bail!("Recovered key does not match expected key")
        }
    }

    // --- Unit Tests ---

    #[tokio::test]
    async fn test_kms_key_injection_verifies_public_key() -> Result<()> {
        let (kms_proc, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let local_pubkey_bytes =
            verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let kms_key = kms_proc.inject_secp256k1_key(&signing_key).await?;

        let kms_public_key_der = kms_key.get_public_key().await?;
        let kms_pubkey_hex = hex::encode(&kms_public_key_der);
        let local_pubkey_hex = hex::encode(local_pubkey_bytes);
        assert!(
            kms_pubkey_hex.contains(&local_pubkey_hex),
            "KMS public key '{}' does not contain our injected local public key '{}'",
            kms_pubkey_hex,
            local_pubkey_hex
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_local_signature() -> Result<()> {
        let (_, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let test_message = b"Test message for local signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();

        let local_signature: Signature = signing_key
            .sign_prehash(&message_hash_array)
            .expect("Failed to sign prehashed message locally");

        let processed_local_sig = RecoverableSignature::from_local_signature(
            &local_signature,
            &message_hash_array,
            &verifying_key,
        )
        .context("Processing local signature failed")?;

        let bytes_rsv = processed_local_sig.to_rsv_bytes();
        assert_eq!(bytes_rsv.len(), 65);

        verify_recoverable_signature(
            &processed_local_sig,
            &message_hash_array,
            &verifying_key,
        )
        .context("Verification of processed local signature failed")?;

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_kms_signature() -> Result<()> {
        let (kms_proc, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let kms_key = kms_proc.inject_secp256k1_key(&signing_key).await?;
        let test_message = b"Test message for KMS signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();

        let kms_signature_der_bytes = kms_key.sign_digest(&message_hash_array).await?;

        let processed_kms_sig = RecoverableSignature::from_kms_der(
            &kms_signature_der_bytes,
            &message_hash_array,
            &verifying_key,
        )
        .context("Processing KMS signature failed")?;

        let bytes_rsv = processed_kms_sig.to_rsv_bytes();
        assert_eq!(bytes_rsv.len(), 65);

        verify_recoverable_signature(
            &processed_kms_sig,
            &message_hash_array,
            &verifying_key,
        )
        .context("Verification of processed KMS signature failed")?;

        Ok(())
    }
}
