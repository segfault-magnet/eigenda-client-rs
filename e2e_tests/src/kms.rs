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
    use k256::ecdsa::{
        signature::hazmat::PrehashVerifier, // For verify_prehash
        RecoveryId, Signature, VerifyingKey,
    };
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    // --- Helper Functions ---

    /// Helper function to set up KMS instance and generate keys
    async fn setup_kms_and_keys() -> Result<(KmsProcess, SigningKey, VerifyingKey)> {
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key().clone();
        Ok((kms_proc, signing_key, verifying_key))
    }

    /// Normalize a DER-encoded signature and determine the recovery ID.
    /// This handles signatures typically returned by KMS.
    fn normalize_der_signature(
        signature_der: &[u8],
        message_hash: &[u8; 32],
        expected_pubkey: &VerifyingKey,
    ) -> Result<(Signature, RecoveryId)> {
        // Parse the DER signature
        let signature = Signature::from_der(signature_der)
            .context("Invalid DER signature")?;

        // Normalize S value (ECDSA allows two valid S values, usually low-S is preferred)
        let normalized_sig = signature.normalize_s().unwrap_or(signature);

        // Determine recovery ID by trying both possibilities
        let recovery_id = determine_recovery_id(&normalized_sig, message_hash, expected_pubkey)?;

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

        if let Ok(recovered_key) = VerifyingKey::recover_from_prehash(message_hash, sig, recid_0) {
            if &recovered_key == expected_pubkey {
                return Ok(recid_0);
            }
        }

        if let Ok(recovered_key) = VerifyingKey::recover_from_prehash(message_hash, sig, recid_1) {
            if &recovered_key == expected_pubkey {
                return Ok(recid_1);
            }
        }

        anyhow::bail!("Could not recover correct public key from signature")
    }

    /// Convert a k256 Signature and RecoveryId into the common 65-byte format [R||S||V].
    fn to_recoverable_signature_bytes(
        signature: &Signature,
        recovery_id: RecoveryId,
    ) -> Vec<u8> {
        let sig_bytes = signature.to_bytes();
        let mut result = Vec::with_capacity(65);
        result.extend_from_slice(&sig_bytes);
        result.push(recovery_id.to_byte());
        result
    }

    /// Process signature bytes (origin unknown) into the 65-byte recoverable format [R||S||V].
    /// It tries parsing as DER (KMS-like) first, then as compact R||S (local-like).
    fn process_signature_for_auth(
        signature_bytes: &[u8],
        message_hash: &[u8; 32],
        verifying_key: &VerifyingKey,
    ) -> Result<Vec<u8>> {
        // 1. Try processing as DER (like KMS)
        if let Ok((normalized_sig, recovery_id)) =
            normalize_der_signature(signature_bytes, message_hash, verifying_key)
        {
            println!("Processed signature as DER (KMS-like)");
            return Ok(to_recoverable_signature_bytes(&normalized_sig, recovery_id));
        }

        // 2. If DER failed, try processing as compact R||S (like local)
        if let Ok(sig) = Signature::try_from(signature_bytes) {
            println!("Processing signature as compact R||S (local-like)...");
            // Normalize the S value before attempting recovery
            let normalized_sig = sig.normalize_s().unwrap_or(sig);
            println!("Normalized compact signature");

            let recovery_id = determine_recovery_id(&normalized_sig, message_hash, verifying_key)
                .context("Failed to determine recovery ID for compact signature")?;
            println!(
                "Determined recovery ID for compact signature: {}",
                recovery_id.to_byte()
            );
            return Ok(to_recoverable_signature_bytes(&normalized_sig, recovery_id));
        }

        anyhow::bail!("Could not process signature bytes in any known format (DER or compact)")
    }

    /// Verify a 65-byte recoverable signature [R||S||V].
    /// Performs both standard verification and recovery verification.
    fn verify_recoverable_signature(
        signature_bytes_65: &[u8],
        message_hash: &[u8; 32],
        expected_verifying_key: &VerifyingKey,
    ) -> Result<()> {
        if signature_bytes_65.len() != 65 {
            anyhow::bail!("Invalid signature length: expected 65 bytes");
        }

        let signature_rs_bytes = &signature_bytes_65[..64];
        let recovery_id_byte = signature_bytes_65[64];

        // Parse the R||S signature bytes
        let signature = Signature::try_from(signature_rs_bytes)
            .context("Failed to parse R||S signature bytes")?;

        // Parse the recovery ID byte
        let recovery_id = RecoveryId::from_byte(recovery_id_byte)
            .context("Failed to parse recovery ID byte")?;

        println!(
            "Verifying recoverable sig ({} bytes) with RecID {}...",
            signature_bytes_65.len(),
            recovery_id.to_byte()
        );

        // 1. Standard Verification using expected key and prehashed message
        expected_verifying_key
            .verify_prehash(message_hash, &signature)
            .context("Standard verification failed using prehashed message")?;
        println!(" -> Standard prehashed verification successful.");

        // 2. Recovery Verification
        let recovered_key =
            VerifyingKey::recover_from_prehash(message_hash, &signature, recovery_id)
                .context("Failed to recover public key from signature")?;

        if &recovered_key == expected_verifying_key {
            println!(" -> Recovered key matches expected key.");
            Ok(())
        } else {
            anyhow::bail!("Recovered key does not match expected key")
        }
    }

    // --- Unit Tests ---

    #[tokio::test]
    async fn test_kms_key_injection_verifies_public_key() -> Result<()> {
        // Given: A KMS instance and a local secp256k1 key
        println!("Setting up KMS and local key...");
        let (kms_proc, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let local_pubkey_bytes =
            verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // When: The key is injected into KMS
        println!("Injecting key into KMS...");
        let kms_key = kms_proc.inject_secp256k1_key(&signing_key).await?;

        // Then: The public key retrieved from KMS matches the local public key
        println!("Verifying KMS public key...");
        let kms_public_key_der = kms_key.get_public_key().await?;
        let kms_pubkey_hex = hex::encode(&kms_public_key_der);
        let local_pubkey_hex = hex::encode(local_pubkey_bytes);
        assert!(
            kms_pubkey_hex.contains(&local_pubkey_hex),
            "KMS public key '{}' does not contain our injected local public key '{}'",
            kms_pubkey_hex,
            local_pubkey_hex
        );
        println!("Public key verification successful.");

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_local_signature() -> Result<()> {
        // Given: A local secp256k1 key and a message hash
        println!("Setting up local key...");
        let (_, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let test_message = b"Test message for local signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();
        println!("Message hash: {}", hex::encode(message_hash_array));

        // When: A signature is generated locally (using prehash) and processed
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let local_signature: Signature = signing_key
            .sign_prehash(&message_hash_array)
            .expect("Failed to sign prehashed message locally");
        let local_signature_compact_bytes = local_signature.to_bytes(); // R||S format
        println!(
            "Local signature (compact): {}",
            hex::encode(local_signature_compact_bytes)
        );

        let processed_local_65 = process_signature_for_auth(
            &local_signature_compact_bytes,
            &message_hash_array,
            &verifying_key,
        )
        .context("Processing local signature failed")?;

        // Then: The processed signature is 65 bytes long
        assert_eq!(
            processed_local_65.len(),
            65,
            "Processed local signature should be 65 bytes"
        );
        println!(
            "Processed local signature (65-byte): {}",
            hex::encode(&processed_local_65)
        );

        // And: The 65-byte signature can be verified successfully
        println!("\nVerifying processed LOCAL 65-byte signature:");
        verify_recoverable_signature(
            &processed_local_65,
            &message_hash_array,
            &verifying_key,
        )
        .context("Verification of processed local signature failed")?;
        println!("Local signature processing and verification successful.");

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_kms_signature() -> Result<()> {
        // Given: A KMS instance with an injected key and a message hash
        println!("Setting up KMS and injecting key...");
        let (kms_proc, signing_key, verifying_key) = setup_kms_and_keys().await?;
        let kms_key = kms_proc.inject_secp256k1_key(&signing_key).await?;
        let test_message = b"Test message for KMS signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();
        println!("Message hash: {}", hex::encode(message_hash_array));

        // When: A signature is generated by KMS and processed
        let kms_signature_der_bytes = kms_key.sign_digest(&message_hash_array).await?;
        println!(
            "KMS signature (DER): {}",
            hex::encode(&kms_signature_der_bytes)
        );

        let processed_kms_65 = process_signature_for_auth(
            &kms_signature_der_bytes,
            &message_hash_array,
            &verifying_key,
        )
        .context("Processing KMS signature failed")?;

        // Then: The processed signature is 65 bytes long
        assert_eq!(
            processed_kms_65.len(),
            65,
            "Processed KMS signature should be 65 bytes"
        );
        println!(
            "Processed KMS signature (65-byte): {}",
            hex::encode(&processed_kms_65)
        );

        // And: The 65-byte signature can be verified successfully
        println!("\nVerifying processed KMS 65-byte signature:");
        verify_recoverable_signature(
            &processed_kms_65,
            &message_hash_array,
            &verifying_key,
        )
        .context("Verification of processed KMS signature failed")?;
        println!("KMS signature processing and verification successful.");

        Ok(())
    }
}
