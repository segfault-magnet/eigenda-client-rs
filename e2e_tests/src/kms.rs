use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{
    config::Credentials,
    primitives::Blob,
    types::{KeySpec, KeyUsageType, Tag},
    Client,
};
use base64::Engine;
use k256::SecretKey;
use testcontainers::{core::ContainerPort, runners::AsyncRunner};
use tokio::io::AsyncBufReadExt;

// Add necessary imports
use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use k256::ecdsa::VerifyingKey;
use k256::pkcs8::DecodePublicKey;
use rust_eigenda_signers::{RecoverableSignature, Signer, SignerError};
use secp256k1::{ecdsa as secp_ecdsa, Error, PublicKey, Secp256k1};
use std::fmt;
use tiny_keccak::{Hasher, Keccak};

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
    pub async fn create_key(&self) -> anyhow::Result<String> {
        let response = self
            .client
            .create_key()
            .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
            .key_spec(aws_sdk_kms::types::KeySpec::EccSecgP256K1)
            .send()
            .await?;

        let id = response
            .key_metadata
            .and_then(|metadata| metadata.arn)
            .ok_or_else(|| anyhow::anyhow!("key arn missing from response"))?;

        Ok(id.to_string())
    }

    /// Creates an AwsKmsSigner instance for a given key ID.
    /// This fetches the public key during initialization.
    pub async fn get_signer(&self, key_id: String) -> anyhow::Result<AwsKmsSigner> {
        let public_key_der = self
            .client
            .get_public_key()
            .key_id(&key_id)
            .send()
            .await
            .context("Failed to get public key")?
            .public_key
            .context("Public key missing from response")?
            .into_inner();

        // Parse the DER-encoded public key using k256
        let k256_pub_key = VerifyingKey::from_public_key_der(&public_key_der)
            .context("Failed to parse public key DER from KMS")?;

        // Convert k256 public key to secp256k1 public key (use specific type)
        let secp_pub_key = PublicKey::from_slice(
            k256_pub_key.to_encoded_point(false).as_bytes(), // Get uncompressed bytes
        )
        // Map local secp error to SignerImplementation, not Secp
        .map_err(SignerError::Secp)
        .context("Failed to convert k256 pubkey to secp256k1 pubkey")?;

        Ok(AwsKmsSigner {
            key_id,
            client: self.client.clone(),
            public_key: secp_pub_key,
            k256_verifying_key: k256_pub_key, // Store k256 key for internal use
        })
    }

    /// Injects a secp256k1 private key into LocalStack KMS
    ///
    /// This uses the LocalStack-specific custom tag mechanism to inject the key material
    /// and create a new KMS key that uses the specified private key.
    /// Returns the Key ID (ARN) as a String.
    pub async fn inject_secp256k1_key(
        &self,
        signing_key: &SigningKey,
    ) -> anyhow::Result<String> {
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

        Ok(key_id) // Return the key ID string
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

// Define the new AwsKmsSigner struct
#[derive(Clone)]
pub struct AwsKmsSigner {
    key_id: String,
    client: Client,
    public_key: PublicKey,            // Use standard PublicKey type
    k256_verifying_key: VerifyingKey, // Store k256 version for recovery ID calculation
}

// Implement Debug manually to avoid showing the client details fully
impl fmt::Debug for AwsKmsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsKmsSigner")
            .field("key_id", &self.key_id)
            .field("public_key", &self.public_key)
            .field("k256_verifying_key", &self.k256_verifying_key)
            .field("client", &"aws_sdk_kms::Client { ... }") // Avoid printing potentially large client info
            .field("secp", &"Secp256k1 { ... }")
            .finish()
    }
}

#[async_trait]
impl Signer for AwsKmsSigner {
    async fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> Result<RecoverableSignature, SignerError> {
        // 1. Sign using KMS (returns DER signature)
        let sign_response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| SignerError::SignerImplementation(Box::new(e)))?; // Map SDK error

        let signature_der = sign_response
            .signature
            .ok_or_else(|| {
                SignerError::SignerImplementation(
                    anyhow::anyhow!("Signature missing from KMS response").into(),
                )
            })?
            .into_inner();

        // 2. Parse DER signature using k256
        let k256_sig = k256::ecdsa::Signature::from_der(&signature_der).map_err(|e| {
            SignerError::SignerImplementation(Box::new(e)) // Map k256 error
        })?;

        // 3. Normalize the k256 signature (low-S)
        let k256_sig_normalized = k256_sig.normalize_s().unwrap_or(k256_sig);

        // 4. Determine k256 Recovery ID
        let k256_recid = determine_k256_recovery_id(
            &k256_sig_normalized,
            &digest,
            &self.k256_verifying_key, // Use stored k256 verifying key
        )
        .map_err(|e| SignerError::SignerImplementation(e.into()))?;

        // 5. Convert k256 signature to secp256k1 signature
        let _secp_sig = secp_ecdsa::Signature::from_compact(&k256_sig_normalized.to_bytes())
            // Now map back to Secp as types should align
            .map_err(|e: Error| SignerError::Secp(e))?;

        // 6. Convert k256 recovery ID to secp256k1 recovery ID
        let secp_recid = secp_ecdsa::RecoveryId::from_i32(k256_recid.to_byte() as i32)
            // Map local secp error to SignerImplementation, not Secp
            .map_err(|e: Error| SignerError::Secp(e))?;

        // 8. Serialize to [R||S||V] format (65 bytes)
        // Remove serialization step
        // let (recid_val, sig_compact) = recoverable_sig.serialize_compact();
        // let mut result = [0u8; 65];
        // result[..64].copy_from_slice(&sig_compact);
        // result[64] = recid_val.to_i32() as u8; // V is the recovery ID

        // 9. Construct and return the RecoverableSignature struct
        Ok(RecoverableSignature {
            signature: _secp_sig, // Note: _secp_sig might need renaming if we use it here
            recovery_id: secp_recid,
        })
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }

    // address() method uses the default implementation from the trait
    // which calculates the address from the public_key()
}

// Helper function to determine k256 recovery ID (moved from tests)
fn determine_k256_recovery_id(
    sig: &k256::ecdsa::Signature,
    message_hash: &[u8; 32],
    expected_pubkey: &VerifyingKey,
) -> anyhow::Result<k256::ecdsa::RecoveryId> {
    let recid_0 =
        k256::ecdsa::RecoveryId::from_byte(0).context("Bad RecoveryId byte 0")?;
    let recid_1 =
        k256::ecdsa::RecoveryId::from_byte(1).context("Bad RecoveryId byte 1")?;

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

    anyhow::bail!("Could not recover correct public key from k256 signature")
}

// Restore local keccak256 helper function
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Helper function to set up KMS instance and generate keys
    /// Returns the KmsProcess, the original k256 key (for comparison), and the AwsKmsSigner
    async fn setup_kms_and_signer() -> Result<(KmsProcess, K256SigningKey, AwsKmsSigner)>
    {
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let signing_key = K256SigningKey::random(&mut OsRng); // Use k256 for injection

        // Inject the key and get the KMS key ID (now returns String)
        let kms_key_id = kms_proc
            .inject_secp256k1_key(&signing_key) // Inject accepts k256::ecdsa::SigningKey
            .await?;

        // Create the AwsKmsSigner instance using the key ID
        let aws_signer = kms_proc.get_signer(kms_key_id).await?;

        Ok((kms_proc, signing_key, aws_signer))
    }

    /// Helper to verify a signature using secp256k1 public key recovery
    // Update to accept RecoverableSignature struct
    fn verify_signature_recovery(
        rec_sig: &RecoverableSignature,
        message_hash: &[u8; 32],
        expected_pubkey: &PublicKey, // Use standard PublicKey type
    ) -> Result<()> {
        // Remove extraction from bytes
        // let recid_val = signature_rsv[64];
        // let sig_compact = &signature_rsv[..64];
        //
        // let recid = secp_ecdsa::RecoveryId::from_i32(recid_val as i32)
        //     .context("Invalid recovery ID")?;

        let message = secp256k1::Message::from_slice(message_hash)
            .context("Invalid message hash")?;

        // Use the provided RecoverableSignature components directly
        let sig = secp_ecdsa::RecoverableSignature::from_compact(
            &rec_sig.signature().serialize_compact(), // Get R||S bytes
            rec_sig.recovery_id(),                    // Get recovery ID
        )
        .context(
            "Failed to create secp256k1::RecoverableSignature from struct components",
        )?;

        // let sig = secp_ecdsa::RecoverableSignature::from_compact(sig_compact, recid)
        //     .context("Invalid compact signature format")?;

        let secp = Secp256k1::new();
        let recovered_pk = secp
            .recover_ecdsa(&message, &sig)
            .context("Failed to recover public key")?;

        if &recovered_pk == expected_pubkey {
            Ok(())
        } else {
            anyhow::bail!("Recovered public key does not match expected public key")
        }
    }

    #[tokio::test]
    async fn test_kms_signer_public_key_and_address() -> Result<()> {
        let (_kms_proc, k256_signing_key, aws_signer) = setup_kms_and_signer().await?;

        // 1. Compare Public Keys
        let k256_verifying_key = k256_signing_key.verifying_key();
        let expected_secp_pubkey = PublicKey::from_slice(
            // Use standard PublicKey type
            k256_verifying_key.to_encoded_point(false).as_bytes(),
        )
        .unwrap();

        let actual_secp_pubkey = aws_signer.public_key();
        assert_eq!(
            actual_secp_pubkey, expected_secp_pubkey,
            "Public key from AwsKmsSigner does not match the original injected key"
        );

        // 2. Compare Addresses
        // Calculate expected address from the original k256 key
        let encoded_point = k256_verifying_key.to_encoded_point(false);
        let pk_bytes = encoded_point.as_bytes();
        let hash = keccak256(&pk_bytes[1..]); // Exclude the 0x04 prefix
        let mut expected_address = [0u8; 20];
        expected_address.copy_from_slice(&hash[12..]);

        let actual_address = aws_signer.address(); // Uses trait default impl

        assert_eq!(
            actual_address, expected_address,
            "Address from AwsKmsSigner does not match the calculated address"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_kms_signer_sign_and_verify() -> Result<()> {
        let (_kms_proc, _k256_signing_key, aws_signer) = setup_kms_and_signer().await?;
        let test_message = b"Test message for KMS signer trait implementation";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();

        // Sign using the AwsKmsSigner trait method
        // Expect RecoverableSignature struct now
        let rec_sig = aws_signer
            .sign_digest(message_hash_array)
            .await
            .context("Signing with AwsKmsSigner failed")?;

        // Remove assertion on byte length
        // assert_eq!(signature_rsv.len(), 65, "Signature should be 65 bytes");

        // Get the expected public key (as secp256k1::PublicKey)
        let expected_pubkey = aws_signer.public_key(); // Already verified in another test

        // Verify the signature using public key recovery
        // Pass the RecoverableSignature struct
        verify_signature_recovery(&rec_sig, &message_hash_array, &expected_pubkey)
            .context("Signature verification failed")?;

        Ok(())
    }
}
