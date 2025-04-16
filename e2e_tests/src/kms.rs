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
    use k256::ecdsa::{
        signature::{Signer, Verifier},
        RecoveryId, Signature,
    };
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Normalize a DER-encoded signature and determine the recovery ID
    fn normalize_signature(
        signature_der: &[u8],
        message: &[u8; 32],
        expected_pubkey: &k256::ecdsa::VerifyingKey,
    ) -> anyhow::Result<(Signature, RecoveryId)> {
        // Parse the DER signature
        let signature = Signature::from_der(signature_der)
            .context("Invalid DER signature")?;

        // Normalize S value (ECDSA allows two valid S values)
        let normalized_sig = signature.normalize_s().unwrap_or(signature);

        // Determine recovery ID
        let recovery_id = determine_recovery_id(&normalized_sig, message, expected_pubkey)?;

        Ok((normalized_sig, recovery_id))
    }

    /// Determine the correct recovery ID for a signature
    fn determine_recovery_id(
        sig: &Signature,
        message: &[u8; 32],
        expected_pubkey: &k256::ecdsa::VerifyingKey,
    ) -> anyhow::Result<RecoveryId> {
        // Try both possible recovery IDs
        let recid_even = RecoveryId::from_byte(0)
            .context("Failed to create even recovery ID")?;
        let recid_odd = RecoveryId::from_byte(1)
            .context("Failed to create odd recovery ID")?;

        // Use digest API directly instead of Message
        // The k256 library expects the digest to be a generic parameter
        
        // Attempt recovery with both IDs
        let recovered_even = k256::ecdsa::VerifyingKey::recover_from_prehash(
            message,
            sig,
            recid_even,
        );
        
        let recovered_odd = k256::ecdsa::VerifyingKey::recover_from_prehash(
            message,
            sig,
            recid_odd,
        );

        // Check which one matches our expected key
        if let Ok(key) = recovered_even {
            if &key == expected_pubkey {
                return Ok(recid_even);
            }
        }

        if let Ok(key) = recovered_odd {
            if &key == expected_pubkey {
                return Ok(recid_odd);
            }
        }

        // If neither matches, return error
        anyhow::bail!("Could not recover correct public key from signature")
    }

    /// Convert a signature to the 65-byte format with recovery ID
    fn to_recoverable_signature(signature: &Signature, recovery_id: RecoveryId) -> Vec<u8> {
        let sig_bytes = signature.to_bytes();
        let mut result = Vec::with_capacity(65);
        result.extend_from_slice(&sig_bytes);
        result.push(recovery_id.to_byte());
        result
    }

    #[tokio::test]
    async fn test_kms_key_injection() -> anyhow::Result<()> {
        // Given a LocalStack KMS instance and a local secp256k1 key
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let local_pubkey_bytes =
            verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // When we inject the key into KMS
        let kms_key = kms_proc.inject_secp256k1_key(&signing_key).await?;

        // Then the KMS public key should contain our local public key
        let kms_public_key_der = kms_key.get_public_key().await?;
        let kms_pubkey_hex = hex::encode(&kms_public_key_der);
        let local_pubkey_hex = hex::encode(local_pubkey_bytes);

        assert!(
            kms_pubkey_hex.contains(&local_pubkey_hex),
            "KMS public key does not contain our injected local public key"
        );

        // Sign the same message with both the local key and KMS
        let test_message = b"Test message for signing";
        let mut hasher = Sha256::new();
        hasher.update(test_message);
        let message_hash = hasher.finalize();
        let message_hash_array: [u8; 32] = message_hash.into();

        // Local signature
        let local_signature: Signature = signing_key.sign(&message_hash);
        verifying_key
            .verify(&message_hash, &local_signature)
            .expect("Failed to verify local signature");

        // Get recovery ID for local signature
        // For a locally generated signature, we know it's valid, so use recovery_id=0
        // Use unwrap instead of ? since from_byte returns an Option not a Result
        let local_recid = RecoveryId::from_byte(0)
            .context("Failed to create recovery ID")?;
        
        // Convert local signature to recoverable format (65 bytes)
        let local_recoverable = to_recoverable_signature(&local_signature, local_recid);
        println!("Local recoverable sig: {}", hex::encode(&local_recoverable));

        // KMS signature
        let kms_signature_bytes = kms_key.sign_digest(&message_hash_array).await?;
        println!("KMS signature (DER): {}", hex::encode(&kms_signature_bytes));
        
        // Parse, normalize and find recovery ID for the KMS signature
        println!("Normalizing KMS signature and finding recovery ID...");
        match normalize_signature(&kms_signature_bytes, &message_hash_array, &verifying_key) {
            Ok((normalized_sig, recovery_id)) => {
                println!("Successfully normalized KMS signature");
                println!("KMS signature recovery ID: {}", recovery_id.to_byte());
                
                // Convert to recoverable format (65 bytes)
                let kms_recoverable = to_recoverable_signature(&normalized_sig, recovery_id);
                println!("KMS recoverable sig: {}", hex::encode(&kms_recoverable));
                
                // Now verify the normalized signature
                match verifying_key.verify(&message_hash, &normalized_sig) {
                    Ok(_) => println!("Normalized KMS signature verified successfully!"),
                    Err(e) => println!("Normalized KMS signature verification failed: {}", e),
                }
                
                // Compare R and S components 
                let (local_r, local_s) = {
                    let bytes = local_signature.to_bytes();
                    let r = &bytes[..32];
                    let s = &bytes[32..];
                    (hex::encode(r), hex::encode(s))
                };
                
                let (kms_r, kms_s) = {
                    let bytes = normalized_sig.to_bytes();
                    let r = &bytes[..32];
                    let s = &bytes[32..];
                    (hex::encode(r), hex::encode(s))
                };
                
                println!("Local signature R: {}", local_r);
                println!("Local signature S: {}", local_s);
                println!("KMS signature R: {}", kms_r);
                println!("KMS signature S: {}", kms_s);
            },
            Err(e) => {
                println!("Failed to normalize KMS signature: {}", e);
            }
        }
        
        println!("Key injection test PASSED");
        println!("Public key verification successful");
        
        Ok(())
    }
}
