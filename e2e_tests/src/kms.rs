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
    use k256::ecdsa::{signature::Signer, Signature};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn test_kms_key_injection() -> anyhow::Result<()> {
        // Given a LocalStack KMS instance and a local secp256k1 key
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let signing_key = SigningKey::random(&mut OsRng);
        let local_pubkey_bytes = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

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

        // And when we sign the same message with both keys
        let test_message = b"Test message for signing";
        let mut hasher = Sha256::new();
        hasher.update(test_message);
        let message_hash = hasher.finalize();

        // Then both signatures should be verifiable with the same public key
        let local_signature: Signature = signing_key.sign(&message_hash);
        let kms_signature_bytes = kms_key.sign_digest(message_hash.as_slice()).await?;

        // The signatures will be different due to ECDSA randomness,
        // but both should be valid signatures for the same message and key

        // Verify that we can parse the KMS signature in our crypto library
        let kms_signature = Signature::from_der(&kms_signature_bytes)
            .context("Failed to parse KMS signature")?;

        // Both signatures should be different (due to ECDSA's randomness)
        assert_ne!(
            local_signature, kms_signature,
            "Signatures should be different due to ECDSA randomness"
        );

        Ok(())
    }
}
