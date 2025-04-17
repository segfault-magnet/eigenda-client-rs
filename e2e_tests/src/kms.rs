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

use async_trait::async_trait;
use k256::ecdsa::SigningKey;
use k256::ecdsa::VerifyingKey;
use k256::pkcs8::DecodePublicKey;
use rust_eigenda_signers::{ecdsa, Message, PublicKey, Signer, SignerError};
use std::fmt;

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

        // Convert k256 public key to secp256k1 public key
        let secp_pub_key =
            PublicKey::from_slice(k256_pub_key.to_encoded_point(false).as_bytes())
                .map_err(|e| SignerError::SignerSpecific(Box::new(e)))
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

        let key_id = create_key_resp
            .key_metadata
            .map(|m| m.key_id)
            .context("Key ID missing from response")?;

        Ok(key_id)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Clone)]
pub struct AwsKmsSigner {
    key_id: String,
    client: Client,
    public_key: PublicKey,
    k256_verifying_key: VerifyingKey, // Store k256 key for internal use
}

impl AwsKmsSigner {
    pub async fn new(client: Client, key_id: String) -> anyhow::Result<Self> {
        let public_key_der = client
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

        // Convert k256 public key to secp256k1 public key
        let secp_pub_key =
            PublicKey::from_slice(k256_pub_key.to_encoded_point(false).as_bytes())
                .map_err(|e| SignerError::SignerSpecific(Box::new(e)))
                .context("Failed to convert k256 pubkey to secp256k1 pubkey")?;

        Ok(AwsKmsSigner {
            key_id,
            client,
            public_key: secp_pub_key,
            k256_verifying_key: k256_pub_key, // Store k256 key for internal use
        })
    }
}

// Implement Debug manually to avoid showing the client details fully
impl fmt::Debug for AwsKmsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsKmsSigner")
            .field("key_id", &self.key_id)
            .field("public_key", &self.public_key)
            .field("k256_verifying_key", &self.k256_verifying_key)
            .field("client", &"aws_sdk_kms::Client { ... }") // Avoid printing potentially large client info
            .finish()
    }
}

#[async_trait]
impl Signer for AwsKmsSigner {
    async fn sign_digest(
        &self,
        message: &Message,
    ) -> Result<ecdsa::RecoverableSignature, SignerError> {
        let digest_bytes: &[u8; 32] = message.as_ref();

        let sign_response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest_bytes))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await // Ensure .await is before map_err
            .map_err(|e| SignerError::SignerSpecific(Box::new(e)))?;

        let signature_der = sign_response
            .signature
            .ok_or_else(|| {
                SignerError::SignerSpecific(
                    anyhow::anyhow!("Signature missing from KMS response").into(),
                )
            })?
            .into_inner();

        let k256_sig = k256::ecdsa::Signature::from_der(&signature_der)
            .map_err(|e| SignerError::SignerSpecific(Box::new(e)))?;

        let k256_sig_normalized = k256_sig.normalize_s().unwrap_or(k256_sig);

        let k256_recid = determine_k256_recovery_id(
            &k256_sig_normalized,
            digest_bytes,
            &self.k256_verifying_key, // Use stored k256 key for internal use
        )
        .map_err(|e| SignerError::SignerSpecific(e.into()))?;

        let secp_sig = ecdsa::Signature::from_compact(&k256_sig_normalized.to_bytes())
            .map_err(|e| SignerError::SignerSpecific(Box::new(e)))?;

        let secp_recid = ecdsa::RecoveryId::from_i32(k256_recid.to_byte() as i32)
            .map_err(|e| SignerError::SignerSpecific(Box::new(e)))?;

        let standard_recoverable_sig = ecdsa::RecoverableSignature::from_compact(
            secp_sig.serialize_compact().as_slice(),
            secp_recid,
        )
        .map_err(|e| SignerError::SignerSpecific(Box::new(e)))?;

        Ok(standard_recoverable_sig)
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

// Helper function to determine k256 recovery ID.
// Necessary because KMS returns a DER signature, and we need to extract R, S, and find V.
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use k256::ecdsa::SigningKey as K256SigningKey;
    use rand::rngs::OsRng;
    use rust_eigenda_signers::ecdsa::RecoverableSignature as SecpRecoverableSignature;
    use rust_eigenda_signers::Message as SecpMessage;
    use rust_eigenda_signers::PrivateKeySigner;
    use secp256k1::Secp256k1;
    use sha2::{Digest, Sha256};

    async fn setup_kms_and_signer() -> Result<(KmsProcess, PrivateKeySigner, AwsKmsSigner)>
    {
        let kms_proc = Kms::default().with_show_logs(false).start().await?;

        let k256_secret_key = k256::SecretKey::random(&mut OsRng);
        let k256_signing_key = K256SigningKey::from(&k256_secret_key);

        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&k256_secret_key.to_bytes())
                .expect("Failed to create secp256k1 secret key from k256 bytes");
        let local_signer = PrivateKeySigner::new(secp_secret_key);

        let kms_key_id = kms_proc.inject_secp256k1_key(&k256_signing_key).await?;

        let aws_signer = kms_proc.get_signer(kms_key_id).await?;

        Ok((kms_proc, local_signer, aws_signer))
    }

    fn verify_signature_recovery(
        rec_sig: &SecpRecoverableSignature,
        message: &SecpMessage,
        expected_pubkey: &PublicKey,
    ) -> Result<()> {
        let secp = Secp256k1::new();
        let recovered_pk = secp
            .recover_ecdsa(message, rec_sig)
            .context("Failed to recover public key")?;

        if &recovered_pk == expected_pubkey {
            Ok(())
        } else {
            anyhow::bail!("Recovered public key does not match expected public key")
        }
    }

    #[tokio::test]
    async fn test_kms_signer_public_key_and_address() -> Result<()> {
        let (_kms_proc, local_signer, aws_signer) = setup_kms_and_signer().await?;

        let expected_secp_pubkey = local_signer.public_key();
        let actual_secp_pubkey = aws_signer.public_key();
        assert_eq!(
            actual_secp_pubkey, expected_secp_pubkey,
            "Public key from AwsKmsSigner does not match the expected key from LocalSigner"
        );

        let expected_address = local_signer.address();
        let actual_address = aws_signer.address();
        assert_eq!(
            actual_address, expected_address,
            "Address from AwsKmsSigner does not match the expected address from LocalSigner"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_kms_signer_sign_and_verify() -> Result<()> {
        let (_kms_proc, local_signer, aws_signer) = setup_kms_and_signer().await?;
        let test_message_bytes = b"Test message for KMS signer trait implementation";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message_bytes).into();
        let message = SecpMessage::from_slice(&message_hash_array)
            .expect("Failed to create Message from digest");

        let rec_sig: SecpRecoverableSignature = aws_signer
            .sign_digest(&message)
            .await
            .context("Signing with AwsKmsSigner failed")?;

        let expected_pubkey = local_signer.public_key();

        verify_signature_recovery(&rec_sig, &message, &expected_pubkey)
            .context("Signature verification failed")?;

        Ok(())
    }
}
