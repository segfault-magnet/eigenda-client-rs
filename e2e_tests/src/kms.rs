use anyhow::Context;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_kms::{
    config::Credentials,
    primitives::Blob,
    types::{KeySpec, KeyUsageType, Tag},
    Client,
};
use base64::Engine;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId, Signature},
    Message, PublicKey, Secp256k1, SecretKey, All,
};
use pkcs8::{der::{self, asn1::{ObjectIdentifier, AnyRef, OctetString}, Encode}, AlgorithmIdentifierRef, PrivateKeyInfo};
use der::Sequence;
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
            .key_usage(KeyUsageType::SignVerify)
            .key_spec(KeySpec::EccSecgP256K1)
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
    pub async fn inject_secp256k1_key(
        &self,
        secret_key: &SecretKey,
    ) -> anyhow::Result<KmsKey> {
        // Manual PKCS#8 DER encoding following RFC 5915
        let secret_bytes = secret_key.secret_bytes();

        // 1. Construct the inner ECPrivateKey structure
        let ec_private_key = EcPrivateKey {
            version: 1,
            private_key: OctetString::new(&secret_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to create OctetString: {}", e))?,
        };

        // 2. Encode the inner ECPrivateKey to DER bytes using to_der()
        let ec_private_key_der = ec_private_key.to_der()
             .map_err(|e| anyhow::anyhow!("Failed to encode ECPrivateKey to DER: {}", e))
             .context("Inner ECPrivateKey DER encoding failed")?;

        // 3. Define the AlgorithmIdentifier
        let alg_id = AlgorithmIdentifierRef {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(AnyRef::from(&OID_SECP256K1)),
        };

        // 4. Create the outer PrivateKeyInfo structure
        //    The private_key field contains the DER bytes of the ECPrivateKey
        let private_key_info = PrivateKeyInfo {
            algorithm: alg_id,
            private_key: &ec_private_key_der, // Use encoded inner structure
            public_key: None,
        };

        // 5. Encode the outer PrivateKeyInfo to DER
        let pkcs8_der_vec = private_key_info.to_der()
            .map_err(|e| anyhow::anyhow!("Failed to encode PrivateKeyInfo to DER: {}", e))
            .context("Outer PrivateKeyInfo DER encoding failed")?;

        // Base64-encode the final DER-encoded private key
        let base64_key_material =
            base64::engine::general_purpose::STANDARD.encode(&pkcs8_der_vec);

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

        // Extract key ID/ARN
        let key_id = create_key_resp
            .key_metadata
            .and_then(|m| Some(m.key_id))
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

// OID for secp256k1 curve
const OID_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
// OID for EC public key algorithm
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

// Define the ECPrivateKey structure
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(dead_code)]
struct EcPrivateKey {
    version: u8,
    private_key: OctetString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId, Signature},
        All, Message, PublicKey, Secp256k1, SecretKey,
    };
    use pkcs8::SubjectPublicKeyInfoRef;
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    /// Helper function to set up KMS instance and generate keys
    async fn setup_kms_and_keys(secp: &Secp256k1<All>) -> Result<(KmsProcess, SecretKey, PublicKey)> {
        let kms_proc = Kms::default().with_show_logs(false).start().await?;
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secret_key.public_key(secp);
        Ok((kms_proc, secret_key, public_key))
    }

    /// Verify a signature using the secp256k1 library
    fn verify_signature(
        secp: &Secp256k1<All>,
        sig: &Signature,
        message_hash: &[u8; 32],
        expected_pubkey: &PublicKey,
    ) -> Result<()> {
        let message = Message::from_digest_slice(message_hash)
            .context("Failed to create message from hash")?;
        secp.verify_ecdsa(&message, sig, expected_pubkey)
            .context("secp256k1 verification failed")?;
        Ok(())
    }

    /// Verify a recoverable signature using secp256k1 library
    fn verify_recoverable_signature(
        secp: &Secp256k1<All>,
        rec_sig: &RecoverableSignature,
        message_hash: &[u8; 32],
        expected_pubkey: &PublicKey,
    ) -> Result<()> {
        let message = Message::from_digest_slice(message_hash)
            .context("Failed to create message from hash")?;
        let recovered_key = secp
            .recover_ecdsa(&message, rec_sig)
            .context("Failed to recover public key from signature")?;

        if &recovered_key == expected_pubkey {
            Ok(())
        } else {
            anyhow::bail!("Recovered key does not match expected key")
        }
    }

    // --- Unit Tests ---

    #[tokio::test]
    async fn test_kms_key_injection_verifies_public_key() -> Result<()> {
        let secp = Secp256k1::new();
        let (kms_proc, secret_key, public_key) = setup_kms_and_keys(&secp).await?;
        let local_pubkey_bytes = public_key.serialize_uncompressed();

        let kms_key = kms_proc.inject_secp256k1_key(&secret_key).await?;
        let kms_public_key_der = kms_key.get_public_key().await?;

        let spki = SubjectPublicKeyInfoRef::try_from(&kms_public_key_der[..])
            .map_err(|e| anyhow::anyhow!("Failed to parse SPKI DER: {}", e))
            .context("Parsing SubjectPublicKeyInfo failed")?;

        // Access subject_public_key field directly, then call raw_bytes(). No context() needed here.
        let kms_pubkey_bytes_slice = spki
            .subject_public_key // Access field
            .raw_bytes();

        let kms_pubkey_hex = hex::encode(&kms_pubkey_bytes_slice);
        let local_pubkey_hex = hex::encode(local_pubkey_bytes.as_ref());

        assert_eq!(
            kms_pubkey_bytes_slice,
            local_pubkey_bytes.as_ref(),
            "KMS public key \'{}\' does not match injected local public key \'{}\'",
            kms_pubkey_hex,
            local_pubkey_hex
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_local_signature() -> Result<()> {
        let secp = Secp256k1::new();
        let (_, secret_key, public_key) = setup_kms_and_keys(&secp).await?;
        let test_message = b"Test message for local signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();
        let message = Message::from_digest_slice(&message_hash_array)
            .context("Failed to create message from hash")?;

        let local_signature: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &secret_key);

        verify_recoverable_signature(&secp, &local_signature, &message_hash_array, &public_key)
            .context("Verification of local signature failed")?;

        let (rec_id, sig_bytes) = local_signature.serialize_compact();
        let mut bytes_rsv = [0u8; 65];
        bytes_rsv[..64].copy_from_slice(&sig_bytes[..]);
        bytes_rsv[64] = rec_id.to_i32() as u8;
        assert_eq!(bytes_rsv.len(), 65);

        Ok(())
    }

    #[tokio::test]
    async fn test_process_and_verify_kms_signature() -> Result<()> {
        let secp = Secp256k1::new();
        let (kms_proc, secret_key, public_key) = setup_kms_and_keys(&secp).await?;
        let kms_key = kms_proc.inject_secp256k1_key(&secret_key).await?;
        let test_message = b"Test message for KMS signing";
        let message_hash_array: [u8; 32] = Sha256::digest(test_message).into();
        let message = Message::from_digest_slice(&message_hash_array)
            .context("Failed to create message from hash")?;

        let kms_signature_der_bytes = kms_key.sign_digest(&message_hash_array).await?;

        let mut kms_sig = Signature::from_der(&kms_signature_der_bytes)
            .context("Failed to parse DER signature from KMS")?;

        kms_sig.normalize_s();

        verify_signature(&secp, &kms_sig, &message_hash_array, &public_key)
            .context("Verification of KMS non-recoverable signature failed")?;

        let sig_compact_bytes = kms_sig.serialize_compact();

        let rec_id_0 = RecoveryId::from_i32(0).unwrap();
        let rec_id_1 = RecoveryId::from_i32(1).unwrap();

        let rec_sig_0 = RecoverableSignature::from_compact(&sig_compact_bytes, rec_id_0)
            .context("Failed to create recoverable signature with recid 0")?;
        let rec_sig_1 = RecoverableSignature::from_compact(&sig_compact_bytes, rec_id_1)
            .context("Failed to create recoverable signature with recid 1")?;

        let recovered_key_0 = secp.recover_ecdsa(&message, &rec_sig_0);
        let recovered_key_1 = secp.recover_ecdsa(&message, &rec_sig_1);

        let kms_recoverable_sig = if recovered_key_0 == Ok(public_key) {
            rec_sig_0
        } else if recovered_key_1 == Ok(public_key) {
            rec_sig_1
        } else {
            anyhow::bail!("Could not recover the correct public key from KMS signature")
        };

        verify_recoverable_signature(&secp, &kms_recoverable_sig, &message_hash_array, &public_key)
            .context("Verification of processed KMS signature failed")?;

        let (rec_id, sig_bytes) = kms_recoverable_sig.serialize_compact();
        let mut bytes_rsv = [0u8; 65];
        bytes_rsv[..64].copy_from_slice(&sig_bytes[..]);
        bytes_rsv[64] = rec_id.to_i32() as u8;
        assert_eq!(bytes_rsv.len(), 65);

        Ok(())
    }
}
