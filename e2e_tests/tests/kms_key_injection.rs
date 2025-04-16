use anyhow::Context;
use aws_sdk_kms::config::endpoint::Endpoint;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec, Tag};
use base64::Engine;
use e2e_tests::kms::Kms;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const TEST_MESSAGE: &[u8] = b"This is a test message for signing";

// #[tokio::test]
// async fn test_kms_key_injection_and_signing() -> anyhow::Result<()> {
//     // 1. Start LocalStack KMS
//     let kms_proc = Kms::default().with_show_logs(true).start().await?;
//     let kms_client = kms_proc.client();
//
//     // 2. Generate a local secp256k1 key pair
//     let signing_key = SigningKey::random(&mut OsRng); // Generate a new private key
//     let verifying_key = signing_key.verifying_key(); // Get the corresponding public key
//
//     // 3. Prepare for key import
//     // 3a. Get import parameters from KMS (without specifying wrapping)
//     let params_response = kms_client
//         .get_parameters_for_import()
//         .send()
//         .await
//         .context("Failed to get parameters for import")?;
//
//     let import_token = params_response
//         .import_token
//         .context("Missing import token")?;
//
//     // 3b. Export the private key bytes
//     let private_key_bytes = signing_key.to_bytes();
//
//     // 4. Create a placeholder key in KMS first
//     let created_key_response = kms_client
//         .create_key()
//         .key_usage(KeyUsageType::SignVerify)
//         .key_spec(KeySpec::EccSecgP256K1)
//         .description("Key for injection test")
//         .send()
//         .await
//         .context("Failed to create initial KMS key")?;
//
//     let key_id = created_key_response
//         .key_metadata
//         .context("Missing key metadata")?
//         .key_id;
//
//     println!("Created KMS key with ID: {}", key_id);
//
//     let import_response_with_id = kms_client
//         .import_key_material()
//         .key_id(key_id.clone())
//         .import_token(import_token) // Use the obtained token
//         .encrypted_key_material(Blob::new(private_key_bytes.as_slice())) // Use key_material for raw bytes
//         .expiration_model(
//             aws_sdk_kms::types::ExpirationModelType::KeyMaterialDoesNotExpire,
//         )
//         .send()
//         .await
//         .context(format!(
//             "Failed to import key material for key ID: {}",
//             key_id
//         ))?;
//
//     println!("Successfully imported key material for key ID: {}", key_id);
//
//     // 5. Prepare the message hash (SHA-256)
//     let mut hasher = Sha256::new();
//     hasher.update(TEST_MESSAGE);
//     let message_hash = hasher.finalize();
//
//     // 6. Sign the hash with the original local key
//     let local_signature: Signature = signing_key.sign(&message_hash);
//     let local_signature_bytes = local_signature.to_der().to_bytes(); // Get DER encoded signature
//     println!(
//         "Local Signature (DER base64): {}",
//         base64::engine::general_purpose::STANDARD.encode(&local_signature_bytes)
//     );
//
//     // 7. Sign the hash using the KMS key
//     let kms_sign_response = kms_client
//         .sign()
//         .key_id(key_id.clone())
//         .message(Blob::new(message_hash.as_slice()))
//         .message_type(MessageType::Digest) // Specify we are signing a digest
//         .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
//         .send()
//         .await
//         .context(format!("Failed to sign using KMS key ID: {}", key_id))?;
//
//     let kms_signature_blob = kms_sign_response
//         .signature
//         .context("Missing signature from KMS response")?;
//     let kms_signature_bytes = kms_signature_blob.into_inner();
//     println!(
//         "KMS Signature (ASN.1 base64): {}",
//         base64::engine::general_purpose::STANDARD.encode(&kms_signature_bytes)
//     );
//
//     // 8. Compare the signatures
//     // AWS KMS returns an ASN.1 DER encoded signature. k256 produces a fixed-size signature.
//     // We need to parse the KMS signature to compare.
//     let kms_signature_parsed = Signature::from_der(&kms_signature_bytes)
//         .context("Failed to parse KMS signature from DER format")?;
//
//     assert_eq!(
//         local_signature, kms_signature_parsed,
//         "Signature from local key does not match signature from KMS key"
//     );
//
//     println!("Signatures match!");
//
//     // Optional: Clean up the key (disable/schedule deletion)
//     // kms_client.schedule_key_deletion().key_id(key_id).pending_window_in_days(7).send().await?;
//
//     Ok(())
// }

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::{Client, Config, Error};
use std::str::FromStr;

#[tokio::test]
async fn test_kms_key_injection_and_signing_gpt() -> anyhow::Result<()> {
    //     // 1. Start LocalStack KMS
    let kms_proc = Kms::default().with_show_logs(true).start().await?;
    let client = kms_proc.client();

    // Define your premade key material (Base64-encoded) and custom key id.
    // Ensure that the key material meets the required length/format for your key.
    let signing_key = SigningKey::random(&mut OsRng); // Generate a new private key
    let material = signing_key.to_bytes();
    let base64_key_material = base64::engine::general_purpose::STANDARD.encode(&material);
    let custom_key_material = base64_key_material.as_str();
    let custom_key_id = "00000000-0000-0000-0000-000000000001";

    // Create the key with custom tags for pre-seeded key material.
    let create_key_resp = client
        .create_key()
        .set_tags(Some(vec![
            Tag::builder()
                .tag_key("_custom_id_")
                .tag_value(custom_key_id)
                .build()
                .unwrap(),
            Tag::builder()
                .tag_key("_custom_key_material_")
                .tag_value(custom_key_material)
                .build()
                .unwrap(),
        ]))
        .send()
        .await?;

    // Print out the created key ID
    if let Some(metadata) = create_key_resp.key_metadata {
        println!("Created KMS Key with ID: {}", metadata.key_id);
    } else {
        println!("No key metadata returned.");
    }

    Ok(())
}
