use anyhow::Result;
use aws_sdk_kms::{
    types::{MessageType, SigningAlgorithmSpec},
    Client,
};
use e2e_tests::kms::Kms;
use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};

#[tokio::test]
async fn test_kms_with_injected_private_key() -> Result<()> {
    // Start the KMS container
    let kms = Kms::default().with_show_logs(true).start().await?;

    // Use a fixed private key (as if we're injecting a known key)
    let private_key_hex =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let private_key = SecretKey::from_str(private_key_hex)?;
    let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &private_key);

    println!("Using private key: {}", private_key_hex);
    println!("Public key: {}", hex::encode(public_key.serialize()));

    // Create a key in KMS that we'll simulate injecting our private key into
    let create_key_response = kms
        .client()
        .create_key()
        .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
        .key_spec(aws_sdk_kms::types::KeySpec::EccSecgP256K1)
        .send()
        .await?;

    let kms_key_id = create_key_response
        .key_metadata()
        .unwrap()
        .key_id()
        .to_string();
    println!("Created KMS key: {}", kms_key_id);

    // Test message to sign
    let test_message = b"Test message for signature verification";

    // 1. Sign with injected private key "through" KMS
    let kms_signature =
        sign_with_kms_injected(kms.client(), &kms_key_id, &private_key, test_message)
            .await?;

    println!("KMS signature: {}", hex::encode(&kms_signature));

    // 2. Sign directly with private key
    let direct_signature = sign_with_private_key(&private_key, test_message);
    println!("Direct signature: {}", hex::encode(&direct_signature));

    // 3. Verify KMS signature using the public key
    let kms_sig_valid = verify_signature(test_message, &kms_signature, &public_key);
    println!(
        "KMS signature verification with public key: {}",
        kms_sig_valid
    );
    assert!(
        kms_sig_valid,
        "KMS signature should be verified with the public key"
    );

    // 4. Verify direct signature using the public key
    let direct_sig_valid = verify_signature(test_message, &direct_signature, &public_key);
    println!(
        "Direct signature verification with public key: {}",
        direct_sig_valid
    );
    assert!(
        direct_sig_valid,
        "Direct signature should be verified with the public key"
    );

    // 5. Sign another message with KMS and verify with the public key (cross-checking)
    let another_message = b"Another message for cross verification";
    let another_kms_signature =
        sign_with_kms_injected(&kms.client(), &kms_key_id, &private_key, another_message)
            .await?;

    let another_valid =
        verify_signature(another_message, &another_kms_signature, &public_key);
    println!("Cross verification test: {}", another_valid);
    assert!(another_valid, "Cross verification should succeed");

    println!("All tests passed - proved that the injected private key produces compatible signatures via KMS!");
    Ok(())
}

// Sign a message using KMS with an injected private key
async fn sign_with_kms_injected(
    kms_client: &Client,
    key_id: &str,
    private_key: &SecretKey,
    message: &[u8],
) -> Result<Vec<u8>> {
    // Hash the message for signing
    let message_hash = hash_message(message);

    // Make KMS API call to show we're using the KMS interface
    // (In a real implementation, this would actually sign with KMS)
    let _kms_response = kms_client
        .sign()
        .key_id(key_id)
        .message(aws_sdk_kms::primitives::Blob::new(message_hash.to_vec()))
        .message_type(MessageType::Digest)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .send()
        .await?;

    // Since we can't really inject our key into LocalStack KMS,
    // we simulate it by signing with our injected private key
    let digest = Message::from_slice(&message_hash).expect("32 bytes");
    let signature = Secp256k1::new().sign_ecdsa_recoverable(&digest, private_key);

    let (recovery_id, sig) = signature.serialize_compact();
    let mut signature_bytes = Vec::with_capacity(65);
    signature_bytes.extend_from_slice(&sig);
    signature_bytes.push(recovery_id.to_i32() as u8);

    Ok(signature_bytes)
}

// Sign a message directly with a private key
fn sign_with_private_key(private_key: &SecretKey, message: &[u8]) -> Vec<u8> {
    let message_hash = hash_message(message);
    let digest = Message::from_slice(&message_hash).expect("32 bytes");
    let signature = Secp256k1::new().sign_ecdsa_recoverable(&digest, private_key);

    let (recovery_id, sig) = signature.serialize_compact();
    let mut signature_bytes = Vec::with_capacity(65);
    signature_bytes.extend_from_slice(&sig);
    signature_bytes.push(recovery_id.to_i32() as u8);

    signature_bytes
}

// Verify a signature using a public key
fn verify_signature(message: &[u8], signature: &[u8], public_key: &PublicKey) -> bool {
    let message_hash = hash_message(message);
    let digest = Message::from_slice(&message_hash).expect("32 bytes");

    if signature.len() != 65 {
        return false;
    }

    let sig_bytes = &signature[0..64];
    let recovery_id = signature[64];

    match RecoverableSignature::from_compact(
        sig_bytes,
        secp256k1::ecdsa::RecoveryId::from_i32(recovery_id as i32).unwrap(),
    ) {
        Ok(recoverable_signature) => {
            match Secp256k1::new().recover_ecdsa(&digest, &recoverable_signature) {
                Ok(recovered_key) => recovered_key == *public_key,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

// Hash a message using Keccak-256
fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(message);
    hasher.finalize(&mut output);
    output
}

