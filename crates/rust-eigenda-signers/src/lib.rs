// use async_trait::async_trait;
// use secp256k1::{
//     ecdsa::{RecoverableSignature, RecoveryId, Signature},
//     Error as SecpError, PublicKey,
// };
// use std::error::Error;
//
// /// Represents a potential error during the signing process.
// #[derive(Debug, thiserror::Error)]
// pub enum SignerError {
//     #[error("Secp256k1 error")]
//     Secp(#[source] SecpError),
//     #[error("Underlying signer error")]
//     SignerImplementation(#[source] Box<dyn Error + Send + Sync>),
// }
//
// /// A trait for signing messages using different key management strategies.
// #[async_trait]
// pub trait Signer: Send + Sync + std::fmt::Debug {
//     /// Signs a 32-byte digest and returns a recoverable signature.
//     ///
//     /// # Arguments
//     ///
//     /// * `digest` - The 32-byte digest to sign.
//     ///
//     /// # Returns
//     ///
//     /// A `Result` containing the 65-byte recoverable signature `[R || S || V]` on success,
//     /// or a `SignerError` on failure.
//     async fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 65], SignerError>;
//
//     /// Returns the public key associated with this signer.
//     fn public_key(&self) -> PublicKey;
//
//     /// Returns the Ethereum address associated with this signer.
//     fn address(&self) -> [u8; 20] {
//         let public_key = self.public_key().serialize_uncompressed();
//         // Ethereum address is the last 20 bytes of the Keccak256 hash of the uncompressed public key (excluding the prefix 0x04)
//         let hash = keccak256(&public_key[1..]);
//         let mut address = [0u8; 20];
//         address.copy_from_slice(&hash[12..]);
//         address
//     }
// }
// //
// // // // Helper function (assuming keccak256 is available or defined elsewhere)
// // fn keccak256(input: &[u8]) -> [u8; 32] {
// //     use tiny_keccak::{Hasher, Keccak};
// //     let mut hasher = Keccak::v256();
// //     let mut output = [0u8; 32];
// //     hasher.update(input);
// //     hasher.finalize(&mut output);
// //     output
// // }
// //
// // // --- Example Implementation for SecretKey (current approach) ---
// // use secp256k1::SecretKey;
// //
// // #[derive(Debug)]
// // pub struct LocalSigner {
// //     secret_key: SecretKey,
// //     public_key: PublicKey,
// // }
// //
// // impl LocalSigner {
// //     pub fn new(secret_key: SecretKey) -> Self {
// //         let secp = secp256k1::Secp256k1::signing_only();
// //         let public_key = PublicKey::from_secret_key(&secp, &secret_key);
// //         Self {
// //             secret_key,
// //             public_key,
// //         }
// //     }
// // }
// //
// // #[async_trait]
// // impl Signer for LocalSigner {
// //     async fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 65], SignerError> {
// //         let secp = secp256k1::Secp256k1::signing_only();
// //         let message = secp256k1::Message::from_slice(&digest)?;
// //         let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &self.secret_key);
// //         let (recovery_id, sig) = recoverable_sig.serialize_compact();
// //
// //         let mut signature_bytes = [0u8; 65];
// //         signature_bytes[..64].copy_from_slice(&sig);
// //         signature_bytes[64] = recovery_id.to_i32() as u8;
// //         Ok(signature_bytes)
// //     }
// //
// //     fn public_key(&self) -> PublicKey {
// //         self.public_key
// //     }
// // }
// //
// // // --- Example skeleton for KmsSigner ---
// // // #[derive(Debug, Clone)] // KmsKey might need Clone if the Signer is cloned
// // // pub struct KmsSigner {
// // //     kms_key: KmsKey, // Assuming KmsKey is defined as in e2e_tests
// // //     public_key: PublicKey, // Need to fetch and store this
// // // }
// //
// // // impl KmsSigner {
// // //     pub async fn new(kms_key: KmsKey) -> Result<Self, SignerError> {
// // //         // Fetch the public key from KMS during initialization
// // //         let pubkey_bytes = kms_key.get_public_key().await
// // //             .map_err(|e| SignerError::SignerImplementation(e.into()))?;
// // //         let public_key = PublicKey::from_slice(&pubkey_bytes)
// // //             .map_err(SignerError::Secp)?;
// // //         Ok(Self { kms_key, public_key })
// // //     }
// // // }
// //
// // // #[async_trait]
// // // impl Signer for KmsSigner {
// // //     async fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 65], SignerError> {
// // //         // 1. Call KMS to sign the digest
// // //         let der_signature = self.kms_key.sign_digest(&digest).await
// // //              .map_err(|e| SignerError::SignerImplementation(e.into()))?;
// //
// // //         // 2. Parse the DER signature
// // //         let sig = k256::ecdsa::Signature::from_der(&der_signature)
// // //             .map_err(|e| SignerError::SignerImplementation(e.into()))?;
// //
// // //         // 3. Determine the recovery ID (This is the tricky part)
// // //         //    You need to try both possible recovery IDs and see which one recovers
// // //         //    the correct public key.
// // //         let message = secp256k1::Message::from_slice(&digest)?;
// // //         let secp = secp256k1::Secp256k1::verification_only();
// //
// // //         let std_sig = secp256k1::ecdsa::Signature::from_compact(&sig.to_bytes())?;
// //
// // //         for rec_id_val in 0..=1 {
// // //              let recovery_id = secp256k1::ecdsa::RecoveryId::from_i32(rec_id_val)?;
// // //              if let Ok(recovered_pk) = secp.recover_ecdsa(&message, &std_sig) {
// // //                  if recovered_pk == self.public_key {
// // //                      let mut signature_bytes = [0u8; 65];
// // //                      signature_bytes[..64].copy_from_slice(&sig.to_bytes());
// // //                      signature_bytes[64] = rec_id_val as u8;
// // //                      return Ok(signature_bytes);
// // //                  }
// // //              }
// // //         }
// // //         Err(SignerError::SignerImplementation("Failed to determine recovery ID".into()))
// // //     }
// //
// // //     fn public_key(&self) -> PublicKey {
// // //         self.public_key
// // //     }
// // // }
