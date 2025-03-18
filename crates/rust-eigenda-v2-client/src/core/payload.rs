use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

use super::{blob::Blob, encoded_payload::EncodedPayload};

// TODO: remove, this will be implemented somewhere else
enum PayloadForm {
    Eval,
    Coeff,
}

/// Payload represents arbitrary user data, without any processing.
pub(crate) struct Payload {
    bytes: Vec<u8>,
}

impl Payload {
    /// Wraps an arbitrary array of bytes into a Payload type.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Converts the Payload bytes into a Blob
    ///
    /// The payload_form indicates how payloads are interpreted. The form of a payload dictates what conversion, if any, must
    /// be performed when creating a blob from the payload.
    pub fn to_blob(&self, payload_form: PayloadForm) -> Blob {
        let encoded_payload = EncodedPayload::new(&self);
        let field_elements = encoded_payload.to_field_elements();

        let blob_length_symbols = ((&field_elements).len() as u32).next_power_of_two();

        let coeff_polynomial = match payload_form {
            PayloadForm::Coeff => {
                // the payload is already in coefficient form. no conversion needs to take place, since blobs are also in
                // coefficient form
                field_elements
            }
            PayloadForm::Eval => {
                // the payload is in evaluation form, so we need to convert it to coeff form, since blobs are in coefficient form
                let eval_poly = field_elements;
                let coeff_poly = eval_to_coeff_poly(eval_poly, blob_length_symbols);
                coeff_poly
            }
        };

        Blob::from_polynomial(coeff_polynomial, blob_length_symbols)
    }

    /// Returns the bytes that underlie the payload, i.e. the unprocessed user data
    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Converts an eval_poly to a coeff_poly, using the IFFT operation
///
/// blob_length_symbols is required, to be able to choose the correct parameters when performing FFT
fn eval_to_coeff_poly(eval_poly: Vec<Fr>, blob_length_symbols: u32) -> Vec<Fr> {
    GeneralEvaluationDomain::<Fr>::new(blob_length_symbols as usize)
        .unwrap()
        .fft(&eval_poly)
}
