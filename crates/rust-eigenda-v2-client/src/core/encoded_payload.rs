use ark_bn254::Fr;

use super::payload::Payload;

pub(crate) struct EncodedPayload {}

impl EncodedPayload {
    pub fn new(payload: &Payload) -> Self {
        EncodedPayload {}
    }

    pub(crate) fn to_field_elements(&self) -> Vec<Fr> {
        todo!()
    }
}
