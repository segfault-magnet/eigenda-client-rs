use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use std::error::Error;
/// Converts an eval_poly to a coeff_poly, using the IFFT operation
///
/// blob_length_symbols is required, to be able to choose the correct parameters when performing FFT
pub(crate) fn eval_to_coeff_poly(
    eval_poly: Vec<Fr>,
    blob_length_symbols: usize,
) -> Result<Vec<Fr>, String> {
    Ok(GeneralEvaluationDomain::<Fr>::new(blob_length_symbols)
        .ok_or("Failed to create domain")?
        .ifft(&eval_poly))
}

/// computeEvalPoly converts a blob's coeffPoly to an evalPoly, using the FFT operation
pub(crate) fn coeff_to_eval_poly(
    coeff_poly: Vec<Fr>,
    blob_length_symbols: usize,
) -> Result<Vec<Fr>, Box<dyn Error>> {
    let evals = GeneralEvaluationDomain::<Fr>::new(blob_length_symbols)
        .ok_or("Failed to construct domain for FFT".to_string())?
        .fft(&coeff_poly);
    Ok(evals)
}
