use ark_bulletproofs::{r1cs::R1CSError as ArkR1CSError, ProofError as ArkProofError};
use ark_std::{boxed::Box, error, fmt, format};
use bulletproofs::{r1cs::R1CSError, ProofError};
use noah_algebra::prelude::AlgebraError;

pub(crate) type Result<T> = core::result::Result<T, CryptoError>;

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum CryptoError {
    ParameterError,
    SignatureError,
    AnonymousCredentialSignError,
    IdentityRevealVerifyError,
    ElGamalVerificationError,
    ZKProofVerificationError,
    ZKProofBatchVerificationError,
    Algebra(AlgebraError),
    R1CS(R1CSError),
    Bulletproofs(ProofError),
    ArkR1CS(ArkR1CSError),
    ArkBulletproofs(ArkProofError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CryptoError::*;
        f.write_str(match self {
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            AnonymousCredentialSignError => "The number of attributes passed as parameter differs from the number of attributes of the AC issuer public key",
            IdentityRevealVerifyError => "Verification error for confidential identity reveal proof",
            ElGamalVerificationError => "ElGamal Ciphertext not valid for proposed scalar message",
            ZKProofVerificationError => "Invalid proof",
            ZKProofBatchVerificationError => "Batch proof instance contains an error",
            Algebra(e) => Box::leak(format!("Algebra: {}", e).into_boxed_str()),
            R1CS(e) => Box::leak(format!("R1CS: {}", e).into_boxed_str()),
            Bulletproofs(e) => Box::leak(format!("Bulletproofs: {}", e).into_boxed_str()),
            ArkR1CS(e) => Box::leak(format!("Ark R1CS: {}", e).into_boxed_str()),
            ArkBulletproofs(e) => Box::leak(format!("ArkBulletproofs: {}", e).into_boxed_str()),
        })
    }
}

impl error::Error for CryptoError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}

impl From<R1CSError> for CryptoError {
    fn from(e: R1CSError) -> CryptoError {
        CryptoError::R1CS(e)
    }
}

impl From<ProofError> for CryptoError {
    fn from(e: ProofError) -> CryptoError {
        CryptoError::Bulletproofs(e)
    }
}

impl From<ArkR1CSError> for CryptoError {
    fn from(e: ArkR1CSError) -> CryptoError {
        CryptoError::ArkR1CS(e)
    }
}

impl From<ArkProofError> for CryptoError {
    fn from(e: ArkProofError) -> CryptoError {
        CryptoError::ArkBulletproofs(e)
    }
}

impl From<AlgebraError> for CryptoError {
    fn from(e: AlgebraError) -> CryptoError {
        CryptoError::Algebra(e)
    }
}
