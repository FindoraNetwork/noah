use ark_std::{error, fmt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum AlgebraError {
    ArgumentVerificationError,
    BitConversionError,
    CommitmentInputError,
    CommitmentVerificationError,
    DecompressElementError,
    DeserializationError,
    SerializationError,
    IndexError,
    ParameterError,
    InconsistentStructureError,
    SignatureError,
    GroupInversionError,
}

impl fmt::Display for AlgebraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AlgebraError::*;
        f.write_str(match self {
            ArgumentVerificationError => "Proof(argument) not valid for statement",
            BitConversionError => "Bit conversion is not valid",
            CommitmentInputError => "The number of messages to be committed is invalid",
            CommitmentVerificationError => "Commitment verification failed",
            DecompressElementError => "Could not decompress group Element",
            DeserializationError => "Could not deserialize object",
            SerializationError => "Could not serialize object",
            IndexError => "Index out of bounds",
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            InconsistentStructureError => "Zei Structure is inconsistent",
            GroupInversionError => "Group Element not invertible",
        })
    }
}

impl error::Error for AlgebraError {
    fn description(&self) -> &str {
        use AlgebraError::*;
        match self {
            ArgumentVerificationError => "Proof(argument) not valid for statement",
            BitConversionError => "Bit conversion is not valid",
            CommitmentInputError => "The number of messages to be committed is invalid",
            CommitmentVerificationError => "Commitment verification failed",
            DecompressElementError => "Could not decompress group Element",
            DeserializationError => "Could not deserialize object",
            SerializationError => "Could not serialize object",
            IndexError => "Index out of bounds",
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            InconsistentStructureError => "Zei Structure is inconsistent",
            GroupInversionError => "Group Element not invertible",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum ZeiError {
    AXfrProverParamsError,
    AXfrVerifierParamsError,
    AXfrVerificationError,
    AXfrProofError,
    AnonFeeProofError,
    ArgumentVerificationError,
    CommitmentInputError,
    CommitmentVerificationError,
    DecompressElementError,
    RangeProofProveError,
    RangeProofVerifyError,
    DeserializationError,
    SerializationError,
    DecryptionError,
    IndexError,
    ParameterError,
    InconsistentStructureError,
    SignatureError,
    XfrVerifyAssetAmountError,
    XfrVerifyConfidentialAssetError,
    XfrCreationAssetAmountError,
    XfrVerifyAssetTracingAssetAmountError,
    XfrVerifyAssetTracingIdentityError,
    XfrVerifyAssetTracingEmptyProofError,
    XfrVerifyConfidentialAmountError,
    ElGamalVerificationError,
    ElGamalDecryptionError,
    IdentityRevealVerifyError,
    AssetMixerVerificationError,
    XfrNotSupported,
    MerkleTreeVerificationError,
    WhitelistVerificationError,
    WhitelistProveError,
    SolvencyInputError,
    SolvencyProveError,
    SolvencyVerificationError,
    ZKProofVerificationError,
    ZKProofBatchVerificationError,
    GroupSignatureTraceError,
    AssetTracingExtractionError,
    IdentityTracingExtractionError,
    AnonymousCredentialSignError,
    R1CSProofError,
    NoMemoInAssetTracerMemo,
    BogusAssetTracerMemo,
    MissingURSError,
    MissingSRSError,
    MissingVerifierParamsError,
    AbarToBarParamsError,
}

impl fmt::Display for ZeiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ZeiError::*;
        f.write_str(match self {
            AXfrProverParamsError => "Could not preprocess anonymous transfer prover",
            AXfrVerifierParamsError => "Could not preprocess anonymous transfer verifier",
            AXfrVerificationError => "Invalid AXfrBody for merkle root",
            AXfrProofError => "Could not create anonymous transfer proof",
            AbarToBarParamsError => "Could not preprocess Abr2Bar conversion prover",
            AnonFeeProofError => "Could not create anonymous transfer proof",
            ArgumentVerificationError => "Proof not valid for statement",
            CommitmentInputError => "The number of messages to be committed is invalid",
            CommitmentVerificationError => "Commitment verification failed",
            DecompressElementError => "Could not decompress group Element",
            RangeProofProveError => "Could not create range proof due to incorrect input or parameters",
            RangeProofVerifyError => "Range proof invalid for input commitments or parameters",
            DeserializationError => "Could not deserialize object",
            SerializationError => "Could not serialize object",
            DecryptionError => "Ciphertext failed authentication verification",
            IndexError => "Index out of bounds",
            ParameterError => "Unexpected parameter for method or function",
            SignatureError => "Signature verification failed",
            XfrVerifyAssetAmountError => "Invalid total amount per asset in non confidential asset transfer",
            XfrVerifyConfidentialAmountError => "Invalid asset type in non confidential asset transfer",
            XfrVerifyAssetTracingAssetAmountError => "Asset Tracking error. Asset commitment and asset ciphertext do not match",
            XfrVerifyAssetTracingIdentityError => "Asset Tracking error. Identity reveal proof does not hold",
            XfrVerifyAssetTracingEmptyProofError => "Asset Tracking error. Tracked assets must contain asset tracking proof",
            XfrVerifyConfidentialAssetError => "Invalid asset type in non confidential asset transfer",
            XfrCreationAssetAmountError => "Invalid total amount per asset in non confidential asset transfer",
            ElGamalVerificationError => "ElGamal Ciphertext not valid for proposed scalar message",
            ElGamalDecryptionError => "ElGamal Ciphertext could not be decrypted",
            InconsistentStructureError => "Zei Structure is inconsistent",
            IdentityRevealVerifyError => "Verification error for confidential identity reveal proof",
            AssetMixerVerificationError => "Verification error for asset mixing proof",
            XfrNotSupported => "Transaction type not supported",
            MerkleTreeVerificationError => "Invalid proof for merkle tree inclusion",
            WhitelistVerificationError => "Invalid proof for whitelist inclusion",
            WhitelistProveError => "Cannot build proof for whitelist",
            SolvencyVerificationError => "Invalid proof for solvency",
            SolvencyProveError => "Cannot build proof of solvency",
            SolvencyInputError => "Invalid input for solvency",
            ZKProofVerificationError => "Invalid proof",
            ZKProofBatchVerificationError => "Batch proof instance contains an error",
            GroupSignatureTraceError => "Trace test did not match",
            AssetTracingExtractionError => "Cannot extract correct data from tracing ciphertext",
            IdentityTracingExtractionError => "Cannot extract identity attributes from tracing ciphertext",
            AnonymousCredentialSignError => "The number of attributes passed as parameter differs from the number of attributes of the AC issuer public key",
            R1CSProofError =>  "Could not create R1CSProof",
            NoMemoInAssetTracerMemo => "Cannot decrypt asset tracer memo, try brute force decoding",
            BogusAssetTracerMemo => "AssetTracerMemo decryption yields inconsistent data, try brute force decoding",
            MissingURSError => "The Zei library is compiled without URS. Such parameters must be created first",
            MissingSRSError => "The Zei library is compiled without SRS, which prevents proof generation",
            MissingVerifierParamsError => "The program is loading verifier parameters that are not hardcoded. Such parameters must be created first",
        })
    }
}

impl error::Error for ZeiError {}
