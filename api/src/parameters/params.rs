use crate::anon_xfr::abar_to_abar::{build_multi_xfr_cs, AXfrWitness};
use crate::anon_xfr::abar_to_ar::build_abar_to_ar_cs;
use crate::anon_xfr::abar_to_bar::build_abar_to_bar_cs;
use crate::anon_xfr::ar_to_abar::build_ar_to_abar_cs;
use crate::anon_xfr::bar_to_abar::build_bar_to_abar_cs;
use crate::anon_xfr::structs::{MTNode, MTPath, PayeeWitness, PayerWitness};
use crate::anon_xfr::{
    commit, nullify, AXfrAddressFoldingWitness, TurboPlonkCS, FEE_TYPE, TREE_DEPTH,
};
use crate::errors::{NoahError, Result};
use crate::keys::KeyPair;
use crate::parameters::AddressFormat::{ED25519, SECP256K1};
use crate::parameters::{
    ABAR_TO_ABAR_VERIFIER_COMMON_PARAMS, ABAR_TO_ABAR_VERIFIER_ED25519_SPECIFIC_PARAMS,
    ABAR_TO_ABAR_VERIFIER_SECP256K1_SPECIFIC_PARAMS, ABAR_TO_AR_ED25519_VERIFIER_PARAMS,
    ABAR_TO_AR_SECP256K1_VERIFIER_PARAMS, ABAR_TO_BAR_ED25519_VERIFIER_PARAMS,
    ABAR_TO_BAR_SECP256K1_VERIFIER_PARAMS, AR_TO_ABAR_VERIFIER_PARAMS, BAR_TO_ABAR_VERIFIER_PARAMS,
    LAGRANGE_BASES, SRS,
};
use ark_std::{collections::BTreeMap, format};
use noah_algebra::bls12_381::{BLSScalar, BLSG1};
use noah_algebra::bn254::BN254G1;
use noah_algebra::prelude::*;
use noah_algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use noah_crypto::delegated_schnorr::{DSInspectionBLSRistretto, DSProofBLSRistretto};
use noah_plonk::plonk::constraint_system::ConstraintSystem;
use noah_plonk::plonk::indexer::{indexer_with_lagrange, PlonkPK, PlonkVK};
use noah_plonk::poly_commit::kzg_poly_com::{KZGCommitmentSchemeBLS, KZGCommitmentSchemeBN254};
use noah_plonk::poly_commit::pcs::PolyComScheme;
use num_traits::Zero;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use super::{BN254_LAGRANGE_BASES, BN254_SRS};

/// The range in the Bulletproofs range check.
pub const BULLET_PROOF_RANGE: usize = 32;
/// The maximal number
pub const MAX_CONFIDENTIAL_RECORD_NUMBER: usize = 128;
/// The maximal number of inputs and outputs supported by this setup program, for standard payments.
pub const MAX_ANONYMOUS_RECORD_NUMBER_STANDARD: usize = 6;
/// The maximal number of inputs supported by this setup program, for consolidation.
pub const MAX_ANONYMOUS_RECORD_NUMBER_CONSOLIDATION_SENDER: usize = 7;
/// The maximal number of outputs supported by this setup program, for consolidation.
pub const MAX_ANONYMOUS_RECORD_NUMBER_CONSOLIDATION_RECEIVER: usize = 3;
/// The maximal number of outputs supported by this setup program, for airport.
pub const MAX_ANONYMOUS_RECORD_NUMBER_ONE_INPUT: usize = 20;
/// The default number of Bulletproofs generators
pub const DEFAULT_BP_NUM_GENS: usize = 256;
/// The number of the Bulletproofs(over the Secq256k1 curve) generators needed for anonymous transfer.
pub const ANON_XFR_BP_GENS_LEN: usize = 2048;

#[derive(Serialize, Deserialize)]
/// The verifier parameters.
pub struct VerifierParams {
    /// A label that describes the prover parameters.
    pub label: String,
    /// The shrunk version of the polynomial commitment scheme.
    pub shrunk_vk: KZGCommitmentSchemeBLS,
    /// The shrunk version of the constraint system.
    pub shrunk_cs: TurboPlonkCS,
    /// The TurboPlonk verifying key.
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

#[derive(Serialize, Deserialize)]
/// The common part of the verifier parameters.
pub struct VerifierParamsSplitCommon {
    /// The shrunk version of the polynomial commitment scheme.
    pub shrunk_pcs: KZGCommitmentSchemeBLS,
}

#[derive(Serialize, Deserialize)]
/// The specific part of the verifier parameters.
pub struct VerifierParamsSplitSpecific {
    /// A label that describes the prover parameters.
    pub label: String,
    /// The shrunk version of the constraint system.
    pub shrunk_cs: TurboPlonkCS,
    /// The verifier parameters.
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

/// The address format.
#[derive(Copy, Clone)]
pub enum AddressFormat {
    /// Secp256k1 address
    SECP256K1,
    /// Ed25519 address
    ED25519,
}

impl ProverParams {
    /// Obtain the parameters for anonymous transfer for a given number of inputs and a given number of outputs.
    pub fn gen_abar_to_abar(
        n_payers: usize,
        n_payees: usize,
        address_format: AddressFormat,
    ) -> Result<ProverParams> {
        let label = match address_format {
            SECP256K1 => format!("abar_to_abar_{}_to_{}_secp256k1", n_payees, n_payers),
            ED25519 => format!("abar_to_abar_{}_to_{}_ed25519", n_payees, n_payers),
        };

        let fake_witness = AXfrWitness::fake(n_payers, n_payees, 0, address_format);

        let mut nullifiers_traces = Vec::new();
        let mut input_commitments_traces = Vec::new();
        let mut output_commitments_traces = Vec::new();
        for payer_witness in fake_witness.payers_witnesses.iter() {
            let (_, trace) = nullify(
                &payer_witness.secret_key.clone().into_keypair(),
                payer_witness.amount,
                payer_witness.asset_type,
                payer_witness.uid,
            )?;
            nullifiers_traces.push(trace);

            let (_, trace) = commit(
                &payer_witness.secret_key.clone().into_keypair().get_pk(),
                payer_witness.blind,
                payer_witness.amount,
                payer_witness.asset_type,
            )?;
            input_commitments_traces.push(trace);
        }

        for payee_witness in fake_witness.payees_witnesses.iter() {
            let (_, trace) = commit(
                &payee_witness.public_key,
                payee_witness.blind,
                payee_witness.amount,
                payee_witness.asset_type,
            )?;
            output_commitments_traces.push(trace);
        }

        let (cs, _) = build_multi_xfr_cs(
            &fake_witness,
            FEE_TYPE.as_scalar(),
            &nullifiers_traces,
            &input_commitments_traces,
            &output_commitments_traces,
            &AXfrAddressFoldingWitness::default(address_format),
        );

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params =
            if let Ok(v) = VerifierParams::load_abar_to_abar(n_payers, n_payees, address_format) {
                Some(v.verifier_params)
            } else {
                None
            };

        let prover_params =
            indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

        Ok(ProverParams {
            label,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for confidential to anonymous.
    pub fn gen_bar_to_abar() -> Result<ProverParams> {
        let label = String::from("bar_to_abar");
        let zero = BLSScalar::zero();

        let proof = DSProofBLSRistretto {
            inspection_comm: Default::default(),
            randomizers: vec![RistrettoPoint::default(); 3],
            response_scalars: vec![(RistrettoScalar::default(), RistrettoScalar::default()); 3],
        };

        let non_zk_state = DSInspectionBLSRistretto {
            committed_data_and_randomizer: vec![
                (
                    RistrettoScalar::default(),
                    RistrettoScalar::default()
                );
                3
            ],
            r: BLSScalar::default(),
            group_phantom: Default::default(),
        };

        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        // It's okay to choose a fixed pk to build CS.
        let keypair = KeyPair::sample(&mut prng, SECP256K1);
        let (_, output_commitment_trace) = commit(&keypair.get_pk(), zero, 0, zero)?;

        let (cs, _) = build_bar_to_abar_cs(
            zero,
            zero,
            zero,
            &keypair.get_pk(),
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
            &output_commitment_trace,
        );

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params = if let Ok(vk) = VerifierParams::load_bar_to_abar() {
            Some(vk.verifier_params)
        } else {
            None
        };

        let prover_params =
            indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

        Ok(ProverParams {
            label,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for anonymous to confidential.
    pub fn gen_abar_to_bar(address_format: AddressFormat) -> Result<ProverParams> {
        let label = match address_format {
            SECP256K1 => String::from("abar_to_bar_secp256k1"),
            ED25519 => String::from("abar_to_bar_ed25519"),
        };

        let bls_zero = BLSScalar::zero();

        let proof = DSProofBLSRistretto {
            inspection_comm: Default::default(),
            randomizers: vec![RistrettoPoint::default(); 3],
            response_scalars: vec![(RistrettoScalar::default(), RistrettoScalar::default()); 3],
        };

        let non_zk_state = DSInspectionBLSRistretto {
            committed_data_and_randomizer: vec![
                (
                    RistrettoScalar::default(),
                    RistrettoScalar::default()
                );
                3
            ],
            r: BLSScalar::default(),
            group_phantom: Default::default(),
        };

        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let node = MTNode {
            left: bls_zero,
            mid: bls_zero,
            right: bls_zero,
            is_left_child: 0,
            is_mid_child: 0,
            is_right_child: 0,
        };

        let keypair = KeyPair::sample(&mut prng, address_format);
        let payer_secret = PayerWitness {
            secret_key: keypair.get_sk(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node.clone(); TREE_DEPTH]),
            blind: bls_zero,
        };

        let (_, nullifier_trace) = nullify(
            &payer_secret.secret_key.clone().into_keypair(),
            payer_secret.amount,
            payer_secret.asset_type,
            payer_secret.uid,
        )?;

        let (_, input_commitment_trace) = commit(
            &payer_secret.secret_key.clone().into_keypair().get_pk(),
            payer_secret.blind,
            payer_secret.amount,
            payer_secret.asset_type,
        )?;

        let (cs, _) = build_abar_to_bar_cs(
            &payer_secret,
            &nullifier_trace,
            &input_commitment_trace,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
            &AXfrAddressFoldingWitness::default(address_format),
        );

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params = match VerifierParams::load_abar_to_bar(address_format).ok() {
            Some(v) => Some(v.verifier_params),
            None => None,
        };

        let prover_params =
            indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

        Ok(ProverParams {
            label,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for transparent to anonymous.
    pub fn gen_ar_to_abar() -> Result<ProverParams> {
        let label = String::from("ar_to_abar");

        let bls_zero = BLSScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        // It's okay to choose a fixed address format.
        let keypair = KeyPair::sample(&mut prng, SECP256K1);

        let dummy_payee = PayeeWitness {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            public_key: keypair.get_pk(),
        };
        let (_, input_commitment_trace) = commit(
            &dummy_payee.public_key,
            dummy_payee.blind,
            dummy_payee.amount,
            dummy_payee.asset_type,
        )?;
        let (cs, _) = build_ar_to_abar_cs(dummy_payee, &input_commitment_trace);

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params = match VerifierParams::load_ar_to_abar().ok() {
            Some(v) => Some(v.verifier_params),
            None => None,
        };

        let prover_params =
            indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

        Ok(ProverParams {
            label,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for anonymous to transparent.
    pub fn gen_abar_to_ar(address_format: AddressFormat) -> Result<ProverParams> {
        let label = match address_format {
            SECP256K1 => String::from("abar_to_ar_secp256k1"),
            ED25519 => String::from("abar_to_ar_ed25519"),
        };

        let bls_zero = BLSScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let node = MTNode {
            left: bls_zero,
            mid: bls_zero,
            right: bls_zero,
            is_left_child: 0,
            is_mid_child: 0,
            is_right_child: 0,
        };

        let keypair = KeyPair::sample(&mut prng, address_format);
        let payer_secret = PayerWitness {
            secret_key: keypair.get_sk(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node.clone(); TREE_DEPTH]),
            blind: bls_zero,
        };
        let (_, nullifier_trace) = nullify(
            &payer_secret.secret_key.clone().into_keypair(),
            payer_secret.amount,
            payer_secret.asset_type,
            payer_secret.uid,
        )?;

        let (_, input_commitment_trace) = commit(
            &payer_secret.secret_key.clone().into_keypair().get_pk(),
            payer_secret.blind,
            payer_secret.amount,
            payer_secret.asset_type,
        )?;

        let (cs, _) = build_abar_to_ar_cs(
            &payer_secret,
            &nullifier_trace,
            &input_commitment_trace,
            &AXfrAddressFoldingWitness::default(address_format),
        );

        let cs_size = cs.size();
        let pcs = load_srs_params(cs_size)?;
        let lagrange_pcs = load_lagrange_params(cs_size);

        let verifier_params = match VerifierParams::load_abar_to_ar(address_format).ok() {
            Some(v) => Some(v.verifier_params),
            None => None,
        };

        let prover_params =
            indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), verifier_params).unwrap();

        Ok(ProverParams {
            label,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }
}

impl VerifierParams {
    /// Load the verifier parameters for a given number of inputs and a given number of outputs.
    pub fn get_abar_to_abar(
        n_payers: usize,
        n_payees: usize,
        address_format: AddressFormat,
    ) -> Result<VerifierParams> {
        if (!(n_payees <= MAX_ANONYMOUS_RECORD_NUMBER_STANDARD
            && n_payers <= MAX_ANONYMOUS_RECORD_NUMBER_STANDARD))
            && (!(n_payers <= MAX_ANONYMOUS_RECORD_NUMBER_CONSOLIDATION_SENDER
                && n_payees <= MAX_ANONYMOUS_RECORD_NUMBER_CONSOLIDATION_RECEIVER))
            && (!(n_payers == 1 && n_payees <= MAX_ANONYMOUS_RECORD_NUMBER_ONE_INPUT))
        {
            Err(NoahError::MissingVerifierParamsError)
        } else {
            match Self::load_abar_to_abar(n_payers, n_payees, address_format) {
                Ok(vk) => Ok(vk),
                Err(_e) => Ok(Self::from(ProverParams::gen_abar_to_abar(
                    n_payers,
                    n_payees,
                    address_format,
                )?)),
            }
        }
    }

    /// Load the verifier parameters from prepare.
    pub fn load_abar_to_abar(
        n_payers: usize,
        n_payees: usize,
        address_format: AddressFormat,
    ) -> Result<VerifierParams> {
        let verifier_specific_params = match address_format {
            SECP256K1 => ABAR_TO_ABAR_VERIFIER_SECP256K1_SPECIFIC_PARAMS,
            ED25519 => ABAR_TO_ABAR_VERIFIER_ED25519_SPECIFIC_PARAMS,
        };

        let label = match address_format {
            SECP256K1 => format!("abar_to_abar_{}_to_{}_secp256k1", n_payees, n_payers),
            ED25519 => format!("abar_to_abar_{}_to_{}_ed25519", n_payees, n_payers),
        };

        match (
            ABAR_TO_ABAR_VERIFIER_COMMON_PARAMS,
            verifier_specific_params,
        ) {
            (Some(c_bytes), Some(s_bytes)) => {
                let common: VerifierParamsSplitCommon =
                    bincode::deserialize(c_bytes).map_err(|_| NoahError::DeserializationError)?;
                let specials: BTreeMap<(usize, usize), Vec<u8>> =
                    bincode::deserialize(s_bytes).unwrap();
                let special_bytes = specials.get(&(n_payers, n_payees));
                if special_bytes.is_none() {
                    return Err(NoahError::DeserializationError);
                }
                let special: VerifierParamsSplitSpecific =
                    bincode::deserialize(special_bytes.unwrap())
                        .map_err(|_| NoahError::DeserializationError)?;

                if special.label != label {
                    return Err(NoahError::AXfrVerifierParamsError);
                }

                Ok(VerifierParams {
                    label,
                    shrunk_vk: common.shrunk_pcs,
                    shrunk_cs: special.shrunk_cs,
                    verifier_params: special.verifier_params,
                })
            }
            _ => Err(NoahError::MissingVerifierParamsError),
        }
    }

    /// Obtain the parameters for anonymous to confidential.
    pub fn get_abar_to_bar(address_format: AddressFormat) -> Result<VerifierParams> {
        match Self::load_abar_to_bar(address_format) {
            Ok(vk) => Ok(vk),
            _ => {
                let prover_params = ProverParams::gen_abar_to_bar(address_format)?;
                Ok(VerifierParams::from(prover_params))
            }
        }
    }

    /// Obtain the parameters for anonymous to confidential from prepare.
    pub fn load_abar_to_bar(address_format: AddressFormat) -> Result<VerifierParams> {
        let bytes = match address_format {
            SECP256K1 => ABAR_TO_BAR_SECP256K1_VERIFIER_PARAMS,
            ED25519 => ABAR_TO_BAR_ED25519_VERIFIER_PARAMS,
        };

        if let Some(bytes) = bytes {
            let verifier_params = bincode::deserialize::<VerifierParams>(bytes);
            if let Ok(verifier_params) = verifier_params {
                let label = match address_format {
                    SECP256K1 => String::from("abar_to_bar_secp256k1"),
                    ED25519 => String::from("abar_to_bar_ed25519"),
                };

                if verifier_params.label != label {
                    Err(NoahError::MissingVerifierParamsError)
                } else {
                    Ok(verifier_params)
                }
            } else {
                Err(NoahError::DeserializationError)
            }
        } else {
            Err(NoahError::MissingVerifierParamsError)
        }
    }

    /// Obtain the parameters for confidential to anonymous.
    pub fn get_bar_to_abar() -> Result<VerifierParams> {
        match Self::load_bar_to_abar() {
            Ok(vk) => Ok(vk),
            _ => {
                let prover_params = ProverParams::gen_bar_to_abar()?;
                Ok(VerifierParams::from(prover_params))
            }
        }
    }

    /// Obtain the parameters for confidential to anonymous from prepare.
    pub fn load_bar_to_abar() -> Result<VerifierParams> {
        if let Some(bytes) = BAR_TO_ABAR_VERIFIER_PARAMS {
            let verifier_params = bincode::deserialize::<VerifierParams>(bytes);
            if let Ok(verifier_params) = verifier_params {
                if verifier_params.label != String::from("bar_to_abar") {
                    Err(NoahError::MissingVerifierParamsError)
                } else {
                    Ok(verifier_params)
                }
            } else {
                Err(NoahError::DeserializationError)
            }
        } else {
            Err(NoahError::MissingVerifierParamsError)
        }
    }

    /// Obtain the parameters for transparent to anonymous.
    pub fn get_ar_to_abar() -> Result<VerifierParams> {
        match Self::load_ar_to_abar() {
            Ok(vk) => Ok(vk),
            _ => {
                let prover_params = ProverParams::gen_ar_to_abar()?;
                Ok(VerifierParams::from(prover_params))
            }
        }
    }

    /// Obtain the parameters for transparent to anonymous from prepare.
    pub fn load_ar_to_abar() -> Result<VerifierParams> {
        if let Some(bytes) = AR_TO_ABAR_VERIFIER_PARAMS {
            let verifier_params = bincode::deserialize::<VerifierParams>(bytes);
            if let Ok(verifier_params) = verifier_params {
                if verifier_params.label != String::from("ar_to_abar") {
                    Err(NoahError::MissingVerifierParamsError)
                } else {
                    Ok(verifier_params)
                }
            } else {
                Err(NoahError::DeserializationError)
            }
        } else {
            Err(NoahError::MissingVerifierParamsError)
        }
    }

    /// Obtain the parameters for anonymous to transparent.
    pub fn get_abar_to_ar(address_format: AddressFormat) -> Result<VerifierParams> {
        match Self::load_abar_to_ar(address_format) {
            Ok(vk) => Ok(vk),
            _ => {
                let prover_params = ProverParams::gen_abar_to_ar(address_format)?;
                Ok(VerifierParams::from(prover_params))
            }
        }
    }

    /// Obtain the parameters for anonymous to transparent from prepare.
    pub fn load_abar_to_ar(address_format: AddressFormat) -> Result<VerifierParams> {
        let bytes = match address_format {
            SECP256K1 => ABAR_TO_AR_SECP256K1_VERIFIER_PARAMS,
            ED25519 => ABAR_TO_AR_ED25519_VERIFIER_PARAMS,
        };

        if let Some(bytes) = bytes {
            let verifier_params = bincode::deserialize::<VerifierParams>(bytes);
            if let Ok(verifier_params) = verifier_params {
                let label = match address_format {
                    SECP256K1 => String::from("abar_to_ar_secp256k1"),
                    ED25519 => String::from("abar_to_ar_ed25519"),
                };

                if verifier_params.label != label {
                    Err(NoahError::MissingVerifierParamsError)
                } else {
                    Ok(verifier_params)
                }
            } else {
                Err(NoahError::DeserializationError)
            }
        } else {
            Err(NoahError::MissingVerifierParamsError)
        }
    }

    /// Split the verifier parameters to the common part and the sspecific part.
    pub fn split(self) -> Result<(VerifierParamsSplitCommon, VerifierParamsSplitSpecific)> {
        Ok((
            VerifierParamsSplitCommon {
                shrunk_pcs: self.shrunk_vk.shrink_to_verifier_only(),
            },
            VerifierParamsSplitSpecific {
                label: self.label,
                shrunk_cs: self.shrunk_cs.shrink_to_verifier_only(),
                verifier_params: self.verifier_params,
            },
        ))
    }
}

impl From<ProverParams> for VerifierParams {
    fn from(params: ProverParams) -> Self {
        VerifierParams {
            label: params.label,
            shrunk_vk: params.pcs.shrink_to_verifier_only(),
            shrunk_cs: params.cs.shrink_to_verifier_only(),
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

#[derive(Serialize, Deserialize)]
/// The prover parameters.
pub struct ProverParams {
    /// A label that describes the prover parameters.
    pub label: String,
    /// The full SRS for the polynomial commitment scheme.
    pub pcs: KZGCommitmentSchemeBLS,
    /// The Lagrange basis format of SRS.
    pub lagrange_pcs: Option<KZGCommitmentSchemeBLS>,
    /// The constraint system.
    pub cs: TurboPlonkCS,
    /// The TurboPlonk proving key.
    pub prover_params: PlonkPK<KZGCommitmentSchemeBLS>,
}

fn load_lagrange_params(size: usize) -> Option<KZGCommitmentSchemeBLS> {
    match LAGRANGE_BASES.get(&size) {
        None => None,
        Some(bytes) => KZGCommitmentSchemeBLS::from_unchecked_bytes(&bytes).ok(),
    }
}

#[allow(unused)]
fn load_lagrange_params_bn254(size: usize) -> Option<KZGCommitmentSchemeBN254> {
    match BN254_LAGRANGE_BASES.get(&size) {
        None => None,
        Some(bytes) => KZGCommitmentSchemeBN254::from_unchecked_bytes(&bytes).ok(),
    }
}

fn load_srs_params(size: usize) -> Result<KZGCommitmentSchemeBLS> {
    let srs = SRS.ok_or(NoahError::MissingSRSError)?;

    let KZGCommitmentSchemeBLS {
        public_parameter_group_1,
        public_parameter_group_2,
    } = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)?;

    let mut new_group_1 = vec![BLSG1::default(); core::cmp::max(size + 3, 2051)];
    new_group_1[0..2051].copy_from_slice(&public_parameter_group_1[0..2051]);

    if size == 4096 {
        new_group_1[4096..4099].copy_from_slice(&public_parameter_group_1[2051..2054]);
    }

    if size == 8192 {
        new_group_1[8192..8195].copy_from_slice(&public_parameter_group_1[2054..2057]);
    }

    if size > 8192 {
        return Err(NoahError::ParameterError);
    }

    Ok(KZGCommitmentSchemeBLS {
        public_parameter_group_2,
        public_parameter_group_1: new_group_1,
    })
}

#[allow(unused)]
fn load_srs_params_bn254(size: usize) -> Result<KZGCommitmentSchemeBN254> {
    let srs = BN254_SRS.ok_or(NoahError::MissingSRSError)?;

    let KZGCommitmentSchemeBN254 {
        public_parameter_group_1,
        public_parameter_group_2,
    } = KZGCommitmentSchemeBN254::from_unchecked_bytes(&srs)?;

    let mut new_group_1 = vec![BN254G1::default(); core::cmp::max(size + 3, 2051)];
    new_group_1[0..2051].copy_from_slice(&public_parameter_group_1[0..2051]);

    if size == 4096 {
        new_group_1[4096..4099].copy_from_slice(&public_parameter_group_1[2051..2054]);
    }

    if size == 8192 {
        new_group_1[8192..8195].copy_from_slice(&public_parameter_group_1[2054..2057]);
    }

    if size > 8192 {
        return Err(NoahError::ParameterError);
    }

    Ok(KZGCommitmentSchemeBN254 {
        public_parameter_group_2,
        public_parameter_group_1: new_group_1,
    })
}

#[cfg(test)]
mod test {
    use crate::parameters::params::load_srs_params;
    use crate::parameters::params::AddressFormat::{ED25519, SECP256K1};
    use crate::parameters::params::ProverParams;
    use crate::parameters::params::VerifierParams;
    use noah_algebra::{
        bls12_381::{BLSScalar, BLSG1},
        prelude::*,
    };
    use noah_plonk::poly_commit::{field_polynomial::FpPolynomial, pcs::PolyComScheme};

    #[test]
    fn test_params_serialization() {
        let params = ProverParams::gen_abar_to_abar(1, 1, SECP256K1).unwrap();

        let v = bincode::serialize(&params).unwrap();
        let params_de: ProverParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);

        let params = ProverParams::gen_abar_to_abar(1, 1, ED25519).unwrap();

        let v = bincode::serialize(&params).unwrap();
        let params_de: ProverParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_vk_params_serialization() {
        let params = VerifierParams::get_abar_to_abar(3, 3, SECP256K1).unwrap();
        let v = bincode::serialize(&params).unwrap();
        let params_de: VerifierParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);

        let params = VerifierParams::get_abar_to_abar(3, 3, ED25519).unwrap();
        let v = bincode::serialize(&params).unwrap();
        let params_de: VerifierParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_crs_commit() {
        let pcs = load_srs_params(16).unwrap();

        let one = BLSScalar::one();
        let two = one.add(&one);
        let three = two.add(&one);
        let six = three.add(&three);

        let fq_poly = FpPolynomial::from_coefs(vec![two, three, six]);
        let commitment = pcs.commit(&fq_poly).unwrap();

        let coefs_poly_blsscalar = fq_poly.get_coefs_ref().iter().collect_vec();
        let mut expected_committed_value = BLSG1::get_identity();

        // Doing the multiexp by hand
        for (i, coef) in coefs_poly_blsscalar.iter().enumerate() {
            let g_i = pcs.public_parameter_group_1[i].clone();
            expected_committed_value = expected_committed_value.add(&g_i.mul(&coef));
        }
        assert_eq!(expected_committed_value, commitment.0);
    }
}
