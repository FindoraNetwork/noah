// The Public Setup needed for Proofs
use crate::anon_xfr::abar_to_abar::{build_multi_xfr_cs, AXfrWitness};
use crate::anon_xfr::address_folding::AXfrAddressFoldingWitness;
use crate::anon_xfr::keys::AXfrKeyPair;
use crate::anon_xfr::structs::{PayeeWitness, PayerWitness};
use crate::anon_xfr::{
    abar_to_ar::build_abar_to_ar_cs,
    abar_to_bar::build_abar_to_bar_cs,
    ar_to_abar::build_ar_to_abar_cs,
    bar_to_abar::build_bar_to_abar_cs,
    structs::{MTNode, MTPath},
    TurboPlonkCS, FEE_TYPE, TREE_DEPTH,
};
use crate::parameters::{
    ABAR_TO_AR_VERIFIER_PARAMS, ABAR_TO_BAR_VERIFIER_PARAMS, AR_TO_ABAR_VERIFIER_PARAMS,
    BAR_TO_ABAR_VERIFIER_PARAMS, BULLETPROOF_URS, LAGRANGE_BASES, SRS, VERIFIER_COMMON_PARAMS,
    VERIFIER_SPECIFIC_PARAMS,
};
use bulletproofs::BulletproofGens;
use noah_algebra::ristretto::RistrettoPoint;
use noah_algebra::{
    bls12_381::{BLSScalar, BLSG1},
    prelude::*,
    ristretto::RistrettoScalar,
};
use noah_crypto::delegated_schnorr::{DelegatedSchnorrInspection, DelegatedSchnorrProof};
use noah_crypto::field_simulation::SimFrParamsRistretto;
use noah_plonk::{
    plonk::{
        constraint_system::ConstraintSystem,
        indexer::{indexer_with_lagrange, PlonkPK, PlonkVK},
    },
    poly_commit::{kzg_poly_com::KZGCommitmentSchemeBLS, pcs::PolyComScheme},
};
use rand_chacha::ChaChaRng;
use serde::Deserialize;

/// The Bulletproofs URS.
#[derive(Serialize, Deserialize)]
pub struct BulletproofParams {
    /// The Bulletproofs generators.
    pub bp_gens: BulletproofGens,
    /// The Bulletproofs circuit generators.
    pub bp_circuit_gens: BulletproofGens,
    /// The number of bits in the range proof.
    pub range_proof_bits: usize,
}

#[derive(Serialize, Deserialize)]
/// The prover parameters.
pub struct ProverParams {
    /// The full SRS for the polynomial commitment scheme.
    pub pcs: KZGCommitmentSchemeBLS,
    /// The Lagrange basis format of SRS.
    pub lagrange_pcs: Option<KZGCommitmentSchemeBLS>,
    /// The constraint system.
    pub cs: TurboPlonkCS,
    /// The TurboPlonk proving key.
    pub prover_params: PlonkPK<KZGCommitmentSchemeBLS>,
}

#[derive(Serialize, Deserialize)]
/// The verifier parameters.
pub struct VerifierParams {
    /// The shrunk version of the polynomial commitment scheme.
    pub pcs: KZGCommitmentSchemeBLS,
    /// The shrunk version of the constraint system.
    pub cs: TurboPlonkCS,
    /// The TurboPlonk verifying key.
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

#[derive(Serialize, Deserialize)]
/// The common part of the verifier parameters.
pub struct VerifierParamsSplitCommon {
    /// The shrunk version of the polynomial commitment scheme.
    pub pcs: KZGCommitmentSchemeBLS,
}

#[derive(Serialize, Deserialize)]
/// The specific part of the verifier parameters.
pub struct VerifierParamsSplitSpecific {
    /// The shrunk version of the constraint system.
    pub cs: TurboPlonkCS,
    /// The verifier parameters.
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

/// The range in the Bulletproofs range check.
pub const BULLET_PROOF_RANGE: usize = 32;
/// The maximal number
pub const MAX_CONFIDENTIAL_RECORD_NUMBER: usize = 128;
/// The maximal number of inputs and outputs supported by this setup program.
pub const MAX_ANONYMOUS_RECORD_NUMBER: usize = 6;
/// The default number of Bulletproofs generators
pub const DEFAULT_BP_NUM_GENS: usize = 256;

impl BulletproofParams {
    /// Load the URS for Bulletproofs.
    pub fn new() -> Result<BulletproofParams> {
        let urs = BULLETPROOF_URS.c(d!(NoahError::MissingSRSError))?;

        let pp: BulletproofParams = bincode::deserialize(&urs)
            .c(d!(NoahError::DeserializationError))
            .unwrap();
        Ok(pp)
    }

    /// Increase the Bulletproofs URS on demand.
    pub fn increase_circuit_gens(&mut self, new_size: usize) {
        self.bp_circuit_gens
            .increase_capacity(new_size.next_power_of_two());
    }
}

impl Default for BulletproofParams {
    fn default() -> Self {
        let range_generators =
            BulletproofGens::new(BULLET_PROOF_RANGE, MAX_CONFIDENTIAL_RECORD_NUMBER);
        let circuit_generators = BulletproofGens::new(DEFAULT_BP_NUM_GENS, 1);

        BulletproofParams {
            bp_gens: range_generators,
            bp_circuit_gens: circuit_generators,
            range_proof_bits: BULLET_PROOF_RANGE,
        }
    }
}

impl ProverParams {
    /// Obtain the parameters for anonymous transfer for a given number of inputs and a given number of outputs.
    pub fn new(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
    ) -> Result<ProverParams> {
        let srs = SRS.c(d!(NoahError::MissingSRSError))?;

        let folding_witness = AXfrAddressFoldingWitness::default();

        let (cs, _) = match tree_depth {
            Some(depth) => build_multi_xfr_cs(
                AXfrWitness::fake(n_payers, n_payees, depth, 0),
                FEE_TYPE.as_scalar(),
                &folding_witness,
            ),
            None => build_multi_xfr_cs(
                AXfrWitness::fake(n_payers, n_payees, TREE_DEPTH, 0),
                FEE_TYPE.as_scalar(),
                &folding_witness,
            ),
        };

        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(NoahError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params = indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref()).unwrap();

        Ok(ProverParams {
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for confidential to anonymous.
    pub fn bar_to_abar_params() -> Result<ProverParams> {
        let srs = SRS.c(d!(NoahError::MissingSRSError))?;
        let zero = BLSScalar::zero();

        let proof = DelegatedSchnorrProof::<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto> {
            inspection_comm: Default::default(),
            randomizers: vec![RistrettoPoint::default(); 3],
            response_scalars: vec![(RistrettoScalar::default(), RistrettoScalar::default()); 3],
            params_phantom: Default::default(),
        };

        let non_zk_state =
            DelegatedSchnorrInspection::<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto> {
                committed_data_and_randomizer: vec![
                    (
                        RistrettoScalar::default(),
                        RistrettoScalar::default()
                    );
                    3
                ],
                r: BLSScalar::default(),
                params_phantom: Default::default(),
                group_phantom: Default::default(),
            };

        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);

        let (cs, _) = build_bar_to_abar_cs(
            zero,
            zero,
            zero,
            &keypair.get_public_key(),
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
        );

        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(NoahError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params = indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref()).unwrap();

        Ok(ProverParams {
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for anonymous to confidential.
    pub fn abar_to_bar_params(tree_depth: usize) -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();

        let proof = DelegatedSchnorrProof::<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto> {
            inspection_comm: Default::default(),
            randomizers: vec![RistrettoPoint::default(); 3],
            response_scalars: vec![(RistrettoScalar::default(), RistrettoScalar::default()); 3],
            params_phantom: Default::default(),
        };

        let non_zk_state =
            DelegatedSchnorrInspection::<RistrettoScalar, RistrettoPoint, SimFrParamsRistretto> {
                committed_data_and_randomizer: vec![
                    (
                        RistrettoScalar::default(),
                        RistrettoScalar::default()
                    );
                    3
                ],
                r: BLSScalar::default(),
                params_phantom: Default::default(),
                group_phantom: Default::default(),
            };

        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerWitness {
            secret_key: keypair.get_secret_key(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let folding_witness = AXfrAddressFoldingWitness::default();

        let (cs, _) = build_abar_to_bar_cs(
            payer_secret,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
            &folding_witness,
        );
        let srs = SRS.c(d!(NoahError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(NoahError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params = indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref()).unwrap();

        Ok(ProverParams {
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for transparent to anonymous.
    pub fn ar_to_abar_params() -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);
        let dummy_payee = PayeeWitness {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            public_key: keypair.get_public_key(),
        };

        let (cs, _) = build_ar_to_abar_cs(dummy_payee);

        let srs = SRS.c(d!(NoahError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(NoahError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params = indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref()).unwrap();

        Ok(ProverParams {
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    /// Obtain the parameters for anonymous to transparent.
    pub fn abar_to_ar_params(tree_depth: usize) -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();

        // It's okay to choose a fixed seed to build CS.
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerWitness {
            secret_key: keypair.get_secret_key(),
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let folding_witness = AXfrAddressFoldingWitness::default();

        let (cs, _) = build_abar_to_ar_cs(payer_secret, &folding_witness);

        let srs = SRS.c(d!(NoahError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(NoahError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params = indexer_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref()).unwrap();

        Ok(ProverParams {
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }
}

fn load_lagrange_params(size: usize) -> Option<KZGCommitmentSchemeBLS> {
    match LAGRANGE_BASES.get(&size) {
        None => None,
        Some(bytes) => {
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&bytes[0..4]);
            let len = u32::from_le_bytes(len_bytes) as usize;

            let n = BLSG1::unchecked_size();

            let mut v = vec![];
            for i in 0..len {
                v.push(BLSG1::from_unchecked_bytes(&bytes[(4 + n * i)..(4 + n * (i + 1))]).ok()?);
            }

            Some(KZGCommitmentSchemeBLS {
                public_parameter_group_1: v,
                public_parameter_group_2: vec![],
            })
        }
    }
}

impl VerifierParams {
    /// Create the verifier parameters for a given number of inputs and a given number of outputs.
    pub fn create(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
    ) -> Result<VerifierParams> {
        let prover_params = ProverParams::new(n_payers, n_payees, tree_depth)?;
        Ok(Self::from(prover_params))
    }

    /// Load the verifier parameters for a given number of inputs and a given number of outputs.
    pub fn load(n_payers: usize, n_payees: usize) -> Result<VerifierParams> {
        if n_payees > MAX_ANONYMOUS_RECORD_NUMBER || n_payers > MAX_ANONYMOUS_RECORD_NUMBER {
            Err(SimpleError::new(d!(NoahError::MissingVerifierParamsError), None).into())
        } else {
            match (VERIFIER_COMMON_PARAMS, VERIFIER_SPECIFIC_PARAMS) {
                (Some(c_bytes), Some(s_bytes)) => {
                    let common: VerifierParamsSplitCommon =
                        bincode::deserialize(c_bytes).c(d!(NoahError::DeserializationError))?;
                    let specials: Vec<Vec<Vec<u8>>> = bincode::deserialize(s_bytes).unwrap();
                    let special: VerifierParamsSplitSpecific =
                        bincode::deserialize(&specials[n_payers - 1][n_payees - 1])
                            .c(d!(NoahError::DeserializationError))?;
                    Ok(VerifierParams {
                        pcs: common.pcs,
                        cs: special.cs,
                        verifier_params: special.verifier_params,
                    })
                }
                _ => Self::create(n_payers, n_payees, None),
            }
        }
    }

    /// Obtain the parameters for anonymous to confidential.
    pub fn abar_to_bar_params() -> Result<VerifierParams> {
        if let Some(bytes) = ABAR_TO_BAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(NoahError::DeserializationError))
        } else {
            let prover_params = ProverParams::abar_to_bar_params(TREE_DEPTH)?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// Obtain the parameters for confidential to anonymous.
    pub fn bar_to_abar_params() -> Result<VerifierParams> {
        if let Some(bytes) = BAR_TO_ABAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(NoahError::DeserializationError))
        } else {
            let prover_params = ProverParams::bar_to_abar_params()?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// Obtain the parameters for transparent to anonymous.
    pub fn ar_to_abar_params() -> Result<VerifierParams> {
        if let Some(bytes) = AR_TO_ABAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(NoahError::DeserializationError))
        } else {
            let prover_params = ProverParams::ar_to_abar_params()?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// Obtain the parameters for anonymous to transparent.
    pub fn abar_to_ar_params() -> Result<VerifierParams> {
        if let Some(bytes) = ABAR_TO_AR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(NoahError::DeserializationError))
        } else {
            let prover_params = ProverParams::abar_to_ar_params(TREE_DEPTH)?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// Shrink the verifier parameters.
    pub fn shrink(self) -> Result<VerifierParams> {
        Ok(VerifierParams {
            pcs: self.pcs.shrink_to_verifier_only()?,
            cs: self.cs.shrink_to_verifier_only()?,
            verifier_params: self.verifier_params,
        })
    }

    /// Split the verifier parameters to the common part and the sspecific part.
    pub fn split(self) -> Result<(VerifierParamsSplitCommon, VerifierParamsSplitSpecific)> {
        Ok((
            VerifierParamsSplitCommon {
                pcs: self.pcs.shrink_to_verifier_only()?,
            },
            VerifierParamsSplitSpecific {
                cs: self.cs.shrink_to_verifier_only()?,
                verifier_params: self.verifier_params,
            },
        ))
    }
}

impl From<ProverParams> for VerifierParams {
    fn from(params: ProverParams) -> Self {
        VerifierParams {
            pcs: params.pcs,
            cs: params.cs,
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::TREE_DEPTH;
    use crate::parameters::SRS;
    use crate::setup::{ProverParams, VerifierParams};
    use noah_algebra::{
        bls12_381::{BLSScalar, BLSG1},
        prelude::*,
    };
    use noah_plonk::poly_commit::{
        field_polynomial::FpPolynomial, kzg_poly_com::KZGCommitmentSchemeBLS, pcs::PolyComScheme,
    };

    #[test]
    fn test_params_serialization() {
        let params = ProverParams::new(1, 1, Some(1)).unwrap();

        let v = bincode::serialize(&params).unwrap();
        let params_de: ProverParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_vk_params_serialization() {
        let params = VerifierParams::create(3, 3, Some(TREE_DEPTH))
            .unwrap()
            .shrink()
            .unwrap();
        let v = bincode::serialize(&params).unwrap();
        let params_de: VerifierParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_crs_commit() {
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&SRS.unwrap()).unwrap();
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
