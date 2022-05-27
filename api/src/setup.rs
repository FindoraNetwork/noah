// The Public Setup needed for Proofs
use crate::anon_xfr::{
    abar_to_ar::build_abar_to_ar_cs,
    abar_to_bar::build_abar_to_bar_cs,
    anon_fee::build_anon_fee_cs,
    ar_to_abar::build_ar_to_abar_cs,
    bar_to_abar::build_bar_to_abar_cs,
    circuits::{
        build_multi_xfr_cs, AMultiXfrWitness, PayeeSecret, PayerSecret, TurboPlonkCS, TREE_DEPTH,
    },
    config::{FEE_CALCULATING_FUNC, FEE_TYPE},
    structs::{MTNode, MTPath},
};
use crate::parameters::{
    ABAR_TO_AR_VERIFIER_PARAMS, ABAR_TO_BAR_VERIFIER_PARAMS, ANON_FEE_VERIFIER_PARAMS,
    AR_TO_ABAR_VERIFIER_PARAMS, BAR_TO_ABAR_VERIFIER_PARAMS, BULLETPROOF_URS, LAGRANGE_BASES, SRS,
    VERIFIER_COMMON_PARAMS, VERIFIER_SPECIALS_PARAMS,
};
use bulletproofs::BulletproofGens;
use serde::Deserialize;
use zei_algebra::{
    bls12_381::{BLSScalar, BLSG1},
    jubjub::JubjubScalar,
    prelude::*,
    ristretto::RistrettoScalar,
};
use zei_crypto::pc_eq_rescue_zk_part::{NonZKState, ZKPartProof};
use zei_plonk::{
    plonk::{
        constraint_system::ConstraintSystem,
        setup::{preprocess_prover_with_lagrange, PlonkPK, PlonkVK},
    },
    poly_commit::{kzg_poly_com::KZGCommitmentSchemeBLS, pcs::PolyComScheme},
};

// Shared by all members of the ledger
#[derive(Serialize, Deserialize)]
pub struct BulletproofParams {
    pub bp_gens: BulletproofGens,
    pub bp_circuit_gens: BulletproofGens,
    pub range_proof_bits: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ProverParams {
    pub bp_params: BulletproofParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub lagrange_pcs: Option<KZGCommitmentSchemeBLS>,
    pub cs: TurboPlonkCS,
    pub prover_params: PlonkPK<KZGCommitmentSchemeBLS>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifierParams {
    pub bp_params: BulletproofParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub cs: TurboPlonkCS,
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeParamsSplitCommon {
    pub bp_params: BulletproofParams,
    pub pcs: KZGCommitmentSchemeBLS,
}

#[derive(Serialize, Deserialize)]
pub struct NodeParamsSplitSpecial {
    pub cs: TurboPlonkCS,
    pub verifier_params: PlonkVK<KZGCommitmentSchemeBLS>,
}

pub const BULLET_PROOF_RANGE: usize = 32;
pub const MAX_PARTY_NUMBER: usize = 128;
const COMMON_SEED: [u8; 32] = [0u8; 32];
pub const PRECOMPUTED_PARTY_NUMBER: usize = 6;
pub const DEFAULT_BP_NUM_GENS: usize = 256;

impl BulletproofParams {
    pub fn new() -> Result<BulletproofParams> {
        let urs = BULLETPROOF_URS.c(d!(ZeiError::MissingSRSError))?;

        let pp: BulletproofParams = bincode::deserialize(&urs)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();
        Ok(pp)
    }

    /// Has no effect if new_size.next_power_of_two() is less or equal than current capacity
    pub fn increase_circuit_gens(&mut self, new_size: usize) {
        self.bp_circuit_gens
            .increase_capacity(new_size.next_power_of_two());
    }
}

impl Default for BulletproofParams {
    fn default() -> Self {
        let range_generators = BulletproofGens::new(BULLET_PROOF_RANGE, MAX_PARTY_NUMBER);
        let circuit_generators = BulletproofGens::new(DEFAULT_BP_NUM_GENS, 1);

        BulletproofParams {
            bp_gens: range_generators,
            bp_circuit_gens: circuit_generators,
            range_proof_bits: BULLET_PROOF_RANGE,
        }
    }
}

impl ProverParams {
    pub fn new(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
    ) -> Result<ProverParams> {
        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;

        let zero = BLSScalar::zero();

        let hash = zero;
        let non_malleability_randomizer = zero;
        let non_malleability_tag = zero;

        let (cs, _) = match tree_depth {
            Some(depth) => build_multi_xfr_cs(
                AMultiXfrWitness::fake(n_payers, n_payees, depth),
                FEE_TYPE.as_scalar(),
                &FEE_CALCULATING_FUNC,
                &hash,
                &non_malleability_randomizer,
                &non_malleability_tag,
            ),
            None => build_multi_xfr_cs(
                AMultiXfrWitness::fake(n_payers, n_payees, TREE_DEPTH),
                FEE_TYPE.as_scalar(),
                &FEE_CALCULATING_FUNC,
                &hash,
                &non_malleability_randomizer,
                &non_malleability_tag,
            ),
        };

        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    pub fn bar_to_abar_params() -> Result<ProverParams> {
        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;
        let zero = BLSScalar::zero();
        let proof = ZKPartProof::default();
        let non_zk_state = NonZKState::default();
        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();
        let (cs, _) = build_bar_to_abar_cs(
            zero,
            zero,
            zero,
            zero,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
        );

        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    pub fn abar_to_bar_params(tree_depth: usize) -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();

        let proof = ZKPartProof::default();
        let non_zk_state = NonZKState::default();
        let beta = RistrettoScalar::zero();
        let lambda = RistrettoScalar::zero();
        let hash = bls_zero;
        let non_malleability_randomizer = bls_zero;
        let non_malleability_tag = bls_zero;

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let (cs, _) = build_abar_to_bar_cs(
            payer_secret,
            &proof,
            &non_zk_state,
            &beta,
            &lambda,
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        );
        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    pub fn ar_to_abar_params() -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();
        let dummy_payee = PayeeSecret {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            pubkey_x: bls_zero,
        };

        let (cs, _) = build_ar_to_abar_cs(dummy_payee);

        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    pub fn abar_to_ar_params(tree_depth: usize) -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let hash = bls_zero;
        let non_malleability_randomizer = bls_zero;
        let non_malleability_tag = bls_zero;

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let (cs, _) = build_abar_to_ar_cs(
            payer_secret,
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        );

        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
            pcs,
            lagrange_pcs,
            cs,
            prover_params,
        })
    }

    pub fn anon_fee_params(tree_depth: usize) -> Result<ProverParams> {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let hash = bls_zero;
        let non_malleability_randomizer = bls_zero;
        let non_malleability_tag = bls_zero;

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_secret = PayeeSecret {
            amount: 0,
            blind: Default::default(),
            asset_type: Default::default(),
            pubkey_x: Default::default(),
        };
        let (cs, _) = build_anon_fee_cs(
            payer_secret,
            payee_secret,
            FEE_TYPE.as_scalar(),
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        );

        let srs = SRS.c(d!(ZeiError::MissingSRSError))?;
        let pcs = KZGCommitmentSchemeBLS::from_unchecked_bytes(&srs)
            .c(d!(ZeiError::DeserializationError))?;

        let lagrange_pcs = load_lagrange_params(cs.size());

        let prover_params =
            preprocess_prover_with_lagrange(&cs, &pcs, lagrange_pcs.as_ref(), COMMON_SEED).unwrap();

        Ok(ProverParams {
            bp_params: BulletproofParams::new()?,
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
    pub fn create(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
    ) -> Result<VerifierParams> {
        let prover_params = ProverParams::new(n_payers, n_payees, tree_depth)?;
        Ok(Self::from(prover_params))
    }

    /// anon transfer verifier parameters.
    pub fn load(n_payers: usize, n_payees: usize) -> Result<VerifierParams> {
        if n_payees > PRECOMPUTED_PARTY_NUMBER || n_payers > PRECOMPUTED_PARTY_NUMBER {
            Err(SimpleError::new(d!(ZeiError::MissingVerifierParamsError), None).into())
        } else {
            match (VERIFIER_COMMON_PARAMS, VERIFIER_SPECIALS_PARAMS) {
                (Some(c_bytes), Some(s_bytes)) => {
                    let common: NodeParamsSplitCommon =
                        bincode::deserialize(c_bytes).c(d!(ZeiError::DeserializationError))?;
                    let specials: Vec<Vec<Vec<u8>>> = bincode::deserialize(s_bytes).unwrap();
                    let special: NodeParamsSplitSpecial =
                        bincode::deserialize(&specials[n_payers - 1][n_payees - 1])
                            .c(d!(ZeiError::DeserializationError))?;
                    Ok(VerifierParams {
                        bp_params: common.bp_params,
                        pcs: common.pcs,
                        cs: special.cs,
                        verifier_params: special.verifier_params,
                    })
                }
                _ => Self::create(n_payers, n_payees, None),
            }
        }
    }

    /// abar to bar transfer verifier parameters.
    pub fn abar_to_bar_params() -> Result<VerifierParams> {
        if let Some(bytes) = ABAR_TO_BAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(ZeiError::DeserializationError))
        } else {
            let prover_params = ProverParams::abar_to_bar_params(TREE_DEPTH)?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// bar to abar transfer verifier parameters.
    pub fn bar_to_abar_params() -> Result<VerifierParams> {
        if let Some(bytes) = BAR_TO_ABAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(ZeiError::DeserializationError))
        } else {
            let prover_params = ProverParams::bar_to_abar_params()?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// ar to abar transfer verifier parameters.
    pub fn ar_to_abar_params() -> Result<VerifierParams> {
        if let Some(bytes) = AR_TO_ABAR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(ZeiError::DeserializationError))
        } else {
            let prover_params = ProverParams::ar_to_abar_params()?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// abar to ar transfer verifier parameters.
    pub fn abar_to_ar_params() -> Result<VerifierParams> {
        if let Some(bytes) = ABAR_TO_AR_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(ZeiError::DeserializationError))
        } else {
            let prover_params = ProverParams::abar_to_ar_params(TREE_DEPTH)?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    /// anon_fee verifier parameters.
    pub fn anon_fee_params() -> Result<VerifierParams> {
        if let Some(bytes) = ANON_FEE_VERIFIER_PARAMS {
            bincode::deserialize(bytes).c(d!(ZeiError::DeserializationError))
        } else {
            let prover_params = ProverParams::anon_fee_params(TREE_DEPTH)?;
            Ok(VerifierParams::from(prover_params))
        }
    }

    pub fn shrink(self) -> Result<VerifierParams> {
        Ok(VerifierParams {
            bp_params: self.bp_params,
            pcs: self.pcs.shrink_to_verifier_only()?,
            cs: self.cs.shrink_to_verifier_only()?,
            verifier_params: self.verifier_params,
        })
    }

    pub fn split(self) -> Result<(NodeParamsSplitCommon, NodeParamsSplitSpecial)> {
        Ok((
            NodeParamsSplitCommon {
                bp_params: self.bp_params,
                pcs: self.pcs.shrink_to_verifier_only()?,
            },
            NodeParamsSplitSpecial {
                cs: self.cs.shrink_to_verifier_only()?,
                verifier_params: self.verifier_params,
            },
        ))
    }
}

impl From<ProverParams> for VerifierParams {
    fn from(params: ProverParams) -> Self {
        VerifierParams {
            bp_params: params.bp_params,
            pcs: params.pcs,
            cs: params.cs,
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::circuits::TREE_DEPTH;
    use crate::parameters::SRS;
    use crate::setup::{ProverParams, VerifierParams};
    use zei_algebra::{
        bls12_381::{BLSScalar, BLSG1},
        prelude::*,
    };
    use zei_plonk::poly_commit::{
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
        let (commitment, open) = pcs.commit(fq_poly).unwrap();

        let coefs_poly_blsscalar = open.get_coefs_ref().iter().collect_vec();
        let mut expected_committed_value = BLSG1::get_identity();

        // Doing the multiexp by hand
        for (i, coef) in coefs_poly_blsscalar.iter().enumerate() {
            let g_i = pcs.public_parameter_group_1[i].clone();
            expected_committed_value = expected_committed_value.add(&g_i.mul(&coef));
        }
        assert_eq!(expected_committed_value, commitment.value);
    }
}
