// The Public Setup needed for Proofs
use crate::anon_xfr::circuits::{
    build_eq_committed_vals_cs, build_multi_xfr_cs, AMultiXfrWitness, PayeeSecret,
    PayerSecret, TurboPlonkCS, TREE_DEPTH,
};
use algebra::bls12_381::BLSScalar;

use crate::anon_xfr::abar_to_bar::build_abar_to_bar_cs;
use crate::anon_xfr::anon_fee::build_anon_fee_cs;
use crate::anon_xfr::config::{FEE_CALCULATING_FUNC, FEE_TYPE};
use crate::anon_xfr::parameters::{RISTRETTO_SRS, SRS};
use crate::anon_xfr::structs::{MTNode, MTPath};
use algebra::groups::Zero;
use algebra::jubjub::JubjubScalar;
use algebra::ristretto::RistrettoScalar;
use bulletproofs::BulletproofGens;
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use crypto::pc_eq_rescue_split_verifier_zk_part::{NonZKState, ZKPartProof};
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::plonk_setup::{preprocess_prover, ProverParams, VerifierParams};
use ruc::*;
use serde::Deserialize;
use utils::errors::ZeiError;

// Shared by all members of the ledger
#[derive(Serialize, Deserialize)]
pub struct PublicParams {
    pub bp_gens: BulletproofGens,
    pub bp_circuit_gens: BulletproofGens,
    pub pc_gens: RistrettoPedersenGens,
    pub range_proof_bits: usize,
}

#[derive(Serialize, Deserialize)]
pub struct UserParams {
    pub bp_params: PublicParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub cs: TurboPlonkCS,
    pub prover_params: ProverParams<KZGCommitmentSchemeBLS>,
}

pub struct NodeParams {
    pub bp_params: PublicParams,
    pub pcs: KZGCommitmentSchemeBLS,
    pub cs: TurboPlonkCS,
    pub verifier_params: VerifierParams<KZGCommitmentSchemeBLS>,
}

pub const BULLET_PROOF_RANGE: usize = 32;
pub const MAX_PARTY_NUMBER: usize = 128;
const COMMON_SEED: [u8; 32] = [0u8; 32];

impl PublicParams {
    pub fn new() -> PublicParams {
        let pp: PublicParams = bincode::deserialize(&RISTRETTO_SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();
        pp
    }

    /// Has no effect if new_size.next_power_of_two() is less or equal than current capacity
    pub fn increase_circuit_gens(&mut self, new_size: usize) {
        self.bp_circuit_gens
            .increase_capacity(new_size.next_power_of_two());
    }
}

impl Default for PublicParams {
    fn default() -> Self {
        PublicParams::new()
    }
}

impl UserParams {
    pub fn new(
        n_payers: usize,
        n_payees: usize,
        tree_depth: Option<usize>,
    ) -> UserParams {
        let (cs, _) = match tree_depth {
            Some(depth) => build_multi_xfr_cs(
                AMultiXfrWitness::fake(n_payers, n_payees, depth),
                FEE_TYPE.as_scalar(),
                &FEE_CALCULATING_FUNC,
            ),
            None => build_multi_xfr_cs(
                AMultiXfrWitness::fake(n_payers, n_payees, TREE_DEPTH),
                FEE_TYPE.as_scalar(),
                &FEE_CALCULATING_FUNC,
            ),
        };

        let pcs: KZGCommitmentSchemeBLS = bincode::deserialize(&SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();
        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();

        UserParams {
            bp_params: PublicParams::new(),
            pcs,
            cs,
            prover_params,
        }
    }

    pub fn eq_committed_vals_params() -> UserParams {
        let zero = BLSScalar::zero();
        let proof = ZKPartProof::default();
        let non_zk_state = NonZKState::default();
        let beta = RistrettoScalar::zero();
        let (cs, _) =
            build_eq_committed_vals_cs(zero, zero, zero, &proof, &non_zk_state, &beta);

        let pcs: KZGCommitmentSchemeBLS = bincode::deserialize(&SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();
        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(),
            pcs,
            cs,
            prover_params,
        }
    }

    pub fn abar_to_bar_params(tree_depth: usize) -> UserParams {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();

        let proof = ZKPartProof::default();
        let non_zk_state = NonZKState::default();
        let beta = RistrettoScalar::zero();

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            diversifier: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };

        let (cs, _) = build_abar_to_bar_cs(payer_secret, &proof, &non_zk_state, &beta);
        let pcs: KZGCommitmentSchemeBLS = bincode::deserialize(&SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();

        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(),
            pcs,
            cs,
            prover_params,
        }
    }

    pub fn anon_fee_params(tree_depth: usize) -> UserParams {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();

        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            diversifier: jubjub_zero,
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
        };
        let (cs, _) =
            build_anon_fee_cs(payer_secret, payee_secret, FEE_TYPE.as_scalar());

        let pcs: KZGCommitmentSchemeBLS = bincode::deserialize(&SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();

        let prover_params = preprocess_prover(&cs, &pcs, COMMON_SEED).unwrap();
        UserParams {
            bp_params: PublicParams::new(),
            pcs,
            cs,
            prover_params,
        }
    }
}

impl NodeParams {
    pub fn new(
        tree_depth: Option<usize>,
        n_payers: usize,
        n_payees: usize,
    ) -> Result<NodeParams> {
        let user_params = UserParams::new(n_payers, n_payees, tree_depth);
        Ok(Self::from(user_params))
    }
}

impl From<UserParams> for NodeParams {
    fn from(params: UserParams) -> Self {
        NodeParams {
            bp_params: params.bp_params,
            pcs: params.pcs,
            cs: params.cs,
            verifier_params: params.prover_params.get_verifier_params(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::parameters::SRS;
    use crate::setup::UserParams;
    use algebra::bls12_381::{BLSScalar, BLSG1};
    use algebra::groups::{Group, GroupArithmetic, One, ScalarArithmetic};
    use itertools::Itertools;
    use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
    use poly_iops::commitments::pcs::PolyComScheme;
    use poly_iops::polynomials::field_polynomial::FpPolynomial;
    use ruc::RucResult;
    use utils::errors::ZeiError;

    #[test]
    fn test_params_serialization() {
        let params = UserParams::new(1, 1, Some(1));

        let v = bincode::serialize(&params).unwrap();
        let params_de: UserParams = bincode::deserialize(&v).unwrap();
        let v2 = bincode::serialize(&params_de).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn test_crs_commit() {
        let pcs: KZGCommitmentSchemeBLS = bincode::deserialize(&SRS)
            .c(d!(ZeiError::DeserializationError))
            .unwrap();
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
