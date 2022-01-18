use crate::anon_xfr::circuits::{
    build_eq_committed_vals_cs, build_multi_xfr_cs, AMultiXfrPubInputs, AMultiXfrWitness,
};
use crate::setup::{NodeParams, UserParams};
use algebra::bls12_381::BLSScalar;
use algebra::groups::Scalar;
use algebra::ristretto::RistrettoScalar;
use crypto::field_simulation::{SimFr, NUM_OF_LIMBS};
use crypto::pc_eq_rescue_split_verifier_zk_part::{NonZKState, ZKPartProof};
use merlin::Transcript;
use num_bigint::BigUint;
use poly_iops::commitments::kzg_poly_com::KZGCommitmentSchemeBLS;
use poly_iops::plonk::protocol::prover::{prover, verifier, PlonkPf};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;

const ANON_XFR_TRANSCRIPT: &[u8] = b"Anon Xfr";
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";
const EQ_COMM_TRANSCRIPT: &[u8] = b"Equal committed values proof";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// I generates the plonk proof for a multi-inputs/outputs anonymous transaction.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `secret_inputs` - input to generate witness of the constraint system
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    secret_inputs: AMultiXfrWitness,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(
        N_INPUTS_TRANSCRIPT,
        secret_inputs.payers_secrets.len() as u64,
    );
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        secret_inputs.payees_secrets.len() as u64,
    );

    let (mut cs, _) = build_multi_xfr_cs(secret_inputs);
    let witness = cs.get_and_clear_witness();

    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))
}

/// I verify the plonk proof for a multi-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and the constraint system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_xfr(
    params: &NodeParams,
    pub_inputs: &AMultiXfrPubInputs,
    proof: &AXfrPlonkPf,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        pub_inputs.payees_commitments.len() as u64,
    );
    let online_inputs = pub_inputs.to_vec();
    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

/// I generates the plonk proof for equality of values in a Pedersen commitment and a Rescue commitment.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `amount` - transaction amount
/// * `asset_type` - asset type
/// * `blind_pc` - blinding factor for the Pedersen commitment
/// * `blind_hash` - blinding factor for the Rescue commitment
/// * `pc_gens` - the Pedersen commitment instance
/// * Return the plonk proof if the witness is valid, return an error otherwise.
pub(crate) fn prove_eq_committed_vals<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_hash: BLSScalar,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let (mut cs, _) = build_eq_committed_vals_cs(
        amount,
        asset_type,
        blind_hash,
        proof,
        non_zk_state,
        beta,
    );
    let witness = cs.get_and_clear_witness();

    prover(
        rng,
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.prover_params,
        &witness,
    )
    .c(d!(ZeiError::AXfrProofError))
}

/// I verify the plonk proof for equality of values in a Pedersen commitment and a Rescue commitment.
/// * `params` - System parameters including KZG params and the constraint system
/// * `hash_comm` - the Rescue commitment
/// * `ped_comm` - the Pedersen commitment
/// * `proof` - the proof
/// * Returns Ok() if the verification succeeds, returns an error otherwise.
pub(crate) fn verify_eq_committed_vals(
    params: &NodeParams,
    hash_comm: BLSScalar,
    proof_zk_part: &ZKPartProof,
    proof: &AXfrPlonkPf,
    beta: &RistrettoScalar,
) -> Result<()> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let mut online_inputs = Vec::with_capacity(2 + 3 * NUM_OF_LIMBS);
    online_inputs.push(hash_comm);
    online_inputs.push(proof_zk_part.non_zk_part_state_commitment);
    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let s1_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof_zk_part.s_1.to_bytes()));
    let s2_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof_zk_part.s_2.to_bytes()));
    online_inputs.extend_from_slice(&beta_sim_fr.limbs);
    online_inputs.extend_from_slice(&s1_sim_fr.limbs);
    online_inputs.extend_from_slice(&s2_sim_fr.limbs);
    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        proof,
    )
    .c(d!(ZeiError::ZKProofVerificationError))
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::circuits::tests::new_multi_xfr_witness_for_test;
    use crate::anon_xfr::circuits::AMultiXfrPubInputs;
    use crate::anon_xfr::proofs::{prove_xfr, verify_xfr};
    use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{One, Zero};
    use rand::RngCore;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_single_asset() {
        // single asset type
        let zero = BLSScalar::zero();

        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;
        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();
        for _i in 1..3 {
            let rnd_amount = rng.next_u64();
            let amount = rnd_amount % total_input;
            inputs.push((amount, zero));
            total_input -= amount;
        }
        inputs.push((total_input, zero));

        let mut outputs: Vec<(u64, BLSScalar)> = Vec::new();
        for _i in 1..6 {
            let rnd_amount = rng.next_u64();
            let amount = rnd_amount % total_output;
            outputs.push((amount, zero));
            total_output -= amount;
        }
        outputs.push((total_output, zero));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (3, 3)

        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;

        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();

        let mut outputs: Vec<(u64, BLSScalar)> = Vec::new();

        for _i in 1..3 {
            let amount = rng.next_u64() % total_input;
            inputs.push((amount, zero));
            total_input -= amount;

            let amount_out = rng.next_u64() % total_output;
            outputs.push((amount_out, zero));
            total_output -= amount_out;
        }

        inputs.push((total_input, zero));
        outputs.push((total_output, zero));

        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_2out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (1, 2)
        let mut rng = ChaChaRng::from_entropy();
        let total_input = 50 + rng.next_u64() % 50;
        let inputs = vec![(total_input, zero)];
        let amount = rng.next_u64() % total_input;
        let outputs = vec![(amount, zero), (total_input - amount, zero)];
        test_anon_xfr_proof(inputs.to_vec(), outputs.to_vec());
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_1out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (2, 1)
        let mut rng = ChaChaRng::from_entropy();
        let total_output = 50 + rng.next_u64() % 50;
        let amount = rng.next_u64() % total_output;
        let inputs = vec![(amount, zero), (total_output - amount, zero)];
        let outputs = vec![(total_output, zero)];
        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_1out_single_asset() {
        let zero = BLSScalar::zero();
        // (n, m) = (1, 1)

        let mut rng = ChaChaRng::from_entropy();
        let amount = 50 + rng.next_u64() % 50;
        let inputs = vec![(amount, zero)];
        let outputs = vec![(amount, zero)];
        test_anon_xfr_proof(outputs, inputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_multi_asset() {
        let zero = BLSScalar::zero();
        // multiple asset types
        // (n, m) = (3, 6)
        let one = BLSScalar::one();

        let mut rng = ChaChaRng::from_entropy();
        let total_input_zero = 50 + rng.next_u64() % 50;
        let amount_zero = rng.next_u64() % total_input_zero;
        let total_input_one = 50 + rng.next_u64() % 50;

        let mut total_output_zero = total_input_zero;
        let mut total_output_one = total_input_one;

        let inputs = vec![
            (/*amount=*/ amount_zero, /*asset_type=*/ zero),
            (total_input_one, one),
            (total_input_zero - amount_zero, zero),
        ];

        let mut outputs: Vec<(u64, BLSScalar)> = Vec::new();

        for _i in 1..3 {
            let amount_one = rng.next_u64() % total_output_one;
            let amount_zero = rng.next_u64() % total_output_zero;
            outputs.push((amount_one, one));
            outputs.push((amount_zero, zero));
            total_output_one -= amount_one;
            total_output_zero -= amount_zero;
        }
        outputs.push((total_output_one, one));
        outputs.push((total_output_zero, zero));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_multi_asset() {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        // (n, m) = (3, 3)

        let mut rng = ChaChaRng::from_entropy();

        let total_input_zero = 50 + rng.next_u64() % 50;
        let amount_zero = rng.next_u64() % total_input_zero;
        let total_input_one = 50 + rng.next_u64() % 50;
        let amount_one = rng.next_u64() % total_input_one;

        let inputs = vec![
            (amount_zero, zero),
            (total_input_one, one),
            (total_input_zero - amount_zero, zero),
        ];

        let outputs = vec![
            (amount_one, one),
            (total_input_zero, zero),
            (total_input_one - amount_one, one),
        ];

        test_anon_xfr_proof(outputs, inputs);
    }

    fn test_anon_xfr_proof(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar)>,
    ) {
        let n_payers = inputs.len();
        let n_payees = outputs.len();

        // build cs
        let secret_inputs =
            new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
        let params = UserParams::from_file_if_exists(
            n_payers,
            n_payees,
            Some(1),
            DEFAULT_BP_NUM_GENS,
            None,
        )
        .unwrap();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let proof = prove_xfr(&mut prng, &params, secret_inputs).unwrap();

        // A bad proof should fail the verification
        let bad_secret_inputs =
            new_multi_xfr_witness_for_test(inputs, outputs, [1u8; 32]);
        let bad_proof = prove_xfr(&mut prng, &params, bad_secret_inputs).unwrap();

        // verify good witness
        let node_params = NodeParams::from(params);
        assert!(verify_xfr(&node_params, &pub_inputs, &proof).is_ok());

        // verify bad witness
        assert!(verify_xfr(&node_params, &pub_inputs, &bad_proof).is_err());
    }
}
