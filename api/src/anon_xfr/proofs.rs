use crate::anon_xfr::{
    circuits::{
        build_eq_committed_vals_cs, build_multi_xfr_cs, AMultiXfrPubInputs, AMultiXfrWitness,
    },
    config::{FEE_CALCULATING_FUNC, FEE_TYPE},
};
use crate::setup::{ProverParams, VerifierParams};
use merlin::Transcript;
use num_bigint::BigUint;
use zei_algebra::{bls12_381::BLSScalar, prelude::*, ristretto::RistrettoScalar};
use zei_crypto::{
    field_simulation::{SimFr, NUM_OF_LIMBS},
    pc_eq_rescue_split_verifier_zk_part::{NonZKState, ZKPartProof},
};
use zei_plonk::{
    plonk::{prover::prover_with_lagrange, setup::PlonkPf, verifier::verifier},
    poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS,
};

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
    params: &ProverParams,
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

    let fee_type = FEE_TYPE.as_scalar();
    let fee_calculating_func = FEE_CALCULATING_FUNC;

    let (mut cs, _) = build_multi_xfr_cs(secret_inputs, fee_type, &fee_calculating_func);
    let witness = cs.get_and_clear_witness();

    prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
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
    params: &VerifierParams,
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
    params: &ProverParams,
    amount: BLSScalar,
    asset_type: BLSScalar,
    blind_hash: BLSScalar,
    pubkey_x: BLSScalar,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let (mut cs, _) = build_eq_committed_vals_cs(
        amount,
        asset_type,
        blind_hash,
        pubkey_x,
        proof,
        non_zk_state,
        beta,
        lambda,
    );
    let witness = cs.get_and_clear_witness();

    prover_with_lagrange(
        rng,
        &mut transcript,
        &params.pcs,
        params.lagrange_pcs.as_ref(),
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
    params: &VerifierParams,
    hash_comm: BLSScalar,
    proof_zk_part: &ZKPartProof,
    proof: &AXfrPlonkPf,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
) -> Result<()> {
    let mut transcript = Transcript::new(EQ_COMM_TRANSCRIPT);
    let mut online_inputs = Vec::with_capacity(2 + 3 * NUM_OF_LIMBS);
    online_inputs.push(hash_comm);
    online_inputs.push(proof_zk_part.non_zk_part_state_commitment);
    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 = proof_zk_part.s_1 + proof_zk_part.s_2 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    online_inputs.extend_from_slice(&beta_sim_fr.limbs);
    online_inputs.extend_from_slice(&lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&beta_lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&s1_plus_lambda_s2_sim_fr.limbs);

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
    use crate::anon_xfr::{
        circuits::{tests::new_multi_xfr_witness_for_test, AMultiXfrPubInputs},
        config::{FEE_CALCULATING_FUNC, FEE_TYPE},
        proofs::{prove_xfr, verify_xfr},
    };
    use crate::setup::{ProverParams, VerifierParams};
    use rand_chacha::ChaChaRng;
    use rand_core::{RngCore, SeedableRng};
    use zei_algebra::{bls12_381::BLSScalar, One};

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_single_asset() {
        // single asset type
        let fee_type = FEE_TYPE.as_scalar();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;
        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();

        let rnd_amount = rng.next_u64();
        let amount = rnd_amount % total_input;
        inputs.push((amount, fee_type));
        total_input -= amount;
        inputs.push((total_input, fee_type));

        let mut outputs: Vec<(u64, BLSScalar, BLSScalar)> = Vec::new();
        for _i in 1..6 {
            let rnd_amount = rng.next_u64();
            let amount = rnd_amount % total_output;
            outputs.push((amount, fee_type, pubkey_x));
            total_output -= amount;
        }
        outputs.push((total_output, fee_type, pubkey_x));

        let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32 + 1, outputs.len() as u32) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_3out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (3, 3)
        let mut rng = ChaChaRng::from_entropy();
        let mut total_input = 50 + rng.next_u64() % 50;

        let mut total_output = total_input;

        let mut inputs: Vec<(u64, BLSScalar)> = Vec::new();
        let mut outputs: Vec<(u64, BLSScalar, BLSScalar)> = Vec::new();

        let amount = rng.next_u64() % total_input;
        inputs.push((amount, fee_type));
        total_input -= amount;
        inputs.push((total_input, fee_type));

        let amount_out = rng.next_u64() % total_output;
        outputs.push((amount_out, fee_type, pubkey_x));
        total_output -= amount_out;
        outputs.push((total_output, fee_type, pubkey_x));

        // input for fees
        let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32 + 1, outputs.len() as u32) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_2out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (1, 2)
        let amount = 0; // a random number in [50, 100)
        let outputs = vec![(amount, fee_type, pubkey_x), (amount, fee_type, pubkey_x)];

        let fee_amount = FEE_CALCULATING_FUNC(1, outputs.len() as u32) as u64;

        let inputs = vec![(fee_amount, fee_type)];

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_1out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        // (n, m) = (2, 1)
        let mut rng = ChaChaRng::from_entropy();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        //This time we need one input equal to the output, besides the input for fees
        let amount = 50 + rng.next_u64() % 50; // a random number in [50, 100)

        let outputs = vec![(amount, fee_type, pubkey_x)];
        let mut inputs = vec![(amount, fee_type)];

        let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32 + 1, outputs.len() as u32) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_3in_6out_multi_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        // multiple asset types
        // (n, m) = (3, 6)
        let one = BLSScalar::one();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        let mut inputs = vec![(/*amount=*/ 40, /*asset_type=*/ fee_type), (80, one)];

        let outputs = vec![
            (5, fee_type, pubkey_x),
            (10, fee_type, pubkey_x),
            (25, fee_type, pubkey_x),
            (20, one, pubkey_x),
            (20, one, pubkey_x),
            (40, one, pubkey_x),
        ];

        let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32 + 1, outputs.len() as u32) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs);
    }

    #[test]
    fn test_anon_multi_xfr_proof_2in_3out_multi_asset() {
        let fee_type = FEE_TYPE.as_scalar();
        let one = BLSScalar::one();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (2, 3)
        let input_1 = 20u64;
        let input_2 = 52u64;

        let output_1 = 17u64;
        let output_2 = 3u64;
        let output_3 = 52u64;

        let mut inputs = vec![(input_1, fee_type), (input_2, one)];

        let outputs = vec![
            (output_1, fee_type, pubkey_x),
            (output_2, fee_type, pubkey_x),
            (output_3, one, pubkey_x),
        ];

        let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32 + 1, outputs.len() as u32) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs);
    }

    fn test_anon_xfr_proof(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
    ) {
        let n_payers = inputs.len();
        let n_payees = outputs.len();

        // build cs
        let secret_inputs =
            new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
        let params = ProverParams::new(n_payers, n_payees, Some(1)).unwrap();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let proof = prove_xfr(&mut prng, &params, secret_inputs).unwrap();

        // A bad proof should fail the verification
        let bad_secret_inputs = new_multi_xfr_witness_for_test(inputs, outputs, [1u8; 32]);
        let bad_proof = prove_xfr(&mut prng, &params, bad_secret_inputs).unwrap();

        // verify good witness
        let node_params = VerifierParams::from(params);
        assert!(verify_xfr(&node_params, &pub_inputs, &proof).is_ok());

        // verify bad witness
        assert!(verify_xfr(&node_params, &pub_inputs, &bad_proof).is_err());
    }
}
