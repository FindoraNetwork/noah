use crate::anon_xfr::TurboPlonkCS;
use crate::errors::Result;
use crate::keys::KeyPair;
use crate::parameters::bulletproofs::BulletproofURS;
use crate::parameters::params::AddressFormat::ED25519;
use digest::{consts::U64, Digest};
use merlin::Transcript;
use noah_algebra::bn254::BN254Scalar;
use noah_algebra::ed25519::Ed25519Fq;
use noah_algebra::prelude::*;
use noah_algebra::zorro::{PedersenCommitmentZorro, ZorroBulletproofGens, ZorroG1, ZorroScalar};
use noah_crypto::anemoi_jive::{AnemoiJive, AnemoiJive254};
use noah_crypto::bulletproofs::scalar_mul::ed25519::ScalarMulProof;
use noah_crypto::delegated_schnorr::{
    prove_delegated_schnorr, verify_delegated_schnorr, DSInspection, DSProof,
};
use noah_crypto::field_simulation::{
    SimFr, SimFrParams, SimFrParamsBN254Secq256k1, SimFrParamsBN254Zorro,
};
use noah_plonk::plonk::constraint_system::field_simulation::SimFrVar;
use noah_plonk::plonk::constraint_system::VarIndex;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
/// The instance for address folding.
pub struct AXfrAddressFoldingInstanceEd25519 {
    /// The inspector's proof.
    pub delegated_schnorr_proof: DSProof<BN254Scalar, ZorroScalar, ZorroG1>,
    /// The commitments generated during the scalar mul proof, used in delegated CP.
    pub scalar_mul_commitments: Vec<ZorroG1>,
    /// The scalar mul proof.
    pub scalar_mul_proof: ScalarMulProof,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
/// The witness for address folding.
pub struct AXfrAddressFoldingWitnessEd25519 {
    /// The key pair
    pub keypair: KeyPair,
    /// Blinding factors of the commitments
    pub blinding_factors: Vec<ZorroScalar>,
    /// The inspector's proof.
    pub delegated_schnorr_proof: DSProof<BN254Scalar, ZorroScalar, ZorroG1>,
    /// Inspection data in the delegated Schnorr proof.
    pub delegated_schnorr_inspection: DSInspection<BN254Scalar, ZorroScalar, ZorroG1>,
    /// Beta.
    pub beta: ZorroScalar,
    /// Lambda.
    pub lambda: ZorroScalar,
}

impl Default for AXfrAddressFoldingWitnessEd25519 {
    fn default() -> Self {
        let keypair = KeyPair::default(ED25519);
        let blinding_factors = vec![ZorroScalar::default(); 3];

        let delegated_schnorr_proof = DSProof::<BN254Scalar, ZorroScalar, ZorroG1> {
            inspection_comm: Default::default(),
            randomizers: vec![ZorroG1::default(); 3],
            response_scalars: vec![(ZorroScalar::default(), ZorroScalar::default()); 3],
        };

        let delegated_schnorr_inspection = DSInspection::<BN254Scalar, ZorroScalar, ZorroG1> {
            committed_data_and_randomizer: vec![
                (ZorroScalar::default(), ZorroScalar::default());
                3
            ],
            r: BN254Scalar::default(),
            group_phantom: Default::default(),
        };

        let beta = ZorroScalar::default();
        let lambda = ZorroScalar::default();

        Self {
            keypair,
            blinding_factors,
            delegated_schnorr_proof,
            delegated_schnorr_inspection,
            beta,
            lambda,
        }
    }
}

/// Create the folding instance and witness of address folding.
pub fn create_address_folding_ed25519<
    R: CryptoRng + RngCore,
    D: Digest<OutputSize = U64> + Default,
>(
    prng: &mut R,
    hash: D,
    transcript: &mut Transcript,
    keypair: &KeyPair,
) -> Result<(
    AXfrAddressFoldingInstanceEd25519,
    AXfrAddressFoldingWitnessEd25519,
)> {
    let (sk, pk) = keypair.to_ed25519()?;

    let pc_gens = PedersenCommitmentZorro::default();
    let bp_gens = ZorroBulletproofGens::load().unwrap();

    // important: address folding relies significantly on the Fiat-Shamir transform.
    transcript.append_message(b"hash", hash.finalize().as_slice());

    let (scalar_mul_proof, scalar_mul_commitments, blinding_factors) =
        { ScalarMulProof::prove(prng, &bp_gens, transcript, &pk, &sk)? };

    let (delegated_schnorr_proof, delegated_schnorr_inspection, beta, lambda) = {
        let secret_key_in_fq = ZorroScalar::from_bytes(&sk.to_bytes())?;

        prove_delegated_schnorr::<BN254Scalar, AnemoiJive254, _, _, _, SimFrParamsBN254Zorro, _>(
            prng,
            &vec![
                (pk.get_x(), blinding_factors[0]),
                (pk.get_y(), blinding_factors[1]),
                (secret_key_in_fq, blinding_factors[2]),
            ],
            &pc_gens,
            &scalar_mul_commitments,
            transcript,
        )?
    };

    let instance = AXfrAddressFoldingInstanceEd25519 {
        delegated_schnorr_proof: delegated_schnorr_proof.clone(),
        scalar_mul_commitments,
        scalar_mul_proof,
    };

    let witness = AXfrAddressFoldingWitnessEd25519 {
        keypair: keypair.clone(),
        blinding_factors,
        delegated_schnorr_proof,
        delegated_schnorr_inspection,
        beta,
        lambda,
    };

    Ok((instance, witness))
}

/// Verify an address folding proof.
pub fn verify_address_folding_ed25519<D: Digest<OutputSize = U64> + Default>(
    hash: D,
    transcript: &mut Transcript,
    instance: &AXfrAddressFoldingInstanceEd25519,
) -> Result<(ZorroScalar, ZorroScalar)> {
    let pc_gens = PedersenCommitmentZorro::default();
    let bp_gens = ZorroBulletproofGens::load().unwrap();

    // important: address folding relies significantly on the Fiat-Shamir transform.
    transcript.append_message(b"hash", hash.finalize().as_slice());

    instance
        .scalar_mul_proof
        .verify(&bp_gens, transcript, &instance.scalar_mul_commitments)?;

    let (beta, lambda) = verify_delegated_schnorr(
        &pc_gens,
        &instance.scalar_mul_commitments,
        &instance.delegated_schnorr_proof,
        transcript,
    )?;

    Ok((beta, lambda))
}

/// Generate the constraints used in the Plonk proof for address folding.
pub fn prove_address_folding_in_cs_ed25519(
    cs: &mut TurboPlonkCS,
    public_key_scalars_vars: &[VarIndex; 3],
    secret_key_scalars_vars: &[VarIndex; 2],
    witness: &AXfrAddressFoldingWitnessEd25519,
) -> Result<()> {
    let (sk, pk) = witness.keypair.to_ed25519()?;

    // 1. decompose the scalar inputs.
    let mut public_key_bits_vars = cs.range_check(public_key_scalars_vars[0], 248);
    public_key_bits_vars.extend_from_slice(&cs.range_check(public_key_scalars_vars[1], 248));
    public_key_bits_vars.extend_from_slice(&cs.range_check(public_key_scalars_vars[2], 16));

    let mut secret_key_bits_vars = cs.range_check(secret_key_scalars_vars[0], 248);
    secret_key_bits_vars.extend_from_slice(&cs.range_check(secret_key_scalars_vars[1], 8));

    let bytes_to_bits = |v: &u8| {
        vec![
            v & 1 != 0,
            v & 2 != 0,
            v & 4 != 0,
            v & 8 != 0,
            v & 16 != 0,
            v & 32 != 0,
            v & 64 != 0,
            v & 128 != 0,
        ]
    };

    let secret_key_bits = sk
        .to_bytes()
        .iter()
        .flat_map(bytes_to_bits)
        .collect::<Vec<bool>>();

    // 2. check that the secret key is smaller than the modulus.
    let modulus_bits = Ed25519Fq::get_field_size_le_bytes()
        .iter()
        .flat_map(bytes_to_bits)
        .collect::<Vec<bool>>();

    let mut flag_smaller_than_modulus_var = cs.zero_var();
    let mut flag_meet_first_different_bit_var = cs.zero_var();

    let mut flag_smaller_than_modulus = false;
    let mut flag_meet_first_different_bit = false;

    assert_eq!(secret_key_bits.len(), modulus_bits.len());

    for ((secret_key_bit_var, secret_key_bit), modulus_bit) in secret_key_bits_vars
        .iter()
        .zip(secret_key_bits.iter())
        .zip(modulus_bits.iter())
        .rev()
    {
        if *modulus_bit {
            // If this is the first time we see different bits, then we can set `flag_smaller_than_modulus` to true if the corresponding
            // modulus bit is true (which implies that the secret key bit is false).
            //
            // In other situations, however, `flag_smaller_than_modulus` remains unchanged.
            flag_smaller_than_modulus =
                flag_smaller_than_modulus || (!secret_key_bit && !flag_meet_first_different_bit);

            flag_smaller_than_modulus_var = {
                let res = cs.new_variable(BN254Scalar::from(flag_smaller_than_modulus as u32));

                let zero = BN254Scalar::zero();
                let one = BN254Scalar::one();
                let zero_var = cs.zero_var();

                cs.push_add_selectors(one.neg(), one.neg(), one, zero);
                cs.push_mul_selectors(one, zero);
                cs.push_constant_selector(one);
                cs.push_ecc_selector(zero);
                cs.push_out_selector(one);

                cs.wiring[0].push(flag_meet_first_different_bit_var);
                cs.wiring[1].push(*secret_key_bit_var);
                cs.wiring[2].push(flag_smaller_than_modulus_var);
                cs.wiring[3].push(zero_var);
                cs.wiring[4].push(res);
                cs.finish_new_gate();

                res
            };

            // Track if we have already met different bits.
            flag_meet_first_different_bit = flag_meet_first_different_bit || !secret_key_bit;

            flag_meet_first_different_bit_var = {
                let res = cs.new_variable(BN254Scalar::from(flag_meet_first_different_bit as u32));

                let zero = BN254Scalar::zero();
                let one = BN254Scalar::one();
                let zero_var = cs.zero_var();

                cs.push_add_selectors(zero, one.neg(), zero, zero);
                cs.push_mul_selectors(one, zero);
                cs.push_constant_selector(one);
                cs.push_ecc_selector(zero);
                cs.push_out_selector(one);

                cs.wiring[0].push(flag_meet_first_different_bit_var);
                cs.wiring[1].push(*secret_key_bit_var);
                cs.wiring[2].push(zero_var);
                cs.wiring[3].push(zero_var);
                cs.wiring[4].push(res);
                cs.finish_new_gate();

                res
            };
        } else {
            // Track if we have already met different bits.
            flag_meet_first_different_bit = flag_meet_first_different_bit || *secret_key_bit;

            flag_meet_first_different_bit_var = {
                let res = cs.new_variable(BN254Scalar::from(flag_meet_first_different_bit as u32));

                let zero = BN254Scalar::zero();
                let one = BN254Scalar::one();
                let zero_var = cs.zero_var();

                cs.push_add_selectors(one, one, zero, zero);
                cs.push_mul_selectors(one.neg(), zero);
                cs.push_constant_selector(zero);
                cs.push_ecc_selector(zero);
                cs.push_out_selector(one);

                cs.wiring[0].push(flag_meet_first_different_bit_var);
                cs.wiring[1].push(*secret_key_bit_var);
                cs.wiring[2].push(zero_var);
                cs.wiring[3].push(zero_var);
                cs.wiring[4].push(res);
                cs.finish_new_gate();

                res
            };
        }
    }

    // Enforce `flag_smaller_than_modulus_var = true` and `flag_meet_first_different_bit_var = true`
    {
        let zero = BN254Scalar::zero();
        let one = BN254Scalar::one();
        let zero_var = cs.zero_var();

        cs.push_add_selectors(zero, zero, zero, zero);
        cs.push_mul_selectors(one.neg(), zero);
        cs.push_constant_selector(one);
        cs.push_ecc_selector(zero);
        cs.push_out_selector(zero);

        cs.wiring[0].push(flag_smaller_than_modulus_var);
        cs.wiring[1].push(flag_meet_first_different_bit_var);
        cs.wiring[2].push(zero_var);
        cs.wiring[3].push(zero_var);
        cs.wiring[4].push(zero_var);
        cs.finish_new_gate();
    }

    // 3. allocate the simulated field elements and obtain their bit representations.
    let pk_affine = pk.get_raw();
    let x_sim_fr = SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(&pk_affine.x.into());
    let (x_sim_fr_var, x_sim_bits_vars) = SimFrVar::alloc_witness(cs, &x_sim_fr);
    let y_sim_fr = SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(&pk_affine.y.into());
    let (y_sim_fr_var, y_sim_bits_vars) = SimFrVar::alloc_witness(cs, &y_sim_fr);

    // we can do so only because the secp256k1's order is smaller than its base field modulus.
    let s_sim_fr = SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(&sk.into());
    let (s_sim_fr_var, s_sim_bits_vars) = SimFrVar::alloc_witness(cs, &s_sim_fr);

    // 4. check that the bit representations are the same as the one provided through scalars.
    let mut public_key_sim_bits_vars = x_sim_bits_vars.clone();
    public_key_sim_bits_vars.extend_from_slice(&y_sim_bits_vars);

    assert_eq!(public_key_sim_bits_vars.len(), public_key_bits_vars.len());
    assert_eq!(s_sim_bits_vars.len(), secret_key_bits_vars.len());

    for (sim_bit, scalar_bit) in public_key_sim_bits_vars
        .iter()
        .zip(public_key_bits_vars.iter())
    {
        cs.equal(*sim_bit, *scalar_bit);
    }

    for (sim_bit, scalar_bit) in s_sim_bits_vars.iter().zip(secret_key_bits_vars.iter()) {
        cs.equal(*sim_bit, *scalar_bit);
    }

    // 5. allocate the simulated field elements for the delegated Schnorr protocol.
    // note: the verifier will combine the challenges using the power series of lambda.
    let lambda_series = vec![
        ZorroScalar::one(),
        witness.lambda,
        witness.lambda * witness.lambda,
    ];
    let beta_lambda_series = lambda_series
        .iter()
        .map(|v| *v * witness.beta)
        .collect::<Vec<ZorroScalar>>();

    // skip the first one
    let mut lambda_series_vars_skip_first = vec![];
    for lambda_series_val in lambda_series.iter().skip(1) {
        let sim_fr =
            SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
                &<ZorroScalar as Into<BigUint>>::into(*lambda_series_val),
            );
        lambda_series_vars_skip_first.push(
            SimFrVar::<BN254Scalar, SimFrParamsBN254Zorro>::alloc_input(cs, &sim_fr),
        );
    }

    // include the first one
    let mut beta_lambda_series_vars = vec![];
    for beta_lambda_series_var in beta_lambda_series.iter() {
        let sim_fr =
            SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
                &<ZorroScalar as Into<BigUint>>::into(*beta_lambda_series_var),
            );
        beta_lambda_series_vars.push(SimFrVar::<BN254Scalar, SimFrParamsBN254Zorro>::alloc_input(
            cs, &sim_fr,
        ));
    }

    let query_vars = [x_sim_fr_var, y_sim_fr_var, s_sim_fr_var]
        .iter()
        .zip(
            witness
                .delegated_schnorr_inspection
                .committed_data_and_randomizer
                .iter(),
        )
        .map(|(v_var, (_, blinding_factor))| {
            let sim_fr =
                SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(&<ZorroScalar as Into<
                    BigUint,
                >>::into(
                    *blinding_factor
                ));
            let (blinding_factor_var, _) =
                SimFrVar::<BN254Scalar, SimFrParamsBN254Zorro>::alloc_witness(cs, &sim_fr);

            (v_var.clone(), blinding_factor_var)
        })
        .collect::<Vec<(
            SimFrVar<BN254Scalar, SimFrParamsBN254Zorro>,
            SimFrVar<BN254Scalar, SimFrParamsBN254Zorro>,
        )>>();

    let combined_response_scalar = witness.delegated_schnorr_proof.response_scalars[0].0
        + witness.delegated_schnorr_proof.response_scalars[1].0 * witness.lambda
        + witness.delegated_schnorr_proof.response_scalars[2].0 * witness.lambda * witness.lambda;
    let combined_response_scalar_sim_fr = SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
        &<ZorroScalar as Into<BigUint>>::into(combined_response_scalar),
    );
    let combined_response_scalar_var = SimFrVar::<BN254Scalar, SimFrParamsBN254Zorro>::alloc_input(
        cs,
        &combined_response_scalar_sim_fr,
    );

    let mut lhs = query_vars[0].0.mul(cs, &beta_lambda_series_vars[0]);

    lhs = query_vars[1]
        .0
        .mul(cs, &beta_lambda_series_vars[1])
        .add(cs, &lhs);
    lhs = query_vars[1]
        .1
        .mul(cs, &lambda_series_vars_skip_first[0])
        .add(cs, &lhs);
    lhs = query_vars[2]
        .0
        .mul(cs, &beta_lambda_series_vars[2])
        .add(cs, &lhs);
    lhs = query_vars[2]
        .1
        .mul(cs, &lambda_series_vars_skip_first[1])
        .add(cs, &lhs);

    let rhs = combined_response_scalar_var.sub(cs, &query_vars[0].1);

    let res = lhs.sub(cs, &rhs);
    res.enforce_zero(cs);

    // 6. merge limbs of the committed data as well as the randomizer scalars.
    let mut all_limbs =
        Vec::with_capacity(2 * query_vars.len() * SimFrParamsBN254Secq256k1::NUM_OF_LIMBS);
    let mut all_limbs_var =
        Vec::with_capacity(2 * query_vars.len() * SimFrParamsBN254Secq256k1::NUM_OF_LIMBS);

    // append all the data
    for (v, _) in query_vars.iter() {
        all_limbs.extend_from_slice(&v.val.limbs);
        all_limbs_var.extend_from_slice(&v.var);
    }

    // append all the corresponding randomizers
    for (_, v) in query_vars.iter() {
        all_limbs.extend_from_slice(&v.val.limbs);
        all_limbs_var.extend_from_slice(&v.var);
    }

    let mut compressed_limbs = Vec::new();
    let mut compressed_limbs_var = Vec::new();

    let num_limbs_compressed = BN254Scalar::capacity() / SimFrParamsBN254Zorro::BIT_PER_LIMB;

    let step_vec = (1..=num_limbs_compressed)
        .map(|i| BN254Scalar::from(&BigUint::one().shl(SimFrParamsBN254Zorro::BIT_PER_LIMB * i)))
        .collect::<Vec<BN254Scalar>>();

    for (limbs, limbs_var) in all_limbs
        .chunks(num_limbs_compressed)
        .zip(all_limbs_var.chunks(num_limbs_compressed))
    {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <BN254Scalar as Into<BigUint>>::into(*limb)
                    .shl(SimFrParamsBN254Zorro::BIT_PER_LIMB * i),
            );
        }
        compressed_limbs.push(BN254Scalar::from(&sum));

        let one = BN254Scalar::one();
        let zero = BN254Scalar::zero();
        let zero_var = cs.zero_var();

        let mut sum_var = {
            let first_var = *limbs_var.get(0).unwrap_or(&zero_var);
            let second_var = *limbs_var.get(1).unwrap_or(&zero_var);
            let third_var = *limbs_var.get(2).unwrap_or(&zero_var);
            let fourth_var = *limbs_var.get(3).unwrap_or(&zero_var);

            cs.linear_combine(
                &[first_var, second_var, third_var, fourth_var],
                one,
                step_vec[0],
                step_vec[1],
                step_vec[2],
            )
        };

        if limbs.len() == 5 {
            let fifth_var = *limbs_var.get(4).unwrap_or(&zero_var);
            sum_var = cs.linear_combine(
                &[sum_var, fifth_var, zero_var, zero_var],
                one,
                step_vec[3],
                zero,
                zero,
            );
        }

        compressed_limbs_var.push(sum_var);
    }

    // 7. compare with the inspector's state.
    let r = witness.delegated_schnorr_inspection.r;
    let r_var = cs.new_variable(r);
    let comm_var = cs.new_variable(witness.delegated_schnorr_proof.inspection_comm);

    {
        let mut input_vars = compressed_limbs_var.clone();
        input_vars.push(r_var);

        let mut input = compressed_limbs.clone();
        input.push(r);

        let trace = AnemoiJive254::eval_variable_length_hash_with_trace(&input);
        cs.anemoi_variable_length_hash::<AnemoiJive254>(&trace, &input_vars, comm_var);
    }
    cs.prepare_pi_variable(comm_var);

    for fr_var in lambda_series_vars_skip_first.iter() {
        for i in 0..SimFrParamsBN254Zorro::NUM_OF_LIMBS {
            cs.prepare_pi_variable(fr_var.var[i]);
        }
    }

    for fr_var in beta_lambda_series_vars.iter() {
        for i in 0..SimFrParamsBN254Zorro::NUM_OF_LIMBS {
            cs.prepare_pi_variable(fr_var.var[i]);
        }
    }

    for i in 0..SimFrParamsBN254Zorro::NUM_OF_LIMBS {
        cs.prepare_pi_variable(combined_response_scalar_var.var[i]);
    }

    Ok(())
}

/// Convert the instance into input to the Plonk verifier.
pub fn prepare_verifier_input_ed25519(
    instance: &AXfrAddressFoldingInstanceEd25519,
    beta: &ZorroScalar,
    lambda: &ZorroScalar,
) -> Vec<BN254Scalar> {
    let mut v = vec![instance.delegated_schnorr_proof.inspection_comm];

    let lambda_series = vec![ZorroScalar::one(), *lambda, *lambda * lambda];
    let beta_lambda_series = lambda_series
        .iter()
        .map(|v| *v * beta)
        .collect::<Vec<ZorroScalar>>();

    for lambda_series_val in lambda_series.iter().skip(1) {
        let sim_fr =
            SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
                &<ZorroScalar as Into<BigUint>>::into(*lambda_series_val),
            );
        v.extend_from_slice(&sim_fr.limbs);
    }

    for beta_lambda_series_val in beta_lambda_series.iter() {
        let sim_fr =
            SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
                &<ZorroScalar as Into<BigUint>>::into(*beta_lambda_series_val),
            );
        v.extend_from_slice(&sim_fr.limbs);
    }

    let combined_response_scalar = instance.delegated_schnorr_proof.response_scalars[0].0
        + instance.delegated_schnorr_proof.response_scalars[1].0 * lambda
        + instance.delegated_schnorr_proof.response_scalars[2].0 * lambda * lambda;
    let combined_response_scalar_sim_fr = SimFr::<BN254Scalar, SimFrParamsBN254Zorro>::from(
        &<ZorroScalar as Into<BigUint>>::into(combined_response_scalar),
    );
    v.extend_from_slice(&combined_response_scalar_sim_fr.limbs);

    v
}
