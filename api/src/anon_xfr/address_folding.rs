use crate::anon_xfr::keys::{AXfrKeyPair, AXfrSignatureInstance};
use crate::anon_xfr::TurboPlonkCS;
use digest::{Digest, Output};
use merlin::Transcript;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use zei_algebra::bls12_381::BLSScalar;
use zei_algebra::bs257::{BS257Scalar, BS257G1};
use zei_algebra::prelude::*;
use zei_algebra::secp256k1::{SECP256K1Scalar, SECP256K1G1};
use zei_crypto::bulletproofs::scalar_mul::ScalarMulProof;
use zei_crypto::delegated_chaum_pedersen::{
    prove_delegated_chaum_pedersen, DelegatedChaumPedersenInspection, DelegatedChaumPedersenProof,
};
use zei_crypto::field_simulation::{SimFr, SimFrParamsBS257};
use zei_plonk::plonk::constraint_system::field_simulation::SimFrVar;
use zei_plonk::plonk::constraint_system::VarIndex;

pub struct AXfrAddressFoldingInstance {
    /// The inspector's proof.
    pub delegated_cp_proof: DelegatedChaumPedersenProof<BS257Scalar, BS257G1, SimFrParamsBS257>,
    /// The commitments generated during the scalar mul proof, used in delegated CP.
    pub scalar_mul_commitments: Vec<BS257G1>,
    /// The scalar mul proof.
    pub scalar_mul_proof: ScalarMulProof,
    /// The instance part of the signature.
    pub sig_instance: AXfrSignatureInstance,
}

pub struct AXfrAddressFoldingWitness {
    /// The key pair
    pub keypair: AXfrKeyPair,
    /// Blinding factors of the commitments
    pub blinding_factors: Vec<BS257Scalar>,
    /// Inspection data in the delegated Chaum-Pedersen proof.
    pub delegated_cp_inspection:
        DelegatedChaumPedersenInspection<BS257Scalar, BS257G1, SimFrParamsBS257>,
    /// Beta.
    pub beta: BS257Scalar,
    /// Lambda.
    pub lambda: BS257Scalar,
}

pub fn create_address_folding<R: CryptoRng + RngCore, D: Digest<Output = U64> + Default>(
    prng: &mut R,
    hash: D,
    transcript: &mut Transcript,
    bp_gens_len: usize,
    keypair: &AXfrKeyPair,
    aux_info: &BLSScalar,
) -> Result<(AXfrAddressFoldingInstance, AXfrAddressFoldingWitness)> {
    let sig = keypair.get_secret_key().sign(prng, hash.clone())?;

    let (sig_instance, sig_witness) =
        sig.to_instance_and_witness(&input_keypair.get_public_key())?;

    let pc_gens = bulletproofs_bs257::PedersenGens::default();

    let public_key = keypair.get_public_key();
    let secret_key = keypair.get_secret_key();

    let (scalar_mul_proof, scalar_mul_commitments, blinding_factors) = {
        let bp_gens = bulletproofs_bs257::BulletproofGens::new(bp_gens_len, 1);

        let r = sig_instance.scalar_r.clone();

        let reconstructed_r: BigUint = if sig_instance.recovery & 2 == 0 {
            r.into()
        } else {
            SECP256K1Scalar::get_field_size_biguint() + r.into()
        };

        let reconstructed_x = BS257Scalar::from(&reconstructed_r);

        let mut z_bytes = [0u8; 32];
        z_bytes.copy_from_slice(&hash.finalize().as_slice());
        let z_biguint = BigUint::from_bytes_le(&z_bytes);
        let z = SECP256K1Scalar::from(&z_biguint);

        let mut point_r_divided_by_r = SECP256K1G1::get_point_from_x(&reconstructed_x)?;
        let mut point_g_times_z_divided_by_r = SECP256K1G1::get_base().mul(&z).mul(&r.inv()?);

        ScalarMulProof::prove(
            prng,
            &pc_gens,
            &bp_gens,
            transcript,
            &public_key.0,
            &secret_key.0,
            &point_r_divided_by_r,
            &point_g_times_z_divided_by_r,
        )?
    };

    let (delegated_cp_proof, delegated_cp_inspection, beta, lambda) = {
        let secret_key_in_fq = BS257Scalar::from_bytes(&secret_key.0.to_bytes());

        prove_delegated_chaum_pedersen(
            prng,
            &vec![
                (public_key.0.get_x(), blinding_factors[0]),
                (public_key.0.get_y(), blinding_factors[1]),
                secret_key_in_fq,
                blinding_factors[2],
            ],
            &pc_gens,
            &scalar_mul_commitments,
            &aux_info,
        )
        .c(d!())?
    };

    let instance = AXfrAddressFoldingInstance {
        delegated_cp_proof,
        scalar_mul_commitments,
        scalar_mul_proof,
        sig_instance,
    };

    let witness = AXfrAddressFoldingWitness {
        keypair: keypair.clone(),
        blinding_factors,
        delegated_cp_inspection,
        beta,
        lambda,
    };

    Ok((instance, witness))
}

pub fn prove_address_folding_in_cs(
    cs: &mut TurboPlonkCS,
    public_key_scalars_vars: &[VarIndex; 3],
    secret_key_scalars_vars: &[VarIndex; 2],
    instance: &AXfrAddressFoldingInstance,
    witness: &AXfrAddressFoldingWitness,
) {
    // 1. decompose the scalar inputs.
    let mut public_key_bits_vars = cs.range_check(public_key_scalars_vars[0], 248);
    public_key_bits_vars.extend_from_slice(&cs.range_check(public_key_scalars_vars[1], 248));
    public_key_bits_vars.extend_from_slice(&cs.range_check(public_key_scalars_vars[2], 16));

    let mut secret_key_bits_vars = cs.range_check(secret_key_scalars[0], 248);
    secret_key_bits_vars.extend_from_slice(&cs.range_check(secret_key_scalars[1], 8));

    let bytes_to_bits = |v: u8| {
        [
            v & 128 != 0,
            v & 64 != 0,
            v & 32 != 0,
            v & 16 != 0,
            v & 8 != 0,
            v & 4 != 0,
            v & 2 != 0,
            v & 1 != 0,
        ]
    };

    let secret_key_bits = witness
        .keypair
        .get_secret_key()
        .0
        .to_bytes()
        .iter()
        .flat_map(bytes_to_bits)
        .collect::<Vec<bool>>();

    // 2. check that the secret key is smaller than the modulus.
    let modulus_bits = SECP256K1Scalar::get_field_size_le_bytes()
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
    {
        let modulus_bit_var = cs.new_variable(BLSScalar::from(modulus_bit as u32));

        let meet_different_bit_var =
            cs.is_equal(secret_key_bit_var.clone(), modulus_bit_var.clone());
        let meet_different_bit = secret_key_bit != modulus_bit;

        // If this is the first time we see different bits, then we can set `flag_smaller_than_modulus` to true if the corresponding
        // modulus bit is true (which implies that the secret key bit is false).
        //
        // In other situations, however, `flag_smaller_than_modulus` remains unchanged.
        flag_smaller_than_modulus = flag_smaller_than_modulus
            || (meet_different_bit && *modulus_bit && *!flag_meet_first_different_bit);
        if modulus_bit {
            flag_smaller_than_modulus_var = {
                let res = cs.new_variable(BLSScalar::from(flag_smaller_than_modulus as u32));

                let zero = BLSScalar::zero();
                let one = BLSScalar::one();
                cs.push_add_selectors(zero, one, one, zero);
                cs.push_mul_selectors(one.neg(), zero);
                cs.push_constant_selector(zero);
                cs.push_rescue_selectors(zero, zero, zero, zero);
                cs.push_out_selector(zero);
                cs.wiring[0].push(flag_meet_first_different_bit_var);
                cs.wiring[1].push(meet_different_bit_var);
                cs.wiring[2].push(flag_smaller_than_modulus_var);
                cs.wiring[3].push(cs.zero_var());
                cs.wiring[4].push(cs.zero_var());
                cs.size += 1;

                res
            }
        }

        // Track if we have already met different bits.
        flag_meet_first_different_bit = flag_meet_first_different_bit || meet_different_bit;
        flag_meet_first_different_bit_var = {
            let res = cs.new_variable(BLSScalar::from(flag_meet_first_different_bit as u32));

            let zero = BLSScalar::zero();
            let one = BLSScalar::one();
            cs.push_add_selectors(one, one, zero, zero);
            cs.push_mul_selectors(one.neg(), zero);
            cs.push_constant_selector(zero);
            cs.push_rescue_selectors(zero, zero, zero, zero);
            cs.push_out_selector(zero);
            cs.wiring[0].push(flag_meet_first_different_bit_var);
            cs.wiring[1].push(meet_different_bit_var);
            cs.wiring[2].push(cs.zero_var());
            cs.wiring[3].push(cs.zero_var());
            cs.wiring[4].push(cs.zero_var());
            cs.size += 1;

            res
        };
    }

    // Enforce `flag_smaller_than_modulus_var = true` and `flag_meet_first_different_bit_var = true`
    {
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        cs.push_add_selectors(zero, zero, zero, zero);
        cs.push_mul_selectors(one.neg(), zero);
        cs.push_constant_selector(one);
        cs.push_rescue_selectors(zero, zero, zero, zero);
        cs.push_out_selector(zero);
        cs.wiring[0].push(flag_smaller_than_modulus_var);
        cs.wiring[1].push(flag_meet_first_different_bit_var);
        cs.wiring[2].push(cs.zero_var());
        cs.wiring[3].push(cs.zero_var());
        cs.wiring[4].push(cs.zero_var());
        cs.size += 1;

        res
    }

    // 3. allocate the simulated field elements and obtain their bit representations.
    let x_sim_fr =
        SimFr::<SimFrParamsBS257>::from(&witness.keypair.get_public_key().0.get_x().into());
    let (x_sim_fr_var, x_sim_bits_vars) = SimFrVar::alloc_witness(cs, &x_sim_fr);

    let y_sim_fr =
        SimFr::<SimFrParamsBS257>::from(&witness.keypair.get_public_key().0.get_y().into());
    let (y_sim_fr_var, y_sim_bits_vars) = SimFrVar::alloc_witness(cs, &y_sim_fr);

    // we can do so only because the secp256k1's order is smaller than its base field modulus.
    let s_sim_fr = SimFr::<SimFrParamsBS257>::from(&witness.keypair.get_secret_key().0.into());
    let (s_sim_fr_var, s_sim_bits_vars) = SimFrVar::alloc_witness(cs, &s_sim_fr);

    // 4. Check that the bit representations are the same as the one provided through scalars.

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
}
