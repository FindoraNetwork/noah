use crate::anon_xfr::keys::AXfrSignature;
use crate::anon_xfr::{
    circuits::{
        add_merkle_path_variables, commit, compute_merkle_root, nullify, AccElemVars,
        NullifierInputVars, PayerSecret, PayerSecretVars, TurboPlonkCS,
    },
    keys::{AXfrKeyPair, AXfrPubKey},
    nullifier,
    structs::{Nullifier, OpenAnonBlindAssetRecord},
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::asset_record::{build_open_asset_record, AssetRecordType};
use crate::xfr::sig::XfrPublicKey;
use crate::xfr::structs::{
    AssetRecordTemplate, BlindAssetRecord, OwnerMemo, XfrAmount, XfrAssetType,
};
use algebra::groups::GroupArithmetic;
use algebra::ristretto::{RistrettoPoint, RistrettoScalar};
use algebra::{
    bls12_381::BLSScalar,
    groups::{Group, One as ArkOne, Scalar, ScalarArithmetic, Zero as ArkZero},
    jubjub::{JubjubPoint, JubjubScalar},
};
use crypto::basics::commitments::pedersen::PedersenGens;
use crypto::basics::commitments::ristretto_pedersen::RistrettoPedersenGens;
use crypto::field_simulation::{SimFr, BIT_PER_LIMB, NUM_OF_LIMBS};
use crypto::pc_eq_rescue_split_verifier_zk_part::{
    prove_pc_eq_rescue_external, verify_pc_eq_rescue_external, NonZKState, ZKPartProof,
};
use merlin::Transcript;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use poly_iops::{
    commitments::kzg_poly_com::KZGCommitmentSchemeBLS,
    plonk::{
        constraint_system::{
            field_simulation::SimFrVar, rescue::StateVar, TurboConstraintSystem,
            VarIndex,
        },
        prover::prover,
        setup::PlonkPf,
        verifier::verifier,
    },
};
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::ops::{AddAssign, Shl};
use utils::errors::ZeiError;

pub type Abar2BarPlonkProof = PlonkPf<KZGCommitmentSchemeBLS>;
pub const TWO_POW_32: u64 = 1 << 32;
const ABAR_TO_BAR_TRANSCRIPT: &[u8] = b"Abar to Bar Conversion";
const SK_LEN: usize = 252;

/// ConvertAbarBarProof is a struct to hold various aspects of a ZKP to prove equality, spendability
/// and conversion of an ABAR to a BAR on the chain.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertAbarBarProof {
    commitment_eq_proof: ZKPartProof,
    spending_proof: Abar2BarPlonkProof,
    merkle_root: BLSScalar,
    merkle_root_version: usize,
}

impl ConvertAbarBarProof {
    #[allow(dead_code)]
    pub fn get_merkle_root_version(&self) -> usize {
        return self.merkle_root_version;
    }
}

/// AbarToBarBody has the input, the output and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarBody {
    /// input ABAR being spent
    pub input: (Nullifier, AXfrPubKey),
    /// The new BAR to be created
    pub output: BlindAssetRecord,
    /// The ZKP for the conversion
    pub proof: ConvertAbarBarProof,
    /// The owner memo
    pub memo: Option<OwnerMemo>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarNote {
    pub body: AbarToBarBody,
    pub signature: AXfrSignature,
}

/// This function generates the AbarToBarBody from the Open ABARs, the receiver address and the signing
/// key pair.
#[allow(dead_code)]
pub fn gen_abar_to_bar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    oabar: &OpenAnonBlindAssetRecord,
    abar_keypair: &AXfrKeyPair,
    bar_pub_key: &XfrPublicKey,
    asset_record_type: AssetRecordType,
) -> Result<(AbarToBarBody, AXfrKeyPair)> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.pub_key() != oabar.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    let obar_amount = oabar.amount;
    let obar_type = oabar.asset_type;

    let pc_gens = RistrettoPedersenGens::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        obar_amount,
        obar_type,
        asset_record_type,
        bar_pub_key.clone(),
    );
    let (obar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    // 2. randomize input key pair with open_abar rand key
    let rand_input_keypair = abar_keypair.randomize(&oabar.key_rand_factor);

    // 3. build input witness info
    let diversifier = JubjubScalar::random(prng);
    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let nullifier_and_signing_key = (
        nullifier(
            &rand_input_keypair,
            oabar.amount,
            &oabar.asset_type,
            mt_leaf_info.uid,
        ),
        rand_input_keypair.pub_key().randomize(&diversifier),
    );

    // 4. Construct the equality proof
    let x = RistrettoScalar::from_u64(oabar.amount);
    let y: RistrettoScalar = oabar.asset_type.as_scalar();
    let gamma = obar.amount_blinds.0.add(
        &obar
            .amount_blinds
            .1
            .mul(&RistrettoScalar::from_u64(TWO_POW_32)),
    );
    let delta = obar.type_blind;

    let pc_gens =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());

    let point_p = pc_gens.commit(&[x], &gamma).c(d!())?;
    let point_q = pc_gens.commit(&[y], &delta).c(d!())?;

    let nullifier = nullifier_and_signing_key.0;

    // 5. compute the non-ZK part of the proof
    let (commitment_eq_proof, non_zk_state, beta) = prove_pc_eq_rescue_external(
        prng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &nullifier,
    )
    .c(d!())?;

    // 4. build the plonk proof
    let payers_secret = PayerSecret {
        sec_key: rand_input_keypair.get_secret_scalar(),
        diversifier,
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let spending_proof = prove_abar_to_bar_spending(
        prng,
        params,
        payers_secret,
        &commitment_eq_proof,
        &non_zk_state,
        &beta,
    )
    .c(d!())?;

    let diversified_key_pair = rand_input_keypair.randomize(&diversifier);

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();
    let convert_proof = ConvertAbarBarProof {
        commitment_eq_proof,
        spending_proof,
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
    };

    Ok((
        AbarToBarBody {
            input: nullifier_and_signing_key,
            output: obar.blind_asset_record.clone(),
            proof: convert_proof,
            memo: owner_memo,
        },
        diversified_key_pair,
    ))
}

pub fn gen_abar_to_bar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    record: &OpenAnonBlindAssetRecord,
    abar_keypair: &AXfrKeyPair,
    bar_pub_key: &XfrPublicKey,
    asset_record_type: AssetRecordType,
) -> Result<AbarToBarNote> {
    let (body, randomized_keypair) = gen_abar_to_bar_body(
        prng,
        params,
        record,
        abar_keypair,
        bar_pub_key,
        asset_record_type,
    )
    .c(d!())?;
    let msg = bincode::serialize(&body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;
    let signature = randomized_keypair.sign(&msg);
    let note = AbarToBarNote { body, signature };
    Ok(note)
}

// Verifies the body
#[allow(dead_code)]
pub fn verify_abar_to_bar_body(
    params: &NodeParams,
    body: &AbarToBarBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    verify_abar_to_bar(params, &body, merkle_root)
}

pub fn verify_abar_to_bar_note(
    params: &NodeParams,
    note: &AbarToBarNote,
    merkle_root: &BLSScalar,
) -> Result<()> {
    verify_abar_to_bar_body(params, &note.body, merkle_root).c(d!())?;
    let msg = bincode::serialize(&note.body).c(d!(ZeiError::SerializationError))?;
    note.body.input.1.verify(&msg, &note.signature).c(d!())
}

/// Verifies the proof with the input and output
#[allow(dead_code)]
pub fn verify_abar_to_bar(
    params: &NodeParams,
    body: &AbarToBarBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != body.proof.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let bar = body.output.clone();
    let pc_gens =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());

    // 1. get commitments
    // 1.1 reconstruct total amount commitment from bar object
    let (com_low, com_high) = match bar.amount {
        XfrAmount::Confidential((low, high)) => (
            low.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
            high.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
        ),
        XfrAmount::NonConfidential(amount) => {
            // fake commitment
            let (l, h) = utils::u64_to_u32_pair(amount);
            (
                pc_gens
                    .commit(&[RistrettoScalar::from_u32(l)], &RistrettoScalar::zero())
                    .c(d!())?,
                pc_gens
                    .commit(&[RistrettoScalar::from_u32(h)], &RistrettoScalar::zero())
                    .c(d!())?,
            )
        }
    };

    // 1.2 get asset type commitment
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from_u64(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(ZeiError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // fake commitment
            pc_gens
                .commit(&[a.as_scalar()], &RistrettoScalar::zero())
                .c(d!())?
        }
    };

    let input = body.input;
    let proof = body.proof.clone();

    // 2. verify equality of committed values
    let beta = verify_pc_eq_rescue_external(
        &pc_gens,
        &com_amount,
        &com_asset_type,
        &input.0,
        &proof.commitment_eq_proof,
    )
    .c(d!())?;

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let mut online_inputs = vec![];

    online_inputs.push(input.clone().0);
    online_inputs.push(input.clone().1.as_jubjub_point().get_x());
    online_inputs.push(input.clone().1.as_jubjub_point().get_y());
    online_inputs.push(merkle_root.clone());

    let proof_zk_part = proof.commitment_eq_proof;

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
        &proof.spending_proof,
    )
}

fn prove_abar_to_bar_spending<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &UserParams,
    payers_secret: PayerSecret,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
) -> Result<Abar2BarPlonkProof> {
    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_bar_cs(payers_secret, proof, non_zk_state, beta);
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

///
///        Constraint System for abar_to_bar
///
///
pub fn build_abar_to_bar_cs(
    payers_secret: PayerSecret,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();
    let payers_secrets = add_payers_secret(&mut cs, payers_secret);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from_u64(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;
    let step_1 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB));
    let step_2 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 2));
    let step_3 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 3));
    let step_4 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 4));
    let step_5 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 5));

    // prove knowledge of payer's secret key: pk = base^{sk}
    let (pk_var, pk_point) = cs.scalar_mul(base, payers_secrets.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();
    let pk_y = pk_var.get_y();

    // prove knowledge of diversifier: pk_sign = pk^{diversifier}
    let (pk_sign_var, _) =
        cs.var_base_scalar_mul(pk_var, pk_point, payers_secrets.diversifier, SK_LEN);

    // commitments
    let com_abar_in_var = commit(
        &mut cs,
        payers_secrets.blind,
        payers_secrets.amount,
        payers_secrets.asset_type,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_secrets.uid,
            payers_secrets.amount,
            zero_var,
            zero_var,
        ],
        pow_2_64,
        one,
        zero,
        zero,
    );
    let nullifier_input_vars = NullifierInputVars {
        uid_amount,
        asset_type: payers_secrets.asset_type,
        pub_key_x: pk_x,
        pub_key_y: pk_y,
    };
    let nullifier_var = nullify(&mut cs, payers_secrets.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_secrets.uid,
        commitment: com_abar_in_var,
        pub_key_x: pk_x,
        pub_key_y: pk_y,
    };
    let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payers_secrets.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // 2. Input witness x, y, a, b, r, public input comm, beta, s1, s2
    let x_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.x.to_bytes()));
    let y_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.y.to_bytes()));
    let a_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.a.to_bytes()));
    let b_sim_fr = SimFr::from(&BigUint::from_bytes_le(&non_zk_state.b.to_bytes()));
    let comm = proof.non_zk_part_state_commitment;
    let r = non_zk_state.r;
    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let s1_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof.s_1.to_bytes()));
    let s2_sim_fr = SimFr::from(&BigUint::from_bytes_le(&proof.s_2.to_bytes()));

    let x_sim_fr_var =
        SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &x_sim_fr, 64);
    let y_sim_fr_var =
        SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &y_sim_fr, 240);
    let a_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &a_sim_fr);
    let b_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &b_sim_fr);
    let comm_var = cs.new_variable(comm);
    let r_var = cs.new_variable(r);
    let beta_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &beta_sim_fr);
    let s1_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &s1_sim_fr);
    let s2_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &s2_sim_fr);

    // 3. Merge the limbs for x, y, a, b
    let mut all_limbs = Vec::with_capacity(4 * NUM_OF_LIMBS);
    all_limbs.extend_from_slice(&x_sim_fr.limbs);
    all_limbs.extend_from_slice(&y_sim_fr.limbs);
    all_limbs.extend_from_slice(&a_sim_fr.limbs);
    all_limbs.extend_from_slice(&b_sim_fr.limbs);

    let mut all_limbs_var = Vec::with_capacity(4 * NUM_OF_LIMBS);
    all_limbs_var.extend_from_slice(&x_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&y_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&a_sim_fr_var.var);
    all_limbs_var.extend_from_slice(&b_sim_fr_var.var);

    let mut compressed_limbs = Vec::with_capacity(5);
    let mut compressed_limbs_var = Vec::with_capacity(5);
    for (limbs, limbs_var) in all_limbs.chunks(5).zip(all_limbs_var.chunks(5)) {
        let mut sum = BigUint::zero();
        for (i, limb) in limbs.iter().enumerate() {
            sum.add_assign(
                <&BLSScalar as Into<BigUint>>::into(limb).shl(BIT_PER_LIMB * i),
            );
        }
        compressed_limbs.push(BLSScalar::from(&sum));

        let mut sum_var = {
            let first_var = *limbs_var.get(0).unwrap_or(&zero_var);
            let second_var = *limbs_var.get(1).unwrap_or(&zero_var);
            let third_var = *limbs_var.get(2).unwrap_or(&zero_var);
            let fourth_var = *limbs_var.get(3).unwrap_or(&zero_var);

            cs.linear_combine(
                &[first_var, second_var, third_var, fourth_var],
                one,
                step_1,
                step_2,
                step_3,
            )
        };

        if limbs.len() == 5 {
            let fifth_var = *limbs_var.get(4).unwrap_or(&zero_var);
            sum_var = cs.linear_combine(
                &[sum_var, fifth_var, zero_var, zero_var],
                one,
                step_4,
                zero,
                zero,
            );
        }

        compressed_limbs_var.push(sum_var);
    }

    // 4. Open the non-ZK verifier state
    {
        let h1_var = cs.rescue_hash(&StateVar::new([
            compressed_limbs_var[0],
            compressed_limbs_var[1],
            compressed_limbs_var[2],
            compressed_limbs_var[3],
        ]))[0];

        let h2_var = cs.rescue_hash(&StateVar::new([
            h1_var,
            compressed_limbs_var[4],
            r_var,
            zero_var,
        ]))[0];
        cs.equal(h2_var, comm_var);
    }

    // 5. Perform the check in field simulation
    {
        let beta_x_sim_fr_mul_var = beta_sim_fr_var.mul(&mut cs, &x_sim_fr_var);
        let beta_y_sim_fr_mul_var = beta_sim_fr_var.mul(&mut cs, &y_sim_fr_var);

        let s_1_minus_a_sim_fr_var = s1_sim_fr_var.sub(&mut cs, &a_sim_fr_var);
        let s_2_minus_b_sim_fr_var = s2_sim_fr_var.sub(&mut cs, &b_sim_fr_var);

        let first_eqn = beta_x_sim_fr_mul_var.sub(&mut cs, &s_1_minus_a_sim_fr_var);
        let second_eqn = beta_y_sim_fr_mul_var.sub(&mut cs, &s_2_minus_b_sim_fr_var);

        first_eqn.enforce_zero(&mut cs);
        second_eqn.enforce_zero(&mut cs);
    }

    // 6. Check x = amount_var and y = at_var
    {
        let mut x_in_bls12_381 = cs.linear_combine(
            &[
                x_sim_fr_var.var[0],
                x_sim_fr_var.var[1],
                x_sim_fr_var.var[2],
                x_sim_fr_var.var[3],
            ],
            one,
            step_1,
            step_2,
            step_3,
        );
        x_in_bls12_381 = cs.linear_combine(
            &[
                x_in_bls12_381,
                x_sim_fr_var.var[4],
                x_sim_fr_var.var[5],
                zero_var,
            ],
            one,
            step_4,
            step_5,
            zero,
        );

        let mut y_in_bls12_381 = cs.linear_combine(
            &[
                y_sim_fr_var.var[0],
                y_sim_fr_var.var[1],
                y_sim_fr_var.var[2],
                y_sim_fr_var.var[3],
            ],
            one,
            step_1,
            step_2,
            step_3,
        );
        y_in_bls12_381 = cs.linear_combine(
            &[
                y_in_bls12_381,
                y_sim_fr_var.var[4],
                y_sim_fr_var.var[5],
                zero_var,
            ],
            one,
            step_4,
            step_5,
            zero,
        );

        cs.equal(x_in_bls12_381, payers_secrets.amount);
        cs.equal(y_in_bls12_381, payers_secrets.asset_type);
    }

    // prepare public inputs variables
    cs.prepare_io_variable(nullifier_var);
    cs.prepare_io_point_variable(pk_sign_var);

    // prepare the public input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_io_variable(comm_var);

    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(beta_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(s1_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_io_variable(s2_sim_fr_var.var[i]);
    }

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

fn add_payers_secret(cs: &mut TurboPlonkCS, secret: PayerSecret) -> PayerSecretVars {
    let bls_sk = BLSScalar::from(&secret.sec_key);
    let bls_diversifier = BLSScalar::from(&secret.diversifier);
    let sec_key = cs.new_variable(bls_sk);
    let diversifier = cs.new_variable(bls_diversifier);
    let uid = cs.new_variable(BLSScalar::from_u64(secret.uid));
    let amount = cs.new_variable(BLSScalar::from_u64(secret.amount));
    let blind = cs.new_variable(secret.blind);
    let path = add_merkle_path_variables(cs, secret.path.clone());
    let asset_type = cs.new_variable(secret.asset_type);
    PayerSecretVars {
        sec_key,
        diversifier,
        uid,
        amount,
        asset_type,
        path,
        blind,
    }
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::abar_to_bar::{gen_abar_to_bar_body, verify_abar_to_bar_body};
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{
        AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath,
        OpenAnonBlindAssetRecordBuilder,
    };
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::asset_record::AssetRecordType::ConfidentialAmount_ConfidentialAssetType;
    use crate::xfr::sig::XfrKeyPair;
    use crate::xfr::structs::AssetType;
    use accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath, TREE_DEPTH};
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::{Scalar, Zero};
    use crypto::basics::hash::rescue::RescueInstance;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::sync::Arc;
    use std::thread;
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;

    #[test]
    fn test_abar_to_bar_conversion() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = UserParams::abar_to_bar_params(TREE_DEPTH).unwrap();

        let recv = XfrKeyPair::generate(&mut prng);
        let sender = AXfrKeyPair::generate(&mut prng);
        let sender_dec_key = XSecretKey::new(&mut prng);

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "test_abar_to_bar_conversion_db".to_string(),
            0,
        )));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonBlindAssetRecordBuilder::new()
            .pub_key(sender.pub_key())
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .finalize(&mut prng, &XPublicKey::from(&sender_dec_key))
            .unwrap()
            .build()
            .unwrap();

        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();

        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone()));

        let (body, _) = gen_abar_to_bar_body(
            &mut prng,
            &params,
            &oabar.clone(),
            &sender,
            &recv.pub_key,
            ConfidentialAmount_ConfidentialAssetType,
        )
        .unwrap();

        let node_params = NodeParams::abar_to_bar_params().unwrap();
        verify_abar_to_bar_body(&node_params, &body, &proof.root).unwrap();

        assert!(verify_abar_to_bar_body(
            &node_params,
            &body,
            &BLSScalar::random(&mut prng),
        )
        .is_err());

        let mut body_wrong_nullifier = body.clone();
        body_wrong_nullifier.input.0 = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_bar_body(
            &node_params,
            &body_wrong_nullifier,
            &proof.root,
        )
        .is_err());

        let mut body_wrong_pubkey = body.clone();
        body_wrong_pubkey.input.1 = AXfrKeyPair::generate(&mut prng).pub_key();
        assert!(
            verify_abar_to_bar_body(&node_params, &body_wrong_pubkey, &proof.root)
                .is_err()
        );
    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();

        let pk_hash = hash.rescue_hash(&[
            abar.public_key.0.point_ref().get_x(),
            abar.public_key.0.point_ref().get_y(),
            BLSScalar::zero(),
            BLSScalar::zero(),
        ])[0];

        hash.rescue_hash(&[
            BLSScalar::from_u64(uid),
            abar.amount_type_commitment,
            pk_hash,
            BLSScalar::zero(),
        ])[0]
    }

    fn build_mt_leaf_info_from_proof(proof: Proof) -> MTLeafInfo {
        return MTLeafInfo {
            path: MTPath {
                nodes: proof
                    .nodes
                    .iter()
                    .map(|e| MTNode {
                        siblings1: e.siblings1,
                        siblings2: e.siblings2,
                        is_left_child: (e.path == TreePath::Left) as u8,
                        is_right_child: (e.path == TreePath::Right) as u8,
                    })
                    .collect(),
            },
            root: proof.root,
            root_version: proof.root_version,
            uid: 0,
        };
    }
}
