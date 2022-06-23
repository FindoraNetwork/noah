use crate::anon_xfr::structs::{
    AXfrKeyPair, AccElemVars, NullifierInputVars, PayerSecret, PayerSecretVars,
};
use crate::anon_xfr::{
    add_merkle_path_variables, commit_with_native_address, compute_merkle_root,
    compute_non_malleability_tag, nullifier, nullify_with_native_address,
    structs::{Nullifier, OpenAnonBlindAssetRecord},
    TurboPlonkCS,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::{build_open_asset_record, AssetRecordType},
    sig::XfrPublicKey,
    structs::{AssetRecordTemplate, BlindAssetRecord, OwnerMemo, XfrAmount, XfrAssetType},
};
use digest::Digest;
use merlin::Transcript;
use num_bigint::BigUint;
use sha2::Sha512;
use zei_algebra::{
    bls12_381::BLSScalar, jubjub::JubjubPoint, prelude::*, ristretto::RistrettoScalar,
};
use zei_crypto::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;
use zei_crypto::{
    delegated_chaum_pedersen::{
        prove_delegated_chaum_pedersen, verify_delegated_chaum_pedersen, NonZKState, ZKPartProof,
    },
    field_simulation::{SimFr, BIT_PER_LIMB, NUM_OF_LIMBS},
};
use zei_plonk::{
    plonk::{
        constraint_system::{field_simulation::SimFrVar, rescue::StateVar, TurboCS, VarIndex},
        indexer::PlonkPf,
        prover::prover_with_lagrange,
        verifier::verifier,
    },
    poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS,
};

pub type Abar2BarPlonkProof = PlonkPf<KZGCommitmentSchemeBLS>;
pub const TWO_POW_32: u64 = 1 << 32;
const ABAR_TO_BAR_TRANSCRIPT: &[u8] = b"ABAR to BAR proof";
const SK_LEN: usize = 252;

/// ConvertAbarBarProof is a struct to hold various aspects of a ZKP to prove equality, spendability
/// and conversion of an ABAR to a BAR on the chain.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertAbarBarProof {
    commitment_eq_proof: ZKPartProof,
    spending_proof: Abar2BarPlonkProof,
    merkle_root: BLSScalar,
    merkle_root_version: u64,
}

impl ConvertAbarBarProof {
    #[allow(dead_code)]
    pub fn get_merkle_root_version(&self) -> u64 {
        return self.merkle_root_version;
    }
}

/// AbarToBarNote has the input, the output and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarNote {
    /// The body part of ABAR to BAR
    pub body: AbarToBarBody,
    /// The spending proof (assuming non-malleability)
    pub spending_proof: Abar2BarPlonkProof,
    /// The non-malleability tag
    pub non_malleability_tag: BLSScalar,
}

/// AbarToBarNote has the input, the output and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarBody {
    /// input ABAR being spent
    pub input: Nullifier,
    /// The new BAR to be created
    pub output: BlindAssetRecord,
    /// The ZK part of commitment equality proof
    pub commitment_eq_proof: ZKPartProof,
    /// The Merkle root hash
    pub merkle_root: BLSScalar,
    /// The Merkle root version
    pub merkle_root_version: u64,
    /// The owner memo
    pub memo: Option<OwnerMemo>,
}

/// This function generates the AbarToBarBody from the Open ABARs, the receiver address and the signing
/// key pair.
#[allow(dead_code)]
pub fn gen_abar_to_bar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    oabar: &OpenAnonBlindAssetRecord,
    abar_keypair: &AXfrKeyPair,
    bar_pub_key: &XfrPublicKey,
    asset_record_type: AssetRecordType,
) -> Result<AbarToBarNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.pub_key() != oabar.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    let obar_amount = oabar.amount;
    let obar_type = oabar.asset_type;

    let pc_gens = RistrettoPedersenCommitment::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        obar_amount,
        obar_type,
        asset_record_type,
        bar_pub_key.clone(),
    );
    let (obar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    // 2. build input witness info
    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let this_nullifier = nullifier(
        &abar_keypair,
        oabar.amount,
        &oabar.asset_type,
        mt_leaf_info.uid,
    );

    // 3. Construct the equality proof
    let x = RistrettoScalar::from(oabar.amount);
    let y: RistrettoScalar = oabar.asset_type.as_scalar();
    let gamma = obar
        .amount_blinds
        .0
        .add(&obar.amount_blinds.1.mul(&RistrettoScalar::from(TWO_POW_32)));
    let delta = obar.type_blind;

    let pc_gens = RistrettoPedersenCommitment::default();

    let point_p = pc_gens.commit(x, gamma);
    let point_q = pc_gens.commit(y, delta);

    // 4. compute the non-ZK part of the proof
    let (commitment_eq_proof, non_zk_state, beta, lambda) = prove_delegated_chaum_pedersen(
        prng,
        &x,
        &gamma,
        &y,
        &delta,
        &pc_gens,
        &point_p,
        &point_q,
        &this_nullifier,
    )
    .c(d!())?;

    // 5. build the plonk proof
    let payers_secret = PayerSecret {
        sec_key: abar_keypair.get_secret_scalar(),
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();

    let body = AbarToBarBody {
        input: this_nullifier,
        output: obar.blind_asset_record.clone(),
        commitment_eq_proof: commitment_eq_proof.clone(),
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        memo: owner_memo,
    };

    let msg = bincode::serialize(&body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;

    let (hash, non_malleability_randomizer, non_malleability_tag) =
        compute_non_malleability_tag(prng, b"AbarToBar", &msg, &[&abar_keypair]);

    let spending_proof = prove_abar_to_bar_spending(
        prng,
        params,
        payers_secret,
        &commitment_eq_proof,
        &non_zk_state,
        &beta,
        &lambda,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
    )
    .c(d!())?;

    Ok(AbarToBarNote {
        body,
        spending_proof,
        non_malleability_tag,
    })
}

// Verifies the body
#[allow(dead_code)]
pub fn verify_abar_to_bar_note(
    params: &VerifierParams,
    note: &AbarToBarNote,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let bar = note.body.output.clone();
    let pc_gens = RistrettoPedersenCommitment::default();

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
            let (l, h) = u64_to_u32_pair(amount);
            (
                pc_gens.commit(RistrettoScalar::from(l), RistrettoScalar::zero()),
                pc_gens.commit(RistrettoScalar::from(h), RistrettoScalar::zero()),
            )
        }
    };

    // 1.2 get asset type commitment
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(ZeiError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // fake commitment
            pc_gens.commit(a.as_scalar(), RistrettoScalar::zero())
        }
    };

    let input = note.body.input;

    // 2. verify equality of committed values
    let (beta, lambda) = verify_delegated_chaum_pedersen(
        &pc_gens,
        &com_amount,
        &com_asset_type,
        &input,
        &note.body.commitment_eq_proof,
    )
    .c(d!())?;

    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);
    let mut online_inputs = vec![];

    online_inputs.push(input.clone());
    online_inputs.push(merkle_root.clone());

    let proof_zk_part = note.body.commitment_eq_proof.clone();

    let beta_lambda = beta * &lambda;
    let s1_plus_lambda_s2 = proof_zk_part.s_1 + proof_zk_part.s_2 * &lambda;

    online_inputs.push(proof_zk_part.non_zk_part_state_commitment);
    let beta_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta.to_bytes()));
    let lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&lambda.to_bytes()));
    let beta_lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));
    let s1_plus_lambda_s2_sim_fr =
        SimFr::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));
    online_inputs.extend_from_slice(&beta_sim_fr.limbs);
    online_inputs.extend_from_slice(&lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&beta_lambda_sim_fr.limbs);
    online_inputs.extend_from_slice(&s1_plus_lambda_s2_sim_fr.limbs);

    let msg = bincode::serialize(&note.body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;
    let mut hasher = Sha512::new();
    hasher.update(b"AbarToBar");
    hasher.update(msg);
    let hash = BLSScalar::from_hash(hasher);
    online_inputs.push(hash);
    online_inputs.push(note.non_malleability_tag);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &note.spending_proof,
    )
}

fn prove_abar_to_bar_spending<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_secret: PayerSecret,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<Abar2BarPlonkProof> {
    let mut transcript = Transcript::new(ABAR_TO_BAR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_bar_cs(
        payers_secret,
        proof,
        non_zk_state,
        beta,
        lambda,
        hash,
        non_malleability_randomizer,
        non_malleability_tag,
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

///
///        Constraint System for abar_to_bar
///
///
pub fn build_abar_to_bar_cs(
    payers_secret: PayerSecret,
    proof: &ZKPartProof,
    non_zk_state: &NonZKState,
    beta: &RistrettoScalar,
    lambda: &RistrettoScalar,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();
    let payers_secrets = add_payers_secret(&mut cs, payers_secret);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let one_var = cs.one_var();
    let mut root_var: Option<VarIndex> = None;
    let step_1 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB));
    let step_2 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 2));
    let step_3 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 3));
    let step_4 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 4));
    let step_5 = BLSScalar::from(&BigUint::one().shl(BIT_PER_LIMB * 5));

    let hash_var = cs.new_variable(*hash);
    let non_malleability_randomizer_var = cs.new_variable(*non_malleability_randomizer);
    let non_malleability_tag_var = cs.new_variable(*non_malleability_tag);

    // prove knowledge of payer's secret key: pk = base^{sk}
    let pk_var = cs.scalar_mul(base, payers_secrets.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();

    // commitments
    let com_abar_in_var = commit_with_native_address(
        &mut cs,
        payers_secrets.blind,
        payers_secrets.amount,
        payers_secrets.asset_type,
        pk_x,
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
    };

    let nullifier_var =
        nullify_with_native_address(&mut cs, payers_secrets.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_secrets.uid,
        commitment: com_abar_in_var,
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
    let lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&lambda.to_bytes()));

    let beta_lambda = *beta * lambda;
    let beta_lambda_sim_fr = SimFr::from(&BigUint::from_bytes_le(&beta_lambda.to_bytes()));

    let s1_plus_lambda_s2 = proof.s_1 + proof.s_2 * lambda;
    let s1_plus_lambda_s2_sim_fr =
        SimFr::from(&BigUint::from_bytes_le(&s1_plus_lambda_s2.to_bytes()));

    let x_sim_fr_var = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &x_sim_fr, 64);
    let y_sim_fr_var = SimFrVar::alloc_witness_bounded_total_bits(&mut cs, &y_sim_fr, 240);
    let a_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &a_sim_fr);
    let b_sim_fr_var = SimFrVar::alloc_witness(&mut cs, &b_sim_fr);
    let comm_var = cs.new_variable(comm);
    let r_var = cs.new_variable(r);
    let beta_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_sim_fr);
    let lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &lambda_sim_fr);
    let beta_lambda_sim_fr_var = SimFrVar::alloc_input(&mut cs, &beta_lambda_sim_fr);
    let s1_plus_lambda_s2_sim_fr_var = SimFrVar::alloc_input(&mut cs, &s1_plus_lambda_s2_sim_fr);

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
            sum.add_assign(<&BLSScalar as Into<BigUint>>::into(limb).shl(BIT_PER_LIMB * i));
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
        let beta_lambda_y_sim_fr_mul_var = beta_lambda_sim_fr_var.mul(&mut cs, &y_sim_fr_var);
        let lambda_b_sim_fr_mul_var = lambda_sim_fr_var.mul(&mut cs, &b_sim_fr_var);

        let mut rhs = beta_x_sim_fr_mul_var.add(&mut cs, &beta_lambda_y_sim_fr_mul_var);
        rhs = rhs.add(&mut cs, &lambda_b_sim_fr_mul_var);

        let s1_plus_lambda_s2_minus_a_sim_fr_var =
            s1_plus_lambda_s2_sim_fr_var.sub(&mut cs, &a_sim_fr_var);

        let eqn = rhs.sub(&mut cs, &s1_plus_lambda_s2_minus_a_sim_fr_var);
        eqn.enforce_zero(&mut cs);
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

    // 7. Check the validity of the non malleability tag.
    {
        let non_malleability_tag_var_supposed = cs.rescue_hash(&StateVar::new([
            one_var,
            hash_var,
            non_malleability_randomizer_var,
            payers_secrets.sec_key,
        ]))[0];

        cs.equal(non_malleability_tag_var_supposed, non_malleability_tag_var);
    }

    // prepare public inputs variables
    cs.prepare_pi_variable(nullifier_var);

    // prepare the public input for merkle_root
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_pi_variable(comm_var);

    for i in 0..NUM_OF_LIMBS {
        cs.prepare_pi_variable(beta_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_pi_variable(lambda_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_pi_variable(beta_lambda_sim_fr_var.var[i]);
    }
    for i in 0..NUM_OF_LIMBS {
        cs.prepare_pi_variable(s1_plus_lambda_s2_sim_fr_var.var[i]);
    }

    cs.prepare_pi_variable(hash_var);
    cs.prepare_pi_variable(non_malleability_tag_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

fn add_payers_secret(cs: &mut TurboPlonkCS, secret: PayerSecret) -> PayerSecretVars {
    let bls_sk = BLSScalar::from(&secret.sec_key);
    let sec_key = cs.new_variable(bls_sk);
    let uid = cs.new_variable(BLSScalar::from(secret.uid));
    let amount = cs.new_variable(BLSScalar::from(secret.amount));
    let blind = cs.new_variable(secret.blind);
    let path = add_merkle_path_variables(cs, secret.path.clone());
    let asset_type = cs.new_variable(secret.asset_type);
    PayerSecretVars {
        sec_key,
        uid,
        amount,
        asset_type,
        path,
        blind,
    }
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::structs::AXfrKeyPair;
    use crate::anon_xfr::{
        abar_to_bar::{gen_abar_to_bar_note, verify_abar_to_bar_note},
        structs::{
            AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecordBuilder,
        },
        TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::{
        asset_record::AssetRecordType::ConfidentialAmount_ConfidentialAssetType, sig::XfrKeyPair,
        structs::AssetType,
    };
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use std::{sync::Arc, thread};
    use storage::{
        db::TempRocksDB,
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, traits::Scalar, Zero};
    use zei_crypto::basic::hybrid_encryption::{XPublicKey, XSecretKey};
    use zei_crypto::basic::rescue::RescueInstance;

    #[test]
    fn test_abar_to_bar_conversion() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = ProverParams::abar_to_bar_params(TREE_DEPTH).unwrap();

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

        let note = gen_abar_to_bar_note(
            &mut prng,
            &params,
            &oabar.clone(),
            &sender,
            &recv.pub_key,
            ConfidentialAmount_ConfidentialAssetType,
        )
        .unwrap();

        let node_params = VerifierParams::abar_to_bar_params().unwrap();
        verify_abar_to_bar_note(&node_params, &note, &proof.root).unwrap();

        assert!(
            verify_abar_to_bar_note(&node_params, &note, &BLSScalar::random(&mut prng),).is_err()
        );

        let mut note_wrong_nullifier = note.clone();
        note_wrong_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(
            verify_abar_to_bar_note(&node_params, &note_wrong_nullifier, &proof.root,).is_err()
        );
    }

    fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
        let hash = RescueInstance::new();
        hash.rescue(&[
            BLSScalar::from(uid),
            abar.commitment,
            BLSScalar::zero(),
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
