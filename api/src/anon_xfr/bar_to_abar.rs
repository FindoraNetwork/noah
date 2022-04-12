use crate::anon_xfr::{
    circuits::build_eq_committed_vals_cs,
    keys::AXfrPubKey,
    proofs::AXfrPlonkPf,
    structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder},
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    sig::{XfrKeyPair, XfrPublicKey, XfrSignature},
    structs::{BlindAssetRecord, OpenAssetRecord, OwnerMemo, XfrAmount, XfrAssetType},
};
use merlin::Transcript;
use num_bigint::BigUint;
use zei_algebra::{bls12_381::BLSScalar, prelude::*, ristretto::RistrettoScalar};
use zei_crypto::basic::rescue::RescueInstance;
use zei_crypto::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;
use zei_crypto::{
    basic::hybrid_encryption::XPublicKey,
    field_simulation::{SimFr, NUM_OF_LIMBS},
    pc_eq_rescue_split_verifier_zk_part::{
        prove_pc_eq_rescue_external, verify_pc_eq_rescue_external, NonZKState, ZKPartProof,
    },
};
use zei_plonk::plonk::{prover::prover_with_lagrange, verifier::verifier};

const EQ_COMM_TRANSCRIPT: &[u8] = b"Equal committed values proof";
pub const TWO_POW_32: u64 = 1 << 32;

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertBarAbarProof {
    commitment_eq_proof: ZKPartProof,
    pc_rescue_commitments_eq_proof: AXfrPlonkPf,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarBody {
    pub input: BlindAssetRecord,
    pub output: AnonBlindAssetRecord,
    pub proof: ConvertBarAbarProof,
    pub memo: OwnerMemo,
}

#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct BarToAbarNote {
    pub body: BarToAbarBody,
    pub signature: XfrSignature,
}

/// Generate Bar To Abar conversion note body
/// Returns note Body and ABAR opening keys
pub fn gen_bar_to_abar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<BarToAbarBody> {
    let (open_abar, proof) = bar_to_abar(prng, params, record, abar_pubkey, enc_key).c(d!())?;
    let body = BarToAbarBody {
        input: record.blind_asset_record.clone(),
        output: AnonBlindAssetRecord::from_oabar(&open_abar),
        proof,
        memo: open_abar.owner_memo.unwrap(),
    };
    Ok(body)
}

/// Generate BlindAssetRecord To AnonymousBlindAssetRecord conversion note: body + spending input signature
/// Returns conversion note and output AnonymousBlindAssetRecord opening keys
pub fn gen_bar_to_abar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    record: &OpenAssetRecord,
    bar_keypair: &XfrKeyPair,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<BarToAbarNote> {
    let body = gen_bar_to_abar_body(prng, params, record, &abar_pubkey, enc_key).c(d!())?;
    let msg = bincode::serialize(&body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;
    let signature = bar_keypair.sign(&msg);
    let note = BarToAbarNote { body, signature };
    Ok(note)
}

/// Verifies BlindAssetRecord To AnonymousBlindAssetRecord conversion body
/// Warning: This function doesn't check that input owner has signed the body
pub fn verify_bar_to_abar_body(params: &VerifierParams, body: &BarToAbarBody) -> Result<()> {
    verify_bar_to_abar(params, &body.input, &body.output, &body.proof).c(d!())
}

/// Verifies BlindAssetRecord To AnonymousBlindAssetRecord conversion note by verifying proof of conversion
/// and signature by input owner key
pub fn verify_bar_to_abar_note(
    params: &VerifierParams,
    note: &BarToAbarNote,
    bar_pub_key: &XfrPublicKey,
) -> Result<()> {
    verify_bar_to_abar_body(params, &note.body).c(d!())?;
    let msg = bincode::serialize(&note.body).c(d!(ZeiError::SerializationError))?;
    bar_pub_key.verify(&msg, &note.signature).c(d!())
}

pub(crate) fn bar_to_abar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    obar: &OpenAssetRecord,
    abar_pubkey: &AXfrPubKey,
    enc_key: &XPublicKey,
) -> Result<(OpenAnonBlindAssetRecord, ConvertBarAbarProof)> {
    let oabar_amount = obar.amount;

    let pc_gens = RistrettoPedersenCommitment::default();

    // 1. Construct ABAR.
    let oabar = OpenAnonBlindAssetRecordBuilder::new()
        .amount(oabar_amount)
        .asset_type(obar.asset_type)
        .pub_key(*abar_pubkey)
        .finalize(prng, &enc_key)
        .c(d!())?
        .build()
        .c(d!())?;

    // 2. Reconstruct the points.
    let x = RistrettoScalar::from(oabar_amount);
    let y: RistrettoScalar = obar.asset_type.as_scalar();
    let gamma = obar
        .amount_blinds
        .0
        .add(&obar.amount_blinds.1.mul(&RistrettoScalar::from(TWO_POW_32)));
    let delta = obar.type_blind;
    let point_p = pc_gens.commit(x, gamma);
    let point_q = pc_gens.commit(y, delta);

    let z_randomizer = oabar.blind;
    let z_instance = RescueInstance::<BLSScalar>::new();

    let x_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&x.to_bytes()));
    let y_in_bls12_381 = BLSScalar::from(&BigUint::from_bytes_le(&y.to_bytes()));

    let z = z_instance.rescue(&[
        z_randomizer,
        x_in_bls12_381,
        y_in_bls12_381,
        abar_pubkey.0.point_ref().get_x(),
    ])[0];

    // 3. compute the non-ZK part of the proof
    let (commitment_eq_proof, non_zk_state, beta, lambda) = prove_pc_eq_rescue_external(
        prng, &x, &gamma, &y, &delta, &pc_gens, &point_p, &point_q, &z,
    )
    .c(d!())?;

    println!("beta = {:?}, lambda = {:?}", beta, lambda);

    // 4. prove abar correctness
    let pc_rescue_commitments_eq_proof = prove_eq_committed_vals(
        prng,
        params,
        x_in_bls12_381,
        y_in_bls12_381,
        oabar.blind,
        abar_pubkey.0.point_ref().get_x(),
        &commitment_eq_proof,
        &non_zk_state,
        &beta,
        &lambda,
    )
    .c(d!())?;

    Ok((
        oabar,
        ConvertBarAbarProof {
            commitment_eq_proof,
            pc_rescue_commitments_eq_proof,
        },
    ))
}

pub(crate) fn verify_bar_to_abar(
    params: &VerifierParams,
    bar: &BlindAssetRecord,
    abar: &AnonBlindAssetRecord,
    proof: &ConvertBarAbarProof,
) -> Result<()> {
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

    // 2. verify equality of committed values
    let (beta, lambda) = verify_pc_eq_rescue_external(
        &pc_gens,
        &com_amount,
        &com_asset_type,
        &abar.commitment,
        &proof.commitment_eq_proof,
    )
    .c(d!())?;

    println!("beta = {:?}, lambda = {:?}", beta, lambda);

    // 3. verify PLONK proof
    verify_eq_committed_vals(
        params,
        abar.commitment,
        &proof.commitment_eq_proof,
        &proof.pc_rescue_commitments_eq_proof,
        &beta,
        &lambda,
    )
    .c(d!())
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
mod test {
    use crate::anon_xfr::{
        bar_to_abar::{gen_bar_to_abar_note, verify_bar_to_abar_note},
        keys::AXfrKeyPair,
        structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder},
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::{
        asset_record::{build_blind_asset_record, open_blind_asset_record, AssetRecordType},
        sig::{XfrKeyPair, XfrPublicKey},
        structs::{AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo},
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use zei_crypto::basic::hybrid_encryption::{XPublicKey, XSecretKey};
    use zei_crypto::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;

    // helper function
    fn build_bar(
        pubkey: &XfrPublicKey,
        prng: &mut ChaChaRng,
        pc_gens: &RistrettoPedersenCommitment,
        amt: u64,
        asset_type: AssetType,
        ar_type: AssetRecordType,
    ) -> (BlindAssetRecord, Option<OwnerMemo>) {
        let ar = AssetRecordTemplate::with_no_asset_tracing(amt, asset_type, ar_type, *pubkey);
        let (bar, _, memo) = build_blind_asset_record(prng, &pc_gens, &ar, vec![]);
        (bar, memo)
    }

    #[test]
    fn test_bar_to_abar() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = RistrettoPedersenCommitment::default();
        let bar_keypair = XfrKeyPair::generate(&mut prng);
        let abar_keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        // proving
        let params = ProverParams::eq_committed_vals_params().unwrap();
        // confidential case
        let (bar_conf, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            10u64,
            AssetType::from_identical_byte(1u8),
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar_conf, &memo, &bar_keypair).unwrap();
        let (oabar_conf, proof_conf) =
            super::bar_to_abar(&mut prng, &params, &obar, &abar_keypair.pub_key(), &enc_key)
                .unwrap();
        let abar_conf = AnonBlindAssetRecord::from_oabar(&oabar_conf);
        // non confidential case
        let (bar_non_conf, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            10u64,
            AssetType::from_identical_byte(1u8),
            AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar_non_conf, &memo, &bar_keypair).unwrap();
        let (oabar_non_conf, proof_non_conf) =
            super::bar_to_abar(&mut prng, &params, &obar, &abar_keypair.pub_key(), &enc_key)
                .unwrap();
        let abar_non_conf = AnonBlindAssetRecord::from_oabar(&oabar_non_conf);

        // verifications
        let node_params = VerifierParams::bar_to_abar_params().unwrap();
        // confidential case
        assert!(
            super::verify_bar_to_abar(&node_params, &bar_conf, &abar_conf, &proof_conf).is_ok()
        );
        // non confidential case
        assert!(super::verify_bar_to_abar(
            &node_params,
            &bar_non_conf,
            &abar_non_conf,
            &proof_non_conf,
        )
        .is_ok());
    }

    #[test]
    fn test_bar_to_abar_xfr_note() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let bar_keypair = XfrKeyPair::generate(&mut prng);
        let abar_keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        let pc_gens = RistrettoPedersenCommitment::default();
        let amount = 10;
        let asset_type = AssetType::from_identical_byte(1u8);
        let (bar, memo) = build_bar(
            &bar_keypair.pub_key,
            &mut prng,
            &pc_gens,
            amount,
            asset_type,
            AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
        );
        let obar = open_blind_asset_record(&bar, &memo, &bar_keypair).unwrap();
        let params = ProverParams::eq_committed_vals_params().unwrap();
        let note = gen_bar_to_abar_note(
            &mut prng,
            &params,
            &obar,
            &bar_keypair,
            &abar_keypair.pub_key(),
            &enc_key,
        )
        .unwrap();

        // 1. check that abar_keypair opens the note
        let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
            &note.body.output,
            note.body.memo.clone(),
            &abar_keypair,
            &dec_key,
        )
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(oabar.amount, amount);
        assert_eq!(oabar.asset_type, asset_type);

        let node_params = VerifierParams::from(params);
        assert!(verify_bar_to_abar_note(&node_params, &note, &bar_keypair.pub_key).is_ok());

        let mut note = note;
        let message = b"anymesage";
        let bad_sig = bar_keypair.sign(message);
        note.signature = bad_sig;
        assert!(verify_bar_to_abar_note(&node_params, &note, &bar_keypair.pub_key).is_err())
    }
}
