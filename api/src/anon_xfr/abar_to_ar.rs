use crate::anon_xfr::{
    abar_to_abar::add_payers_witnesses,
    commit_in_cs, compute_merkle_root_variables, compute_non_malleability_tag,
    keys::{get_view_key_domain_separator, AXfrKeyPair},
    nullify, nullify_in_cs,
    structs::{AccElemVars, Nullifier, NullifierInputVars, OpenAnonAssetRecord, PayerWitness},
    AXfrPlonkPf, TurboPlonkCS, SK_LEN,
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::{
        build_open_asset_record, AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
    },
    sig::XfrPublicKey,
    structs::{AssetRecordTemplate, BlindAssetRecord, OwnerMemo},
};
use digest::{consts::U64, Digest};
use merlin::Transcript;
use zei_algebra::{bls12_381::BLSScalar, jubjub::JubjubPoint, prelude::*};
use zei_crypto::basic::pedersen_comm::PedersenCommitmentRistretto;
use zei_plonk::plonk::{
    constraint_system::{rescue::StateVar, TurboCS, VarIndex},
    prover::prover_with_lagrange,
    verifier::verifier,
};

const ABAR_TO_AR_TRANSCRIPT: &[u8] = b"ABAR to AR proof";

/// The anonymous-to-transparent note.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArNote {
    /// The body part of ABAR to AR.
    pub body: AbarToArBody,
    /// The spending proof (assuming non-malleability).
    pub proof: AXfrPlonkPf,
    /// The non-malleability tag.
    pub non_malleability_tag: BLSScalar,
}

/// The anonymous-to-transparent note without proof or non-malleability tag.
#[derive(Clone, Debug)]
pub struct AbarToArPreNote {
    /// The body part of ABAR to AR.
    pub body: AbarToArBody,
    /// Witness.
    pub witness: PayerWitness,
    /// Input key pair.
    pub input_keypair: AXfrKeyPair,
}

/// The anonymous-to-transparent body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArBody {
    /// input ABAR being spent.
    pub input: Nullifier,
    /// The new AR to be created.
    pub output: BlindAssetRecord,
    /// The Merkle root hash.
    pub merkle_root: BLSScalar,
    /// The Merkle root version.
    pub merkle_root_version: u64,
    /// The owner memo.
    pub memo: Option<OwnerMemo>,
}

/// Generate an anonymous-to-transparent pre-note.
pub fn init_abar_to_ar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    oabar: &OpenAnonAssetRecord,
    abar_keypair: &AXfrKeyPair,
    ar_pub_key: &XfrPublicKey,
) -> Result<AbarToArPreNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.get_public_key() != oabar.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    let oar_amount = oabar.amount;
    let oar_type = oabar.asset_type;

    let pc_gens = PedersenCommitmentRistretto::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        oar_amount,
        oar_type,
        NonConfidentialAmount_NonConfidentialAssetType,
        ar_pub_key.clone(),
    );
    let (oar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let this_nullifier = nullify(
        &abar_keypair,
        oabar.amount,
        &oabar.asset_type,
        mt_leaf_info.uid,
    );

    let payers_secret = PayerWitness {
        secret_key: abar_keypair.get_secret_key_scalar(),
        uid: mt_leaf_info.uid,
        amount: oabar.amount,
        asset_type: oabar.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: oabar.blind,
    };

    let mt_info_temp = oabar.mt_leaf_info.as_ref().unwrap();

    let body = AbarToArBody {
        input: this_nullifier,
        output: oar.blind_asset_record.clone(),
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        memo: owner_memo,
    };

    Ok(AbarToArPreNote {
        body,
        witness: payers_secret,
        input_keypair: abar_keypair.clone(),
    })
}

/// Finalize an anonymous-to-transparent note.
pub fn finish_abar_to_ar_note<R: CryptoRng + RngCore, D: Digest<OutputSize = U64> + Default>(
    prng: &mut R,
    params: &ProverParams,
    pre_note: AbarToArPreNote,
    hash: D,
) -> Result<AbarToArNote> {
    let AbarToArPreNote {
        body,
        witness,
        input_keypair,
    } = pre_note;

    let hash_scalar = BLSScalar::from_hash::<D>(hash);

    let (non_malleability_randomizer, non_malleability_tag) =
        compute_non_malleability_tag(prng, hash_scalar, &[&input_keypair]);

    let proof = prove_abar_to_ar(
        prng,
        params,
        witness,
        &hash_scalar,
        &non_malleability_randomizer,
        &non_malleability_tag,
    )
    .c(d!())?;

    Ok(AbarToArNote {
        body,
        proof,
        non_malleability_tag,
    })
}

/// Verify the anonymous-to-transparent note.
pub fn verify_abar_to_ar_note<D: Digest<OutputSize = U64> + Default>(
    params: &VerifierParams,
    note: &AbarToArNote,
    merkle_root: &BLSScalar,
    hash: D,
) -> Result<()> {
    // require the output amount & asset type are non-confidential
    if note.body.output.amount.is_confidential() || note.body.output.asset_type.is_confidential() {
        return Err(eg!(ZeiError::ParameterError));
    }

    let payer_amount = note.body.output.amount.get_amount().unwrap();
    let payer_asset_type = note.body.output.asset_type.get_asset_type().unwrap();

    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let hash_scalar = BLSScalar::from_hash::<D>(hash);

    let mut transcript = Transcript::new(ABAR_TO_AR_TRANSCRIPT);
    let mut online_inputs = vec![];
    online_inputs.push(note.body.input.clone());
    online_inputs.push(merkle_root.clone());
    online_inputs.push(BLSScalar::from(payer_amount));
    online_inputs.push(payer_asset_type.as_scalar());
    online_inputs.push(hash_scalar);
    online_inputs.push(note.non_malleability_tag);

    verifier(
        &mut transcript,
        &params.pcs,
        &params.cs,
        &params.verifier_params,
        &online_inputs,
        &note.proof,
    )
    .c(d!(ZeiError::AXfrVerificationError))
}

fn prove_abar_to_ar<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_witness: PayerWitness,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<AXfrPlonkPf> {
    let mut transcript = Transcript::new(ABAR_TO_AR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_ar_cs(
        payers_witness,
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

/// Construct the anonymous-to-transparent constraint system.
pub fn build_abar_to_ar_cs(
    payers_witness: PayerWitness,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboCS::new();
    let payers_witnesses_vars = add_payers_witnesses(&mut cs, &[payers_witness]);
    let payers_witness_vars = &payers_witnesses_vars[0];

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    let view_key_domain_separator = get_view_key_domain_separator();
    let view_key_domain_separator_var = cs.new_variable(view_key_domain_separator);
    cs.insert_constant_gate(view_key_domain_separator_var, view_key_domain_separator);

    // prove knowledge of payer's secret key: pk = base^{sk}.
    let view_key = cs.rescue_hash(&StateVar::new([
        view_key_domain_separator_var,
        payers_witness_vars.spend_key,
        zero_var,
        zero_var,
    ]))[0];
    let pk_var = cs.scalar_mul(base, view_key, SK_LEN);
    let pk_x = pk_var.get_x();

    // commitments
    let com_abar_in_var = commit_in_cs(
        &mut cs,
        payers_witness_vars.blind,
        payers_witness_vars.amount,
        payers_witness_vars.asset_type,
        pk_x,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_witness_vars.uid,
            payers_witness_vars.amount,
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
        asset_type: payers_witness_vars.asset_type,
        pub_key_x: pk_x,
    };
    let nullifier_var = nullify_in_cs(&mut cs, payers_witness_vars.spend_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_witness_vars.uid,
        commitment: com_abar_in_var,
    };
    let tmp_root_var = compute_merkle_root_variables(&mut cs, acc_elem, &payers_witness_vars.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // Check the non-malleability tag
    let one_var = cs.one_var();
    let hash_var = cs.new_variable(*hash);
    let non_malleability_randomizer_var = cs.new_variable(*non_malleability_randomizer);
    let non_malleability_tag_var = cs.new_variable(*non_malleability_tag);

    {
        let non_malleability_tag_var_supposed = cs.rescue_hash(&StateVar::new([
            one_var,
            hash_var,
            non_malleability_randomizer_var,
            payers_witness_vars.spend_key,
        ]))[0];

        cs.equal(non_malleability_tag_var_supposed, non_malleability_tag_var);
    }

    // prepare public inputs variables
    cs.prepare_pi_variable(nullifier_var);
    cs.prepare_pi_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_pi_variable(payers_witness_vars.amount);
    cs.prepare_pi_variable(payers_witness_vars.asset_type);

    cs.prepare_pi_variable(hash_var);
    cs.prepare_pi_variable(non_malleability_tag_var);

    // pad the number of constraints to power of two
    cs.pad();

    let n_constraints = cs.size;
    (cs, n_constraints)
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::{
        abar_to_ar::{finish_abar_to_ar_note, init_abar_to_ar_note, verify_abar_to_ar_note},
        structs::{AnonAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonAssetRecordBuilder},
        TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::{sig::XfrKeyPair, structs::AssetType};
    use digest::Digest;
    use mem_db::MemoryDB;
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use sha2::Sha512;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::basic::rescue::RescueInstance;

    #[test]
    fn test_abar_to_ar() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();

        let recv = XfrKeyPair::generate(&mut prng);
        let sender = AXfrKeyPair::generate(&mut prng);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "test_abar_to_ar_db".to_string(),
            0,
        )));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);
        let mut mt = PersistentMerkleTree::new(store).unwrap();

        let mut oabar = OpenAnonAssetRecordBuilder::new()
            .pub_key(&sender.get_public_key())
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .finalize(&mut prng)
            .unwrap()
            .build()
            .unwrap();

        let abar = AnonAssetRecord::from_oabar(&oabar);
        mt.add_commitment_hash(hash_abar(0, &abar)).unwrap();
        mt.commit().unwrap();
        let proof = mt.generate_proof(0).unwrap();

        oabar.update_mt_leaf_info(build_mt_leaf_info_from_proof(proof.clone()));

        let pre_note =
            init_abar_to_ar_note(&mut prng, &oabar.clone(), &sender, &recv.pub_key).unwrap();

        let hash = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        let note = finish_abar_to_ar_note(&mut prng, &params, pre_note, hash.clone()).unwrap();

        let node_params = VerifierParams::abar_to_ar_params().unwrap();
        verify_abar_to_ar_note(&node_params, &note, &proof.root, hash.clone()).unwrap();

        assert!(verify_abar_to_ar_note(
            &node_params,
            &note,
            &BLSScalar::random(&mut prng),
            hash.clone()
        )
        .is_err());

        let mut note_wrong_nullifier = note.clone();
        note_wrong_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_ar_note(
            &node_params,
            &note_wrong_nullifier,
            &proof.root,
            hash.clone()
        )
        .is_err());

        let hash2 = {
            let mut hasher = Sha512::new();
            let mut random_bytes = [0u8; 32];
            prng.fill_bytes(&mut random_bytes);
            hasher.update(&random_bytes);
            hasher
        };

        assert!(verify_abar_to_ar_note(&node_params, &note, &proof.root, hash2).is_err())
    }

    fn hash_abar(uid: u64, abar: &AnonAssetRecord) -> BLSScalar {
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
