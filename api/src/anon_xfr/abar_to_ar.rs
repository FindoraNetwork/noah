use crate::anon_xfr::{
    circuits::{
        add_merkle_path_variables, commit, compute_merkle_root, nullify, AccElemVars,
        NullifierInputVars, PayerSecret, PayerSecretVars, TurboPlonkCS, SK_LEN,
    },
    compute_non_malleability_tag,
    keys::AXfrKeyPair,
    nullifier,
    structs::{Nullifier, OpenAnonBlindAssetRecord},
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::{
    asset_record::{
        build_open_asset_record, AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
    },
    sig::XfrPublicKey,
    structs::{AssetRecordTemplate, BlindAssetRecord, OwnerMemo},
};
use digest::Digest;
use merlin::Transcript;
use sha2::Sha512;
use zei_algebra::{bls12_381::BLSScalar, jubjub::JubjubPoint, prelude::*};
use zei_crypto::basic::ristretto_pedersen_comm::RistrettoPedersenCommitment;
use zei_plonk::{
    plonk::{
        constraint_system::{rescue::StateVar, TurboConstraintSystem, VarIndex},
        prover::prover_with_lagrange,
        setup::PlonkPf,
        verifier::verifier,
    },
    poly_commit::kzg_poly_com::KZGCommitmentSchemeBLS,
};

pub type Abar2ArPlonkProof = PlonkPf<KZGCommitmentSchemeBLS>;
const ABAR_TO_AR_TRANSCRIPT: &[u8] = b"ABAR to AR proof";

/// ConvertAbarArProof is a struct to hold various aspects of a ZKP to prove spendability
/// and conversion of an ABAR to a AR on the chain.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertAbarArProof {
    /// proof of correctness of spent ABAR and new Asset Record
    spending_proof: Abar2ArPlonkProof,
    /// root hash of merkle tree
    merkle_root: BLSScalar,
    /// version of the root hash of merkle tree
    merkle_root_version: u64,
}

impl ConvertAbarArProof {
    #[allow(dead_code)]
    pub fn get_merkle_root_version(&self) -> u64 {
        return self.merkle_root_version;
    }
}

/// AbarToArNote has the AbarToArBody and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArNote {
    /// The body part of ABAR to AR
    pub body: AbarToArBody,
    /// The spending proof (assuming non-malleability)
    pub spending_proof: Abar2ArPlonkProof,
    /// The non-malleability tag
    pub non_malleability_tag: BLSScalar,
}

/// AbarToArBody has the input, the output, the merkle root and the owner memo.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToArBody {
    /// input ABAR being spent
    pub input: Nullifier,
    /// The new AR to be created
    pub output: BlindAssetRecord,
    /// The Merkle root hash
    pub merkle_root: BLSScalar,
    /// The Merkle root version
    pub merkle_root_version: u64,
    /// The owner memo
    pub memo: Option<OwnerMemo>,
}

/// This function generates the AbarToArBody from the Open ABARs, the receiver address and the signing
/// key pair.
/// * `prng` - pseudo random generator
/// * `params` - prover params for abar_to_ar note
/// * `oabar` - OpenAnonBlindAssetRecord to spend
/// * `abar_keypair` - keypair for spending ABAR
/// * `ar_pub_key` - Public key for receiving AR
#[allow(dead_code)]
pub fn gen_abar_to_ar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    oabar: &OpenAnonBlindAssetRecord,
    abar_keypair: &AXfrKeyPair,
    ar_pub_key: &XfrPublicKey,
) -> Result<AbarToArNote> {
    if oabar.mt_leaf_info.is_none() || abar_keypair.pub_key() != oabar.pub_key {
        return Err(eg!(ZeiError::ParameterError));
    }

    let oar_amount = oabar.amount;
    let oar_type = oabar.asset_type;

    let pc_gens = RistrettoPedersenCommitment::default();
    let art = AssetRecordTemplate::with_no_asset_tracing(
        oar_amount,
        oar_type,
        NonConfidentialAmount_NonConfidentialAssetType,
        ar_pub_key.clone(),
    );
    let (oar, _, owner_memo) = build_open_asset_record(prng, &pc_gens, &art, vec![]);

    // 2. build input witness info
    let mt_leaf_info = oabar.mt_leaf_info.as_ref().unwrap();
    let this_nullifier = nullifier(
        &abar_keypair,
        oabar.amount,
        &oabar.asset_type,
        mt_leaf_info.uid,
    );

    // 3. build the plonk proof
    let payers_secret = PayerSecret {
        sec_key: abar_keypair.get_secret_scalar(),
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

    let msg = bincode::serialize(&body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;

    let (hash, non_malleability_randomizer, non_malleability_tag) =
        compute_non_malleability_tag(prng, b"AbarToAr", &msg, &[&abar_keypair]);

    let spending_proof = prove_abar_to_ar_spending(
        prng,
        params,
        payers_secret,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
    )
    .c(d!())?;

    Ok(AbarToArNote {
        body,
        spending_proof,
        non_malleability_tag,
    })
}

/// Verifies the body
/// * `params` - verifier params
/// * `note` - note to verify
/// * `merkle_root` - root hash of ABAR commitment tree
#[allow(dead_code)]
pub fn verify_abar_to_ar_note(
    params: &VerifierParams,
    note: &AbarToArNote,
    merkle_root: &BLSScalar,
) -> Result<()> {
    // check amount & asset type are non-confidential
    if note.body.output.amount.is_confidential() || note.body.output.asset_type.is_confidential() {
        return Err(eg!(ZeiError::ParameterError));
    }

    let payer_amount = note.body.output.amount.get_amount().unwrap();
    let payer_asset_type = note.body.output.asset_type.get_asset_type().unwrap();

    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let input = note.body.input;

    let mut transcript = Transcript::new(ABAR_TO_AR_TRANSCRIPT);
    let mut online_inputs = vec![];

    online_inputs.push(input.clone());
    online_inputs.push(merkle_root.clone());
    online_inputs.push(BLSScalar::from(payer_amount));
    online_inputs.push(payer_asset_type.as_scalar());

    let msg = bincode::serialize(&note.body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;
    let mut hasher = Sha512::new();
    hasher.update(b"AbarToAr");
    hasher.update(msg.as_slice());
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

fn prove_abar_to_ar_spending<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    payers_secret: PayerSecret,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<Abar2ArPlonkProof> {
    let mut transcript = Transcript::new(ABAR_TO_AR_TRANSCRIPT);

    let (mut cs, _) = build_abar_to_ar_cs(
        payers_secret,
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
///        Constraint System for abar_to_ar
///
///
pub fn build_abar_to_ar_cs(
    payers_secret: PayerSecret,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> (TurboPlonkCS, usize) {
    let mut cs = TurboConstraintSystem::new();
    let payers_secrets_vars = add_payers_secret(&mut cs, payers_secret);

    let base = JubjubPoint::get_base();
    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let zero_var = cs.zero_var();
    let mut root_var: Option<VarIndex> = None;

    // prove knowledge of payer's secret key: pk = base^{sk}
    let pk_var = cs.scalar_mul(base, payers_secrets_vars.sec_key, SK_LEN);
    let pk_x = pk_var.get_x();

    // commitments
    let com_abar_in_var = commit(
        &mut cs,
        payers_secrets_vars.blind,
        payers_secrets_vars.amount,
        payers_secrets_vars.asset_type,
        pk_x,
    );

    // prove pre-image of the nullifier
    // 0 <= `amount` < 2^64, so we can encode (`uid`||`amount`) to `uid` * 2^64 + `amount`
    let uid_amount = cs.linear_combine(
        &[
            payers_secrets_vars.uid,
            payers_secrets_vars.amount,
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
        asset_type: payers_secrets_vars.asset_type,
        pub_key_x: pk_x,
    };
    let nullifier_var = nullify(&mut cs, payers_secrets_vars.sec_key, nullifier_input_vars);

    // Merkle path authentication
    let acc_elem = AccElemVars {
        uid: payers_secrets_vars.uid,
        commitment: com_abar_in_var,
    };
    let tmp_root_var = compute_merkle_root(&mut cs, acc_elem, &payers_secrets_vars.path);

    if let Some(root) = root_var {
        cs.equal(root, tmp_root_var);
    } else {
        root_var = Some(tmp_root_var);
    }

    // Check the validity of the non malleability tag
    let one_var = cs.one_var();
    let hash_var = cs.new_variable(*hash);
    let non_malleability_randomizer_var = cs.new_variable(*non_malleability_randomizer);
    let non_malleability_tag_var = cs.new_variable(*non_malleability_tag);

    {
        let non_malleability_tag_var_supposed = cs.rescue_hash(&StateVar::new([
            one_var,
            hash_var,
            non_malleability_randomizer_var,
            payers_secrets_vars.sec_key,
        ]))[0];

        cs.equal(non_malleability_tag_var_supposed, non_malleability_tag_var);
    }

    // prepare public inputs variables
    cs.prepare_io_variable(nullifier_var);

    // prepare the public input for merkle_root
    cs.prepare_io_variable(root_var.unwrap()); // safe unwrap

    cs.prepare_io_variable(payers_secrets_vars.amount);
    cs.prepare_io_variable(payers_secrets_vars.asset_type);

    cs.prepare_io_variable(hash_var);
    cs.prepare_io_variable(non_malleability_tag_var);

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
    use crate::anon_xfr::{
        abar_to_ar::{gen_abar_to_ar_note, verify_abar_to_ar_note},
        circuits::TREE_DEPTH,
        keys::AXfrKeyPair,
        structs::{
            AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecordBuilder,
        },
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::{sig::XfrKeyPair, structs::AssetType};
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
    fn test_abar_to_ar_conversion() {
        let mut prng = ChaChaRng::from_seed([5u8; 32]);
        let params = ProverParams::abar_to_ar_params(TREE_DEPTH).unwrap();

        let recv = XfrKeyPair::generate(&mut prng);
        let sender = AXfrKeyPair::generate(&mut prng);
        let sender_dec_key = XSecretKey::new(&mut prng);

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(
            fdb,
            "test_abar_to_ar_conversion_db".to_string(),
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

        let note = gen_abar_to_ar_note(&mut prng, &params, &oabar.clone(), &sender, &recv.pub_key)
            .unwrap();

        let node_params = VerifierParams::abar_to_ar_params().unwrap();
        verify_abar_to_ar_note(&node_params, &note, &proof.root).unwrap();

        assert!(
            verify_abar_to_ar_note(&node_params, &note, &BLSScalar::random(&mut prng),).is_err()
        );

        let mut note_wrong_nullifier = note.clone();
        note_wrong_nullifier.body.input = BLSScalar::random(&mut prng);
        assert!(verify_abar_to_ar_note(&node_params, &note_wrong_nullifier, &proof.root,).is_err());
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
