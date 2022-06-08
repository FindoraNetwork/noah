use crate::anon_xfr::{
    circuits::{AMultiXfrPubInputs, AMultiXfrWitness, PayeeSecret, PayerSecret},
    config::{FEE_CALCULATING_FUNC, FEE_TYPE},
    keys::AXfrKeyPair,
    proofs::{prove_xfr, verify_xfr},
    structs::{AXfrNote, AnonBlindAssetRecord, OpenAnonBlindAssetRecord},
};
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::structs::{AssetType, OwnerMemo, ASSET_TYPE_LENGTH};
use digest::Digest;
use sha2::Sha512;
use zei_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    collections::HashMap,
    prelude::*,
};
use zei_crypto::basic::hybrid_encryption::{hybrid_decrypt_with_x25519_secret_key, XSecretKey};

pub mod abar_to_ar;
pub mod abar_to_bar;
pub mod anon_fee;
pub mod ar_to_abar;
pub mod bar_to_abar;
pub(crate) mod circuits;
pub mod config;
pub mod keys;
mod merkle_tree_test;
pub(crate) mod proofs;
pub mod structs;
use crate::anon_xfr::structs::AXfrBody;
pub use circuits::TREE_DEPTH;
use zei_crypto::basic::rescue::RescueInstance;

/// Build an anonymous transfer structure AXfrNote. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `inputs` - Open source asset records
/// * `outputs` - Description of output asset records.
pub fn gen_anon_xfr_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &ProverParams,
    inputs: &[OpenAnonBlindAssetRecord],
    outputs: &[OpenAnonBlindAssetRecord],
    input_keypairs: &[AXfrKeyPair],
) -> Result<AXfrNote> {
    // 1. check input correctness
    if inputs.is_empty() || outputs.is_empty() {
        return Err(eg!(ZeiError::AXfrProverParamsError));
    }
    check_inputs(inputs, input_keypairs).c(d!())?;
    check_asset_amount(inputs, outputs).c(d!())?;
    check_roots(inputs).c(d!())?;

    // 2. build input witness infos
    let nullifiers = inputs
        .iter()
        .zip(input_keypairs.iter())
        .map(|(input, keypair)| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            nullifier(&keypair, input.amount, &input.asset_type, mt_leaf_info.uid)
        })
        .collect();

    // 3. build proof
    let payers_secrets = inputs
        .iter()
        .zip(input_keypairs.iter())
        .map(|(input, keypair)| {
            let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
            PayerSecret {
                sec_key: keypair.get_secret_scalar(),
                uid: mt_leaf_info.uid,
                amount: input.amount,
                asset_type: input.asset_type.as_scalar(),
                path: mt_leaf_info.path.clone(),
                blind: input.blind,
            }
        })
        .collect();
    let payees_secrets = outputs
        .iter()
        .map(|output| PayeeSecret {
            amount: output.amount,
            blind: output.blind,
            asset_type: output.asset_type.as_scalar(),
            pubkey_x: output.pub_key.0.point_ref().get_x(),
        })
        .collect();

    let secret_inputs = AMultiXfrWitness {
        payers_secrets,
        payees_secrets,
    };
    let out_abars = outputs
        .iter()
        .map(AnonBlindAssetRecord::from_oabar)
        .collect_vec();
    let out_memos: Result<Vec<OwnerMemo>> = outputs
        .iter()
        .map(|output| output.owner_memo.clone().c(d!(ZeiError::ParameterError)))
        .collect();

    let mt_info_temp = inputs[0].mt_leaf_info.as_ref().unwrap();
    let body = AXfrBody {
        inputs: nullifiers,
        outputs: out_abars,
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        owner_memos: out_memos.c(d!())?,
    };

    let msg = bincode::serialize(&body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;

    let input_keypairs_ref: Vec<&AXfrKeyPair> = input_keypairs.iter().collect();

    let (hash, non_malleability_randomizer, non_malleability_tag) =
        compute_non_malleability_tag(prng, b"AnonXfr", &msg, &input_keypairs_ref);

    let proof = prove_xfr(
        prng,
        params,
        secret_inputs,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
    )
    .c(d!())?;

    Ok(AXfrNote {
        body,
        anon_xfr_proof: proof,
        non_malleability_tag,
    })
}

/// Verifies an anonymous transfer structure AXfrNote.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
pub fn verify_anon_xfr_note(
    params: &VerifierParams,
    note: &AXfrNote,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != note.body.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }
    let payees_commitments = note
        .body
        .outputs
        .iter()
        .map(|output| output.commitment)
        .collect();
    let pub_inputs = AMultiXfrPubInputs {
        payers_inputs: note.body.inputs.clone(),
        payees_commitments,
        merkle_root: *merkle_root,
    };

    let msg = bincode::serialize(&note.body)
        .c(d!(ZeiError::SerializationError))
        .c(d!())?;
    let mut hasher = Sha512::new();
    hasher.update(b"AnonXfr");
    hasher.update(&msg);
    let hash = BLSScalar::from_hash(hasher);

    verify_xfr(
        params,
        &pub_inputs,
        &note.anon_xfr_proof,
        &hash,
        &note.non_malleability_tag,
    )
    .c(d!(ZeiError::AXfrVerificationError))
}

/// Check that inputs have mt witness and keypair matched pubkey
fn check_inputs(inputs: &[OpenAnonBlindAssetRecord], keypairs: &[AXfrKeyPair]) -> Result<()> {
    if inputs.len() != keypairs.len() {
        return Err(eg!(ZeiError::ParameterError));
    }
    for (input, keypair) in inputs.iter().zip(keypairs.iter()) {
        if input.mt_leaf_info.is_none() || keypair.pub_key() != input.pub_key {
            return Err(eg!(ZeiError::ParameterError));
        }
    }
    Ok(())
}

/// Check that for each asset type total input amount == total output amount
/// and for FRA, total input amount == total output amount + fees for fra
fn check_asset_amount(
    inputs: &[OpenAnonBlindAssetRecord],
    outputs: &[OpenAnonBlindAssetRecord],
) -> Result<()> {
    let fee_asset_type = FEE_TYPE;
    let mut balances = HashMap::new();

    for record in inputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x += record.amount as i128;
        } else {
            balances.insert(record.asset_type, record.amount as i128);
        }
    }

    for record in outputs.iter() {
        if let Some(x) = balances.get_mut(&record.asset_type) {
            *x -= record.amount as i128;
        } else {
            balances.insert(record.asset_type, -(record.amount as i128));
        }
    }

    let fee_amount = FEE_CALCULATING_FUNC(inputs.len() as u32, outputs.len() as u32);

    for (&asset_type, &sum) in balances.iter() {
        if asset_type != fee_asset_type {
            if sum != 0i128 {
                return Err(eg!(ZeiError::XfrCreationAssetAmountError));
            }
        } else {
            if sum != fee_amount.into() {
                return Err(eg!(ZeiError::XfrCreationAssetAmountError));
            }
        }
    }

    Ok(())
}

/// Check that the merkle roots in input asset records are consistent
/// `inputs` is guaranteed to have at least one asset record
fn check_roots(inputs: &[OpenAnonBlindAssetRecord]) -> Result<()> {
    let root = inputs[0]
        .mt_leaf_info
        .as_ref()
        .c(d!(ZeiError::ParameterError))?
        .root;
    for input in inputs.iter().skip(1) {
        if input
            .mt_leaf_info
            .as_ref()
            .c(d!(ZeiError::ParameterError))?
            .root
            != root
        {
            return Err(eg!(ZeiError::AXfrVerificationError));
        }
    }
    Ok(())
}

pub fn compute_non_malleability_tag<R: CryptoRng + RngCore>(
    prng: &mut R,
    domain_separator: &[u8],
    msg: &[u8],
    secret_keys: &[&AXfrKeyPair],
) -> (BLSScalar, BLSScalar, BLSScalar) {
    let mut hasher = Sha512::new();
    hasher.update(domain_separator);
    hasher.update(msg);

    let hash = BLSScalar::from_hash(hasher);
    let randomizer = BLSScalar::random(prng);

    let mut input_to_rescue = vec![];
    input_to_rescue.push(BLSScalar::from(secret_keys.len() as u64));
    input_to_rescue.push(hash);
    input_to_rescue.push(randomizer);
    for secret_key in secret_keys.iter() {
        input_to_rescue.push(BLSScalar::from(&secret_key.get_secret_scalar()));
    }

    if input_to_rescue.len() < 4 {
        // pad to 4
        input_to_rescue.resize(4, BLSScalar::zero());
    } else {
        // pad to 4 + 3k
        input_to_rescue.resize(
            1 + (input_to_rescue.len() - 1 + 2) / 3 * 3,
            BLSScalar::zero(),
        );
    }

    let rescue = RescueInstance::new();
    let mut acc = rescue.rescue(&[
        input_to_rescue[0],
        input_to_rescue[1],
        input_to_rescue[2],
        input_to_rescue[3],
    ])[0];
    for chunk in input_to_rescue[4..].chunks_exact(3) {
        acc = rescue.rescue(&[acc, chunk[0], chunk[1], chunk[2]])[0];
    }

    (hash, randomizer, acc)
}

/// Decrypts the owner memo
/// * `memo` - Owner memo to decrypt
/// * `dec_key` - Decryption key
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match abar's commitment or public key
/// Return Ok(amount, asset_type, blinding) otherwise
pub fn decrypt_memo(
    memo: &OwnerMemo,
    dec_key: &XSecretKey,
    key_pair: &AXfrKeyPair,
    abar: &AnonBlindAssetRecord,
) -> Result<(u64, AssetType, BLSScalar)> {
    let plaintext = hybrid_decrypt_with_x25519_secret_key(&memo.lock, dec_key);
    if plaintext.len() != 8 + ASSET_TYPE_LENGTH + BLS12_381_SCALAR_LEN {
        return Err(eg!(ZeiError::ParameterError));
    }
    let amount = u8_le_slice_to_u64(&plaintext[0..8]);
    let mut i = 8;
    let mut asset_type_array = [0u8; ASSET_TYPE_LENGTH];
    asset_type_array.copy_from_slice(&plaintext[i..i + ASSET_TYPE_LENGTH]);
    let asset_type = AssetType(asset_type_array);
    i += ASSET_TYPE_LENGTH;
    let blind = BLSScalar::from_bytes(&plaintext[i..i + BLS12_381_SCALAR_LEN])
        .c(d!(ZeiError::ParameterError))?;

    // verify abar's commitment
    let hash = RescueInstance::new();
    let expected_commitment = hash.rescue(&[
        blind,
        BLSScalar::from(amount),
        asset_type.as_scalar(),
        key_pair.pub_key().0.point_ref().get_x(),
    ])[0];
    if expected_commitment != abar.commitment {
        return Err(eg!(ZeiError::CommitmentVerificationError));
    }

    Ok((amount, asset_type, blind))
}

pub fn nullifier(
    key_pair: &AXfrKeyPair,
    amount: u64,
    asset_type: &AssetType,
    uid: u64,
) -> BLSScalar {
    let pub_key = key_pair.pub_key();
    let pub_key_point = pub_key.as_jubjub_point();
    let pub_key_x = pub_key_point.get_x();

    let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::from(1u32));
    let uid_shifted = BLSScalar::from(uid).mul(&pow_2_64);
    let uid_amount = uid_shifted.add(&BLSScalar::from(amount));

    let hash = RescueInstance::new();
    hash.rescue(&[
        uid_amount,
        asset_type.as_scalar(),
        pub_key_x,
        BLSScalar::from(&key_pair.get_secret_scalar()),
    ])[0]
}

pub fn hash_abar(uid: u64, abar: &AnonBlindAssetRecord) -> BLSScalar {
    let hash = RescueInstance::new();
    hash.rescue(&[
        BLSScalar::from(uid),
        abar.commitment,
        BLSScalar::zero(),
        BLSScalar::zero(),
    ])[0]
}

#[cfg(test)]
mod tests {
    use crate::anon_xfr::{
        config::{FEE_CALCULATING_FUNC, FEE_TYPE},
        gen_anon_xfr_note, hash_abar,
        keys::AXfrKeyPair,
        structs::{
            AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecord,
            OpenAnonBlindAssetRecordBuilder,
        },
        verify_anon_xfr_note, TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::structs::AssetType;
    use mem_db::MemoryDB;
    use parking_lot::lock_api::RwLock;
    use rand_chacha::ChaChaRng;
    use std::sync::Arc;
    use storage::{
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::basic::hybrid_encryption::{XPublicKey, XSecretKey};
    use zei_crypto::basic::rescue::RescueInstance;

    pub fn create_mt_leaf_info(proof: Proof) -> MTLeafInfo {
        MTLeafInfo {
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
            uid: proof.uid,
        }
    }

    #[test]
    fn test_anon_xfr() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let user_params = ProverParams::new(1, 1, Some(1)).unwrap();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let two = one.add(&one);

        let asset_type = FEE_TYPE;
        let fee_amount = FEE_CALCULATING_FUNC(1u32, 1u32) as u64;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount;

        // simulate input abar
        let (oabar, keypair_in, dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, asset_type);
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());

        let owner_memo = oabar.get_owner_memo().unwrap();

        // simulate Merkle tree state
        let node = MTNode {
            siblings1: one,
            siblings2: two,
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        let hash = RescueInstance::new();
        let leaf = hash.rescue(&[/*uid=*/ two, oabar.compute_commitment(), zero, zero])[0];
        let merkle_root = hash.rescue(&[/*sib1[0]=*/ one, /*sib2[0]=*/ two, leaf, zero])[0];
        let mt_leaf_info = MTLeafInfo {
            path: MTPath { nodes: vec![node] },
            root: merkle_root,
            uid: 2,
            root_version: 0,
        };

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let (note, merkle_root) = {
            // prover scope
            // 1. open abar
            let oabar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                &abar,
                owner_memo,
                &keypair_in,
                &dec_key_in,
            )
            .unwrap()
            .mt_leaf_info(mt_leaf_info)
            .build()
            .unwrap();
            assert_eq!(input_amount, oabar_in.get_amount());
            assert_eq!(asset_type, oabar_in.get_asset_type());
            assert_eq!(keypair_in.pub_key(), oabar_in.pub_key);

            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(asset_type)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &[oabar_in],
                &[oabar_out],
                &[keypair_in],
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
                &note.body.outputs[0],
                note.body.owner_memos[0].clone(),
                &keypair_out,
                &dec_key_out,
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(output_amount, oabar.get_amount());
            assert_eq!(asset_type, oabar.get_asset_type());
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            assert!(verify_anon_xfr_note(&verifier_params, &note, &merkle_root).is_ok());
        }
    }

    // outputs &mut merkle tree (wrap it in an option merkle tree, not req)
    fn build_new_merkle_tree(n: i32, mt: &mut PersistentMerkleTree<MemoryDB>) -> Result<()> {
        // add 6/7 abar and populate and then retrieve values

        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let mut abar = AnonBlindAssetRecord {
            commitment: BLSScalar::random(&mut prng),
        };

        let _ = mt.add_commitment_hash(hash_abar(mt.entry_count(), &abar))?;
        mt.commit()?;

        for _i in 0..n - 1 {
            abar = AnonBlindAssetRecord {
                commitment: BLSScalar::random(&mut prng),
            };

            let _ = mt.add_commitment_hash(hash_abar(mt.entry_count(), &abar))?;
            mt.commit()?;
        }

        Ok(())
    }

    // new test with actual merkle tree
    #[test]
    fn test_new_anon_xfr() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let fdb = MemoryDB::new();
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);

        let user_params = ProverParams::new(1, 1, Some(TREE_DEPTH)).unwrap();

        let fee_amount = FEE_CALCULATING_FUNC(1, 1) as u64;
        let output_amount = 10u64;
        let input_amount = output_amount + fee_amount;
        let asset_type = FEE_TYPE;

        // simulate input abar
        let (oabar, keypair_in, dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, asset_type);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());

        let owner_memo = oabar.get_owner_memo().unwrap();

        let mut mt = PersistentMerkleTree::new(store).unwrap();
        build_new_merkle_tree(5, &mut mt).unwrap();

        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        let uid = mt
            .add_commitment_hash(hash_abar(mt.entry_count(), &abar))
            .unwrap();
        let _ = mt.commit();
        let mt_proof = mt.generate_proof(uid).unwrap();
        assert_eq!(mt.get_root().unwrap(), mt_proof.root);

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let (note, _merkle_root) = {
            // prover scope
            // 1. open abar
            let oabar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                &abar,
                owner_memo,
                &keypair_in,
                &dec_key_in,
            )
            .unwrap()
            .mt_leaf_info(create_mt_leaf_info(mt_proof.clone()))
            .build()
            .unwrap();
            assert_eq!(input_amount, oabar_in.get_amount());
            assert_eq!(asset_type, oabar_in.get_asset_type());
            assert_eq!(keypair_in.pub_key(), oabar_in.pub_key);

            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(asset_type)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &[oabar_in],
                &[oabar_out],
                &[keypair_in],
            )
            .unwrap();
            (note, mt_proof.root)
        };
        {
            // owner scope
            let oabar = OpenAnonBlindAssetRecordBuilder::from_abar(
                &note.body.outputs[0],
                note.body.owner_memos[0].clone(),
                &keypair_out,
                &dec_key_out,
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(output_amount, oabar.get_amount());
            assert_eq!(asset_type, oabar.get_asset_type());
        }
        {
            let mut hash = {
                let hasher = RescueInstance::new();
                hasher.rescue(&[
                    BLSScalar::from(uid),
                    abar.commitment,
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0]
            };
            let hasher = RescueInstance::new();
            for i in mt_proof.nodes.iter() {
                let (s1, s2, s3) = match i.path {
                    TreePath::Left => (hash, i.siblings1, i.siblings2),
                    TreePath::Middle => (i.siblings1, hash, i.siblings2),
                    TreePath::Right => (i.siblings1, i.siblings2, hash),
                };
                hash = hasher.rescue(&[s1, s2, s3, BLSScalar::zero()])[0];
            }
            assert_eq!(hash, mt.get_root().unwrap());
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            let t = verify_anon_xfr_note(&verifier_params, &note, &mt.get_root().unwrap());
            assert!(t.is_ok());

            let vk1 = verifier_params.shrink().unwrap();
            assert!(verify_anon_xfr_note(&vk1, &note, &mt.get_root().unwrap()).is_ok());

            let vk2 = VerifierParams::load(1, 1).unwrap();
            assert!(verify_anon_xfr_note(&vk2, &note, &mt.get_root().unwrap()).is_ok());
        }
    }

    #[test]
    fn test_anon_xfr_multi_assets() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let n_payers = 3;
        let n_payees = 3;
        let user_params = ProverParams::new(n_payers, n_payees, Some(1)).unwrap();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();

        let fee_amount = FEE_CALCULATING_FUNC(3, 3) as u64;

        // simulate input abars
        let amounts_in = vec![10u64 + fee_amount, 20u64, 30u64];
        let asset_types_in = vec![
            FEE_TYPE,
            AssetType::from_identical_byte(1),
            AssetType::from_identical_byte(1),
        ];
        let mut in_abars = vec![];
        let mut in_keypairs = vec![];
        let mut in_dec_keys = vec![];
        let mut in_owner_memos = vec![];
        for i in 0..n_payers {
            let (oabar, keypair, dec_key, _) =
                gen_oabar_and_keys(&mut prng, amounts_in[i], asset_types_in[i]);
            let abar = AnonBlindAssetRecord::from_oabar(&oabar);
            let owner_memo = oabar.get_owner_memo().unwrap();
            in_abars.push(abar);
            in_keypairs.push(keypair);
            in_dec_keys.push(dec_key);
            in_owner_memos.push(owner_memo);
        }
        // simulate Merkle tree state
        let hash = RescueInstance::new();
        let leafs: Vec<BLSScalar> = in_abars
            .iter()
            .enumerate()
            .map(|(uid, in_abar)| {
                hash.rescue(&[BLSScalar::from(uid as u32), in_abar.commitment, zero, zero])[0]
            })
            .collect();
        let node0 = MTNode {
            siblings1: leafs[1],
            siblings2: leafs[2],
            is_left_child: 1u8,
            is_right_child: 0u8,
        };
        let node1 = MTNode {
            siblings1: leafs[0],
            siblings2: leafs[2],
            is_left_child: 0u8,
            is_right_child: 0u8,
        };
        let node2 = MTNode {
            siblings1: leafs[0],
            siblings2: leafs[1],
            is_left_child: 0u8,
            is_right_child: 1u8,
        };
        let nodes = vec![node0, node1, node2];
        let merkle_root = hash.rescue(&[leafs[0], leafs[1], leafs[2], zero])[0];

        // output keys, amounts, asset_types
        let (keypairs_out, dec_keys_out, enc_keys_out) = gen_keys(&mut prng, n_payees);
        let amounts_out = vec![5u64, 5u64, 50u64];
        let asset_types_out = vec![FEE_TYPE, FEE_TYPE, AssetType::from_identical_byte(1)];
        let mut outputs = vec![];
        for i in 0..n_payees {
            outputs.push(
                OpenAnonBlindAssetRecordBuilder::new()
                    .amount(amounts_out[i])
                    .asset_type(asset_types_out[i])
                    .pub_key(keypairs_out[i].pub_key())
                    .finalize(&mut prng, &enc_keys_out[i])
                    .unwrap()
                    .build()
                    .unwrap(),
            );
        }

        let (note, merkle_root) = {
            // prover scope
            let mut open_abars_in: Vec<OpenAnonBlindAssetRecord> = (0..n_payers)
                .map(|uid| {
                    let mt_leaf_info = MTLeafInfo {
                        path: MTPath {
                            nodes: vec![nodes[uid].clone()],
                        },
                        root: merkle_root,
                        uid: uid as u64,
                        root_version: 0,
                    };
                    let open_abar_in = OpenAnonBlindAssetRecordBuilder::from_abar(
                        &in_abars[uid],
                        in_owner_memos[uid].clone(),
                        &in_keypairs[uid],
                        &in_dec_keys[uid],
                    )
                    .unwrap()
                    .mt_leaf_info(mt_leaf_info)
                    .build()
                    .unwrap();
                    assert_eq!(amounts_in[uid], open_abar_in.amount);
                    assert_eq!(asset_types_in[uid], open_abar_in.asset_type);
                    open_abar_in
                })
                .collect();

            let open_abars_out = (0..n_payees)
                .map(|i| {
                    OpenAnonBlindAssetRecordBuilder::new()
                        .amount(amounts_out[i])
                        .asset_type(asset_types_out[i])
                        .pub_key(keypairs_out[i].pub_key())
                        .finalize(&mut prng, &enc_keys_out[i])
                        .unwrap()
                        .build()
                        .unwrap()
                })
                .collect_vec();

            // empty inputs/outputs
            msg_eq!(
                ZeiError::AXfrProverParamsError,
                gen_anon_xfr_note(&mut prng, &user_params, &[], &open_abars_out, &[]).unwrap_err(),
            );
            msg_eq!(
                ZeiError::AXfrProverParamsError,
                gen_anon_xfr_note(&mut prng, &user_params, &open_abars_in, &[], &in_keypairs)
                    .unwrap_err(),
            );
            // invalid inputs/outputs
            open_abars_in[0].amount += 1;
            assert!(gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                &in_keypairs
            )
            .is_err());
            open_abars_in[0].amount -= 1;
            // inconsistent roots
            let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
            mt_info.root.add_assign(&one);
            open_abars_in[0].mt_leaf_info = Some(mt_info);
            assert!(gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                &in_keypairs
            )
            .is_err());
            let mut mt_info = open_abars_in[0].mt_leaf_info.clone().unwrap();
            mt_info.root.sub_assign(&one);
            open_abars_in[0].mt_leaf_info = Some(mt_info);

            let note = gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                &in_keypairs,
            )
            .unwrap();
            (note, merkle_root)
        };
        {
            // owner scope
            for i in 0..n_payees {
                let oabar_out = OpenAnonBlindAssetRecordBuilder::from_abar(
                    &note.body.outputs[i],
                    note.body.owner_memos[i].clone(),
                    &keypairs_out[i],
                    &dec_keys_out[i],
                )
                .unwrap()
                .build()
                .unwrap();
                assert_eq!(amounts_out[i], oabar_out.amount);
                assert_eq!(asset_types_out[i], oabar_out.asset_type);
            }
        }
        {
            // verifier scope
            let verifier_params = VerifierParams::from(user_params);
            // inconsistent merkle roots
            assert!(verify_anon_xfr_note(&verifier_params, &note, &zero).is_err());
            assert!(verify_anon_xfr_note(&verifier_params, &note, &merkle_root).is_ok());
        }
    }

    fn gen_keys<R: CryptoRng + RngCore>(
        prng: &mut R,
        n: usize,
    ) -> (Vec<AXfrKeyPair>, Vec<XSecretKey>, Vec<XPublicKey>) {
        let keypairs_in: Vec<AXfrKeyPair> = (0..n).map(|_| AXfrKeyPair::generate(prng)).collect();

        let dec_keys_in: Vec<XSecretKey> = (0..n).map(|_| XSecretKey::new(prng)).collect();
        let enc_keys_in: Vec<XPublicKey> = dec_keys_in.iter().map(XPublicKey::from).collect();
        (keypairs_in, dec_keys_in, enc_keys_in)
    }

    fn gen_oabar_and_keys<R: CryptoRng + RngCore>(
        prng: &mut R,
        amount: u64,
        asset_type: AssetType,
    ) -> (
        OpenAnonBlindAssetRecord,
        AXfrKeyPair,
        XSecretKey,
        XPublicKey,
    ) {
        let keypair = AXfrKeyPair::generate(prng);
        let dec_key = XSecretKey::new(prng);
        let enc_key = XPublicKey::from(&dec_key);
        let oabar = OpenAnonBlindAssetRecordBuilder::new()
            .amount(amount)
            .asset_type(asset_type)
            .pub_key(keypair.pub_key())
            .finalize(prng, &enc_key)
            .unwrap()
            .build()
            .unwrap();
        (oabar, keypair, dec_key, enc_key)
    }
}
