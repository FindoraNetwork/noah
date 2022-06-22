use crate::anon_xfr::circuits::build_multi_xfr_cs;
use crate::anon_xfr::structs::{AXfrKeyPair, Commitment, MTNode, MTPath, Nullifier};
use crate::anon_xfr::{
    check_asset_amount, check_inputs, check_roots, compute_non_malleability_tag, nullifier,
    structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord},
    PayeeSecret, PayerSecret, FEE_TYPE,
};
use crate::errors::ZeiError;
use crate::setup::{ProverParams, VerifierParams};
use crate::xfr::structs::OwnerMemo;
use digest::Digest;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha512;
use zei_algebra::bls12_381::{BLSPairingEngine, BLSScalar};
use zei_algebra::jubjub::{JubjubPoint, JubjubScalar};
use zei_algebra::prelude::*;
use zei_crypto::basic::rescue::RescueInstance;
use zei_plonk::plonk::indexer::PlonkPf;
use zei_plonk::plonk::prover::prover_with_lagrange;
use zei_plonk::plonk::verifier::verifier;
use zei_plonk::poly_commit::kzg_poly_com::{KZGCommitmentScheme, KZGCommitmentSchemeBLS};

pub type SnarkProof = PlonkPf<KZGCommitmentScheme<BLSPairingEngine>>;

/// Anonymous transfers structure
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrNote {
    /// The body part of AnonFee
    pub body: AXfrBody,
    /// The spending proof (assuming non-malleability)
    pub anon_xfr_proof: SnarkProof,
    /// The non-malleability tag
    pub non_malleability_tag: BLSScalar,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AXfrBody {
    pub inputs: Vec<Nullifier>,
    pub outputs: Vec<AnonBlindAssetRecord>,
    pub merkle_root: BLSScalar,
    pub merkle_root_version: u64,
    pub fee: u32,
    pub owner_memos: Vec<OwnerMemo>,
}

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
    fee: u32,
    input_keypairs: &[AXfrKeyPair],
) -> ruc::Result<AXfrNote> {
    // 1. check input correctness
    if inputs.is_empty() || outputs.is_empty() {
        return Err(eg!(ZeiError::AXfrProverParamsError));
    }
    check_inputs(inputs, input_keypairs).c(d!())?;
    check_asset_amount(inputs, outputs, fee).c(d!())?;
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
        fee,
    };
    let out_abars = outputs
        .iter()
        .map(AnonBlindAssetRecord::from_oabar)
        .collect_vec();
    let out_memos: ruc::Result<Vec<OwnerMemo>> = outputs
        .iter()
        .map(|output| output.owner_memo.clone().c(d!(ZeiError::ParameterError)))
        .collect();

    let mt_info_temp = inputs[0].mt_leaf_info.as_ref().unwrap();
    let body = AXfrBody {
        inputs: nullifiers,
        outputs: out_abars,
        merkle_root: mt_info_temp.root,
        merkle_root_version: mt_info_temp.root_version,
        fee,
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
) -> ruc::Result<()> {
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
        fee: note.body.fee,
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

const ANON_XFR_TRANSCRIPT: &[u8] = b"Anon Xfr";
const N_INPUTS_TRANSCRIPT: &[u8] = b"Number of input ABARs";
const N_OUTPUTS_TRANSCRIPT: &[u8] = b"Number of output ABARs";

pub(crate) type AXfrPlonkPf = PlonkPf<KZGCommitmentSchemeBLS>;

/// I generates the plonk proof for a multi-inputs/outputs anonymous transaction.
/// * `rng` - pseudo-random generator.
/// * `params` - System params
/// * `secret_inputs` - input to generate witness of the constraint system
pub(crate) fn prove_xfr<R: CryptoRng + RngCore>(
    rng: &mut R,
    params: &ProverParams,
    secret_inputs: AMultiXfrWitness,
    hash: &BLSScalar,
    non_malleability_randomizer: &BLSScalar,
    non_malleability_tag: &BLSScalar,
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
    let (mut cs, _) = build_multi_xfr_cs(
        secret_inputs,
        fee_type,
        &hash,
        &non_malleability_randomizer,
        &non_malleability_tag,
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

/// I verify the plonk proof for a multi-input/output anonymous transaction.
/// * `params` - System parameters including KZG params and the constraint system
/// * `pub_inputs` - the public inputs of the transaction.
/// * `proof` - the proof
pub(crate) fn verify_xfr(
    params: &VerifierParams,
    pub_inputs: &AMultiXfrPubInputs,
    proof: &AXfrPlonkPf,
    hash: &BLSScalar,
    non_malleability_tag: &BLSScalar,
) -> Result<()> {
    let mut transcript = Transcript::new(ANON_XFR_TRANSCRIPT);
    transcript.append_u64(N_INPUTS_TRANSCRIPT, pub_inputs.payers_inputs.len() as u64);
    transcript.append_u64(
        N_OUTPUTS_TRANSCRIPT,
        pub_inputs.payees_commitments.len() as u64,
    );
    let mut online_inputs = pub_inputs.to_vec();
    online_inputs.push(*hash);
    online_inputs.push(*non_malleability_tag);

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
    use crate::anon_xfr::abar_to_abar::AMultiXfrPubInputs;
    use crate::anon_xfr::structs::AXfrKeyPair;
    use crate::anon_xfr::{
        abar_to_abar::{gen_anon_xfr_note, prove_xfr, verify_anon_xfr_note, verify_xfr},
        circuits::tests::new_multi_xfr_witness_for_test,
        compute_non_malleability_tag, hash_abar,
        structs::{
            AnonBlindAssetRecord, MTLeafInfo, MTNode, MTPath, OpenAnonBlindAssetRecord,
            OpenAnonBlindAssetRecordBuilder,
        },
        FEE_TYPE, TREE_DEPTH,
    };
    use crate::setup::{ProverParams, VerifierParams};
    use crate::xfr::structs::AssetType;
    use parking_lot::lock_api::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::{RngCore, SeedableRng};
    use std::{sync::Arc, thread};
    use storage::{
        db::TempRocksDB,
        state::{ChainState, State},
        store::PrefixedStore,
    };
    use zei_accumulators::merkle_tree::{PersistentMerkleTree, Proof, TreePath};
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::basic::hybrid_encryption::{XPublicKey, XSecretKey};
    use zei_crypto::basic::rescue::RescueInstance;

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

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
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

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    #[test]
    fn test_anon_multi_xfr_proof_1in_2out_single_asset() {
        let fee_type = FEE_TYPE.as_scalar();

        // Receiver pub key x coordinate
        let pubkey_x = BLSScalar::from(4567u32);

        // (n, m) = (1, 2)
        let amount = 0; // a random number in [50, 100)
        let outputs = vec![(amount, fee_type, pubkey_x), (amount, fee_type, pubkey_x)];

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(1, outputs.len()) as u64;
        let inputs = vec![(fee_amount, fee_type)];

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
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

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
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

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
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

        let fee_calculating_func = |x: usize, y: usize| 5 + (x as u32) + 2 * (y as u32);
        let fee_amount = fee_calculating_func(inputs.len() + 1, outputs.len()) as u64;
        inputs.push((fee_amount, fee_type));

        test_anon_xfr_proof(inputs, outputs, fee_amount as u32);
    }

    fn test_anon_xfr_proof(
        inputs: Vec<(u64, BLSScalar)>,
        outputs: Vec<(u64, BLSScalar, BLSScalar)>,
        fee: u32,
    ) {
        let n_payers = inputs.len();
        let n_payees = outputs.len();

        // build cs
        let secret_inputs =
            new_multi_xfr_witness_for_test(inputs.to_vec(), outputs.to_vec(), fee, [0u8; 32]);
        let pub_inputs = AMultiXfrPubInputs::from_witness(&secret_inputs);
        let params = ProverParams::new(n_payers, n_payees, Some(1)).unwrap();
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let mut msg = [0u8; 32];
        prng.fill_bytes(&mut msg);

        let input_keypairs: Vec<AXfrKeyPair> = secret_inputs
            .payers_secrets
            .iter()
            .map(|x| AXfrKeyPair::from_secret_scalar(x.sec_key))
            .collect();

        let input_keypairs_ref: Vec<&AXfrKeyPair> = input_keypairs.iter().collect();

        let (hash, non_malleability_randomizer, non_malleability_tag) =
            compute_non_malleability_tag(&mut prng, b"AnonXfr", &msg, &input_keypairs_ref);

        let proof = prove_xfr(
            &mut prng,
            &params,
            secret_inputs,
            &hash,
            &non_malleability_randomizer,
            &non_malleability_tag,
        )
        .unwrap();

        // verify good witness
        let node_params = VerifierParams::from(params);
        assert!(verify_xfr(
            &node_params,
            &pub_inputs,
            &proof,
            &hash,
            &non_malleability_tag
        )
        .is_ok());

        // An unmatched input fail the verification
        let bad_secret_inputs = AMultiXfrPubInputs::from_witness(&new_multi_xfr_witness_for_test(
            inputs.to_vec(),
            outputs.to_vec(),
            fee,
            [1u8; 32],
        ));
        // verify bad witness
        assert!(verify_xfr(
            &node_params,
            &bad_secret_inputs,
            &proof,
            &hash,
            &non_malleability_tag
        )
        .is_err());
    }

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
        let fee_amount = 65u32;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount as u64;

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
                fee_amount,
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
    fn build_new_merkle_tree(
        n: i32,
        mt: &mut PersistentMerkleTree<TempRocksDB>,
    ) -> ruc::Result<()> {
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

        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);
        let store = PrefixedStore::new("my_store", &mut state);

        let user_params = ProverParams::new(1, 1, Some(TREE_DEPTH)).unwrap();

        let fee_amount = 25u32;
        let output_amount = 10u64;
        let input_amount = output_amount + fee_amount as u64;
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
                fee_amount,
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

        let fee_amount = 15;

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
                gen_anon_xfr_note(&mut prng, &user_params, &[], &open_abars_out, 15, &[])
                    .unwrap_err(),
            );
            msg_eq!(
                ZeiError::AXfrProverParamsError,
                gen_anon_xfr_note(
                    &mut prng,
                    &user_params,
                    &open_abars_in,
                    &[],
                    15,
                    &in_keypairs
                )
                .unwrap_err(),
            );
            // invalid inputs/outputs
            open_abars_in[0].amount += 1;
            assert!(gen_anon_xfr_note(
                &mut prng,
                &user_params,
                &open_abars_in,
                &open_abars_out,
                15,
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
                15,
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
                15,
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

/// Secret witness of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrWitness {
    pub payers_secrets: Vec<PayerSecret>,
    pub payees_secrets: Vec<PayeeSecret>,
    pub fee: u32,
}

impl AMultiXfrWitness {
    // create a default `AMultiXfrWitness`.
    pub(crate) fn fake(n_payers: usize, n_payees: usize, tree_depth: usize, fee: u32) -> Self {
        let bls_zero = BLSScalar::zero();
        let jubjub_zero = JubjubScalar::zero();
        let node = MTNode {
            siblings1: bls_zero,
            siblings2: bls_zero,
            is_left_child: 0,
            is_right_child: 0,
        };
        let payer_secret = PayerSecret {
            sec_key: jubjub_zero,
            uid: 0,
            amount: 0,
            asset_type: bls_zero,
            path: MTPath::new(vec![node; tree_depth]),
            blind: bls_zero,
        };
        let payee_secret = PayeeSecret {
            amount: 0,
            blind: bls_zero,
            asset_type: bls_zero,
            pubkey_x: bls_zero,
        };

        AMultiXfrWitness {
            payers_secrets: vec![payer_secret; n_payers],
            payees_secrets: vec![payee_secret; n_payees],
            fee,
        }
    }
}

/// Public inputs of an anonymous transaction.
#[derive(Debug)]
pub(crate) struct AMultiXfrPubInputs {
    pub payers_inputs: Vec<Nullifier>,
    pub payees_commitments: Vec<Commitment>,
    pub merkle_root: BLSScalar,
    pub fee: u32,
}

impl AMultiXfrPubInputs {
    pub fn to_vec(&self) -> Vec<BLSScalar> {
        let mut result = vec![];
        // nullifiers and signature verification keys
        for nullifier in &self.payers_inputs {
            result.push(*nullifier);
        }
        // merkle_root
        result.push(self.merkle_root);
        // output commitments
        for comm in &self.payees_commitments {
            result.push(*comm);
        }
        // fee
        result.push(BLSScalar::from(self.fee));
        result
    }

    // Compute the public inputs from the secret inputs
    #[allow(dead_code)]
    pub(crate) fn from_witness(witness: &AMultiXfrWitness) -> Self {
        // nullifiers and signature public keys
        let hash = RescueInstance::new();
        let base = JubjubPoint::get_base();
        let payers_inputs: Vec<Nullifier> = witness
            .payers_secrets
            .iter()
            .map(|sec| {
                let pk_point = base.mul(&sec.sec_key);

                let pow_2_64 = BLSScalar::from(u64::MAX).add(&BLSScalar::one());
                let uid_amount = pow_2_64
                    .mul(&BLSScalar::from(sec.uid))
                    .add(&BLSScalar::from(sec.amount));
                let cur = hash.rescue(&[
                    uid_amount,
                    sec.asset_type,
                    BLSScalar::zero(),
                    pk_point.get_x(),
                ])[0];
                hash.rescue(&[
                    cur,
                    BLSScalar::from(&sec.sec_key),
                    BLSScalar::zero(),
                    BLSScalar::zero(),
                ])[0]
            })
            .collect();

        // output commitments
        let hash = RescueInstance::new();
        let zero = BLSScalar::zero();
        let payees_commitments: Vec<Commitment> = witness
            .payees_secrets
            .iter()
            .map(|sec| {
                let cur = hash.rescue(&[
                    sec.blind,
                    BLSScalar::from(sec.amount),
                    sec.asset_type,
                    BLSScalar::zero(),
                ])[0];
                hash.rescue(&[cur, sec.pubkey_x, BLSScalar::zero(), BLSScalar::zero()])[0]
            })
            .collect();

        // merkle root
        let payer = &witness.payers_secrets[0];
        let pk_point = base.mul(&payer.sec_key);
        let commitment = {
            let cur = hash.rescue(&[
                payer.blind,
                BLSScalar::from(payer.amount),
                payer.asset_type,
                BLSScalar::zero(),
            ])[0];
            hash.rescue(&[cur, pk_point.get_x(), BLSScalar::zero(), BLSScalar::zero()])[0]
        };
        let mut node = hash.rescue(&[BLSScalar::from(payer.uid), commitment, zero, zero])[0];
        for path_node in payer.path.nodes.iter() {
            let input = match (path_node.is_left_child, path_node.is_right_child) {
                (1, 0) => vec![node, path_node.siblings1, path_node.siblings2, zero],
                (0, 0) => vec![path_node.siblings1, node, path_node.siblings2, zero],
                _ => vec![path_node.siblings1, path_node.siblings2, node, zero],
            };
            node = hash.rescue(&input)[0];
        }

        Self {
            payers_inputs,
            payees_commitments,
            merkle_root: node,
            fee: witness.fee,
        }
    }
}
