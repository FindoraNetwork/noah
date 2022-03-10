use crate::anon_xfr::circuits::{
    AMultiXfrPubInputs, AMultiXfrWitness, PayeeSecret, PayerSecret,
};
use crate::anon_xfr::proofs::{prove_xfr, verify_xfr};
use crate::anon_xfr::{
    check_asset_amount,
    keys::{AXfrKeyPair, AXfrPubKey, AXfrSignature},
    nullifier,
    structs::{AXfrProof, AnonBlindAssetRecord, Nullifier, OpenAnonBlindAssetRecord},
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::OwnerMemo;
use algebra::bls12_381::BLSScalar;
use algebra::groups::Scalar;
use algebra::jubjub::JubjubScalar;
use rand_core::{CryptoRng, RngCore};
use ruc::*;
use std::borrow::Borrow;
use utils::errors::ZeiError;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeNote {
    pub body: AnonFeeBody,
    pub signature: AXfrSignature,
}

impl AnonFeeNote {
    pub fn generate_note_from_body(
        body: AnonFeeBody,
        keypair: AXfrKeyPair,
    ) -> Result<AnonFeeNote> {
        let msg: Vec<u8> = bincode::serialize(&body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        Ok(AnonFeeNote {
            body,
            signature: keypair.sign(msg.as_slice()),
        })
    }

    pub fn verify_signatures(&self) -> Result<()> {
        let msg: Vec<u8> = bincode::serialize(&self.body)
            .map_err(|_| ZeiError::SerializationError)
            .c(d!())?;

        self.body
            .input
            .1
            .verify(msg.as_slice(), &self.signature)
            .c(d!("AXfrNote signature verification failed"))?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Eq)]
pub struct AnonFeeBody {
    pub input: (Nullifier, AXfrPubKey),
    pub output: AnonBlindAssetRecord,
    pub proof: AXfrProof,
    pub owner_memo: OwnerMemo,
}

/// Build an anonymous fee structure AnonFeeBody. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `input` - Open source asset records
/// * `output` - Description of output asset records.
#[allow(unused_variables)]
pub fn gen_anon_fee_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    input: &OpenAnonBlindAssetRecord,
    output: &OpenAnonBlindAssetRecord,
    input_keypair: &AXfrKeyPair,
) -> Result<(AnonFeeBody, AXfrKeyPair)> {
    if input.pub_key.ne(input_keypair.pub_key().borrow()) {
        return Err(eg!(ZeiError::ParameterError));
    }
    check_asset_amount(
        vec![input.clone()].as_slice(),
        vec![output.clone()].as_slice(),
    )
    .c(d!())?;

    let mt_leaf_info = input.mt_leaf_info.as_ref().unwrap();
    let rand_input_keypair = input_keypair.randomize(&input.key_rand_factor);
    let diversifier = JubjubScalar::random(prng);
    let nullifier_and_signing_key = (
        nullifier(
            &rand_input_keypair,
            input.amount,
            &input.asset_type,
            mt_leaf_info.uid,
        ),
        rand_input_keypair.pub_key().randomize(&diversifier),
    );

    let payers_secret = PayerSecret {
        sec_key: rand_input_keypair.get_secret_scalar(),
        diversifier,
        uid: mt_leaf_info.uid,
        amount: input.amount,
        asset_type: input.asset_type.as_scalar(),
        path: mt_leaf_info.path.clone(),
        blind: input.blind,
    };
    let payees_secrets = PayeeSecret {
        amount: output.amount,
        blind: output.blind,
        asset_type: output.asset_type.as_scalar(),
    };

    let secret_inputs = AMultiXfrWitness {
        payers_secrets: vec![payers_secret],
        payees_secrets: vec![payees_secrets],
    };
    let proof = prove_xfr(prng, params, secret_inputs).c(d!())?;

    Ok((
        AnonFeeBody {
            input: nullifier_and_signing_key,
            output: AnonBlindAssetRecord::from_oabar(output),
            proof: AXfrProof {
                snark_proof: proof,
                merkle_root: mt_leaf_info.root,
                merkle_root_version: mt_leaf_info.root_version,
            },
            owner_memo: output
                .owner_memo
                .clone()
                .c(d!(ZeiError::ParameterError))
                .c(d!())?,
        },
        rand_input_keypair.randomize(&diversifier),
    ))
}

/// Verifies an anonymous transfer structure AXfrBody.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
#[allow(unused_variables)]
pub fn verify_anon_fee_body(
    params: &NodeParams,
    body: &AnonFeeBody,
    merkle_root: &BLSScalar,
) -> Result<()> {
    if *merkle_root != body.proof.merkle_root {
        return Err(eg!(ZeiError::AXfrVerificationError));
    }

    let pub_inputs = AMultiXfrPubInputs {
        payers_inputs: vec![body.input.clone()],
        payees_commitments: vec![body.output.amount_type_commitment],
        merkle_root: *merkle_root,
    };

    verify_xfr(params, &pub_inputs, &body.proof.snark_proof)
        .c(d!(ZeiError::AXfrVerificationError))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use parking_lot::RwLock;
    use rand_chacha::ChaChaRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use storage::db::TempRocksDB;
    use storage::state::{ChainState, State};
    use storage::store::PrefixedStore;
    use accumulators::merkle_tree::PersistentMerkleTree;
    use algebra::bls12_381::BLSScalar;
    use algebra::groups::Scalar;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use crate::anon_xfr::config::{FEE_CALCULATING_FUNC, FEE_TYPE};
    use crate::anon_xfr::hash_abar;
    use crate::anon_xfr::anon_fee::{AnonFeeNote, gen_anon_fee_body, verify_anon_fee_body};
    use crate::anon_xfr::keys::AXfrKeyPair;
    use crate::anon_xfr::structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord, OpenAnonBlindAssetRecordBuilder};
    use crate::anon_xfr::tests::create_mt_leaf_info;
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::structs::AssetType;

    #[test]
    fn test_anon_fee_happy_path() {

        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let user_params = UserParams::new(1, 1, Some(40));


        let asset_type = FEE_TYPE;
        let fee_amount = FEE_CALCULATING_FUNC(1u32, 1u32) as u64;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount;

        // simulate input abar
        let (mut oabar, keypair_in, _dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, asset_type);
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());
        let rand_keypair_in = keypair_in.randomize(&oabar.get_key_rand_factor());
        assert_eq!(rand_keypair_in.pub_key(), abar.public_key);
        let _owner_memo = oabar.get_owner_memo().unwrap();


        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();

        let id = pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar)).unwrap();
        assert!(pmt.commit().is_ok());
        let proof = pmt.generate_proof(id).unwrap();
        let mt_leaf_info = create_mt_leaf_info(proof);
        oabar.update_mt_leaf_info(mt_leaf_info);

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
            .amount(output_amount)
            .asset_type(asset_type)
            .pub_key(keypair_out.pub_key())
            .finalize(&mut prng, &enc_key_out)
            .unwrap()
            .build()
            .unwrap();

        let (body, key_pairs) = gen_anon_fee_body(
            &mut prng,
            &user_params,
            &oabar,
            &oabar_out,
            &keypair_in,
        )
            .unwrap();

        {
            // verifier scope
            let verifier_params = NodeParams::from(user_params);
            assert!(verify_anon_fee_body(&verifier_params, &body, &pmt.get_root().unwrap()).is_ok());
            assert!(verify_anon_fee_body(&verifier_params, &body, &BLSScalar::from_u64(123u64)).is_err());

            let bad_user_params = UserParams::new(2,1,Some(40));
            let bad_verifier_params = NodeParams::from(bad_user_params);
            assert!(verify_anon_fee_body(&bad_verifier_params, &body, &pmt.get_root().unwrap()).is_err());

            let note = AnonFeeNote::generate_note_from_body(body, key_pairs).unwrap();
            assert!(note.verify_signatures().is_ok());
        }
        {

            let user_params = UserParams::new(1, 1, Some(40));
            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount + 1)
                .asset_type(asset_type)
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            assert!(gen_anon_fee_body(
                &mut prng,
                &user_params,
                &oabar,
                &oabar_out,
                &keypair_in,
            ).is_err());
        }
        {
            let user_params = UserParams::new(1, 1, Some(40));
            let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
                .amount(output_amount)
                .asset_type(AssetType::from_identical_byte(4u8))
                .pub_key(keypair_out.pub_key())
                .finalize(&mut prng, &enc_key_out)
                .unwrap()
                .build()
                .unwrap();

            assert!(gen_anon_fee_body(
                &mut prng,
                &user_params,
                &oabar,
                &oabar_out,
                &keypair_in,
            ).is_err());
        }
    }

    #[test]
    fn test_anon_fee_bad_input() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let user_params = UserParams::new(1, 1, Some(40));


        let asset_type = FEE_TYPE;
        let fee_amount = FEE_CALCULATING_FUNC(1u32, 1u32) as u64;

        let output_amount = 1 + prng.next_u64() % 100;
        let input_amount = output_amount + fee_amount;

        // simulate input abar
        let (mut oabar, keypair_in, _dec_key_in, _) =
            gen_oabar_and_keys(&mut prng, input_amount, AssetType::from_identical_byte(3u8));
        let abar = AnonBlindAssetRecord::from_oabar(&oabar);
        assert_eq!(keypair_in.pub_key(), *oabar.pub_key_ref());
        let rand_keypair_in = keypair_in.randomize(&oabar.get_key_rand_factor());
        assert_eq!(rand_keypair_in.pub_key(), abar.public_key);
        let _owner_memo = oabar.get_owner_memo().unwrap();


        let path = thread::current().name().unwrap().to_owned();
        let fdb = TempRocksDB::open(path).expect("failed to open db");
        let cs = Arc::new(RwLock::new(ChainState::new(fdb, "test_db".to_string(), 0)));
        let mut state = State::new(cs, false);

        let store = PrefixedStore::new("mystore", &mut state);
        let mut pmt = PersistentMerkleTree::new(store).unwrap();

        let id = pmt.add_commitment_hash(hash_abar(pmt.entry_count(), &abar)).unwrap();
        assert!(pmt.commit().is_ok());
        let proof = pmt.generate_proof(id).unwrap();
        let mt_leaf_info = create_mt_leaf_info(proof);
        oabar.update_mt_leaf_info(mt_leaf_info);

        // output keys
        let keypair_out = AXfrKeyPair::generate(&mut prng);
        let dec_key_out = XSecretKey::new(&mut prng);
        let enc_key_out = XPublicKey::from(&dec_key_out);

        let oabar_out = OpenAnonBlindAssetRecordBuilder::new()
            .amount(output_amount)
            .asset_type(asset_type)
            .pub_key(keypair_out.pub_key())
            .finalize(&mut prng, &enc_key_out)
            .unwrap()
            .build()
            .unwrap();

        assert!(gen_anon_fee_body(
            &mut prng,
            &user_params,
            &oabar,
            &oabar_out,
            &keypair_in,
        ).is_err());
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
