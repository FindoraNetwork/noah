use crate::anon_xfr::circuits::{AXfrPubInputs, AXfrWitness};
use crate::anon_xfr::proofs::{prove_single_spend, verify_single_spend};
use crate::anon_xfr::structs::{
  AXfrBody, AXfrProof, AXfrPubKey, AXfrSecKey, AnonAssetRecordTemplate, AnonBlindAssetRecord,
  MTLeafInfo, OpenAnonBlindAssetRecord,
};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::structs::{AssetType, OwnerMemo, ASSET_TYPE_LENGTH};
use algebra::bls12_381::{BLSScalar, BLS_SCALAR_LEN};
use algebra::groups::{Group, GroupArithmetic, Scalar, ScalarArithmetic};
use algebra::jubjub::{JubjubGroup, JubjubScalar, JUBJUB_SCALAR_LEN};
use crypto::basics::hybrid_encryption::{
  hybrid_decrypt_with_x25519_secret_key, hybrid_encrypt_with_x25519_key, XSecretKey,
};
use crypto::basics::prf::PRF;
use rand_core::{CryptoRng, RngCore};
use utils::errors::ZeiError;

#[allow(dead_code)]
pub(crate) mod circuits;
#[allow(dead_code)]
pub(crate) mod proofs;
pub mod structs;

/// Build a anonymous transfer structure AXfrBody. It also returns randomized signature keys to sign the transfer,
/// * `rng` - pseudo-random generator.
/// * `params` - User parameters
/// * `inputs` - Open source asset records
/// * `outputs` - Description of output asset records.
pub fn gen_anon_xfr_body<R: CryptoRng + RngCore>(
  prng: &mut R,
  params: &UserParams,
  inputs: &[OpenAnonBlindAssetRecord],
  outputs: &[AnonAssetRecordTemplate])
  -> Result<(AXfrBody, Vec<AXfrSecKey>), ZeiError> {
  // 1. check input correctness (TODO only single input single output)
  assert_eq!(inputs.len(), 1);
  assert_eq!(outputs.len(), 1);
  assert_eq!(inputs[0].amount, outputs[0].amount);
  assert_eq!(inputs[0].asset_type, outputs[0].asset_type);

  // 2. build output ABAR
  let (out_abar, out_blind, _key_rand, owner_memo) = build_abar(prng, &outputs[0]);

  // 3. build input witness info
  let nullifier = nullifier(&inputs[0].secret_key,
                            inputs[0].amount,
                            &inputs[0].asset_type,
                            inputs[0].mt_leaf_info.uid);
  let diversifier = JubjubScalar::random(prng);
  let signing_key = AXfrPubKey(inputs[0].abar.public_key.0.mul(&diversifier));

  // 4. build proof
  let secret_input = AXfrWitness { sec_key_in: inputs[0].secret_key.0,
                                   diversifier,
                                   uid: inputs[0].mt_leaf_info.uid,
                                   amount: inputs[0].amount,
                                   asset_type: inputs[0].asset_type.as_scalar(),
                                   path: inputs[0].mt_leaf_info.path.clone(),
                                   blind_in: inputs[0].blind,
                                   blind_out: out_blind };
  let proof = prove_single_spend(prng, params, secret_input)?;

  Ok((AXfrBody { inputs: vec![(nullifier, signing_key)],
                 outputs: vec![out_abar],
                 proof: AXfrProof { snark_proof: proof,
                                    merkle_root: inputs[0].mt_leaf_info.root },
                 memo: vec![owner_memo] },
      vec![AXfrSecKey(diversifier.mul(&inputs[0].secret_key.0))]))
}

/// Verifies an anonymous transfer structure AXfrBody.
/// * `params` - Verifier parameters
/// * `body` - Transfer structure to verify
/// * `accumulator` - candidate state of the accumulator. It must match body.proof.merkle_root, otherwise it returns ZeiError::AXfrVerification Error.
pub fn verify_anon_xfr_body(params: &NodeParams,
                            body: &AXfrBody,
                            merkle_root: &BLSScalar)
                            -> Result<(), ZeiError> {
  if *merkle_root != body.proof.merkle_root {
    return Err(ZeiError::AXfrVerificationError);
  }
  let pub_input = AXfrPubInputs { nullifier: body.inputs[0].0,
                                  merkle_root: *merkle_root,
                                  signing_key: body.inputs[0].1.clone(),
                                  recv_amount_type_commitment:
                                    body.outputs[0].amount_type_commitment };
  verify_single_spend(params, &pub_input, &body.proof.snark_proof).map_err(|_| {
                                                                    ZeiError::AXfrVerificationError
                                                                  })
}

fn build_abar<R: CryptoRng + RngCore>(
  prng: &mut R,
  record: &AnonAssetRecordTemplate)
  -> (AnonBlindAssetRecord, BLSScalar, JubjubScalar, OwnerMemo) {
  let rand = JubjubScalar::random(prng);
  let rand_pub_key = record.public_key.randomize(&rand);
  let a = BLSScalar::from_u64(record.amount);
  let at = record.asset_type.as_scalar::<BLSScalar>();
  let blinding = BLSScalar::random(prng);
  let commitment = crypto::basics::commitment::Commitment::new().commit(&blinding, &[a, at])
                                                                .unwrap();
  let mut msg = vec![];
  msg.extend_from_slice(&record.amount.to_le_bytes());
  msg.extend_from_slice(&record.asset_type.0);
  msg.extend_from_slice(&blinding.to_bytes());
  msg.extend_from_slice(&rand.to_bytes());
  let cipher = hybrid_encrypt_with_x25519_key(prng, &record.encryption_key, &msg);
  (AnonBlindAssetRecord { amount_type_commitment: commitment,
                          public_key: rand_pub_key },
   blinding,
   rand,
   OwnerMemo { blind_share: Default::default(),
               lock: cipher })
}

/// Open AnonBlindAssetRecord structure from owner memo and decryption key, appending other
/// parameters to OpenAnonBlindAssetRecord structure.
pub fn open_abar<'a>(abar: &'a AnonBlindAssetRecord,
                     memo: &OwnerMemo,
                     sec_key: &AXfrSecKey,
                     dec_key: &XSecretKey,
                     mt_info: MTLeafInfo)
                     -> Result<OpenAnonBlindAssetRecord<'a>, ZeiError> {
  let (amount, asset_type, blind, key_rand) = decrypt_memo(memo, dec_key, abar)?;
  let secret_key = sec_key.randomize(&key_rand);
  Ok(OpenAnonBlindAssetRecord { amount,
                                asset_type,
                                blind,
                                key_rand,
                                mt_leaf_info: mt_info,
                                secret_key,
                                abar })
}

/// Decrypts the owner memo
/// * `memo` - Owner memo to decrypt
/// * `dec_key` - Decryption key
/// * `abar` - Associated anonymous blind asset record to check memo info against.
/// Return Error if memo info does not match abar's commitment.
/// Return Ok(amount, asset_type, blinding) otherwise
pub fn decrypt_memo(memo: &OwnerMemo,
                    dec_key: &XSecretKey,
                    abar: &AnonBlindAssetRecord)
                    -> Result<(u64, AssetType, BLSScalar, JubjubScalar), ZeiError> {
  let plaintext = hybrid_decrypt_with_x25519_secret_key(&memo.lock, dec_key);
  if plaintext.len() != 8 + ASSET_TYPE_LENGTH + BLS_SCALAR_LEN + JUBJUB_SCALAR_LEN {
    return Err(ZeiError::ParameterError);
  }
  let amount = utils::u8_le_slice_to_u64(&plaintext[0..8]);
  let mut i = 8;
  let mut asset_type_array = [0u8; ASSET_TYPE_LENGTH];
  asset_type_array.copy_from_slice(&plaintext[i..i + ASSET_TYPE_LENGTH]);
  let asset_type = AssetType(asset_type_array);
  i += ASSET_TYPE_LENGTH;
  let blind =
    BLSScalar::from_bytes(&plaintext[i..i + BLS_SCALAR_LEN]).map_err(|_| ZeiError::ParameterError)?;
  i += BLS_SCALAR_LEN;
  let rand =
    JubjubScalar::from_bytes(&plaintext[i..i + JUBJUB_SCALAR_LEN]).map_err(|_| {
                                                                    ZeiError::ParameterError
                                                                  })?;
  crypto::basics::commitment::Commitment::new().verify(&[BLSScalar::from_u64(amount),
                                                         asset_type.as_scalar()],
                                                       &blind,
                                                       &abar.amount_type_commitment)?;
  Ok((amount, asset_type, blind, rand))
}

fn nullifier(secret_key: &AXfrSecKey, amount: u64, asset_type: &AssetType, uid: u64) -> BLSScalar {
  let base = JubjubGroup::get_base();
  let pub_key = base.mul(&secret_key.0);
  let pub_key_x = pub_key.get_x();
  let pub_key_y = pub_key.get_y();

  // TODO From<u128> for ZeiScalar and do let uid_amount = BLSScalar::from(amount as u128 + ((uid as u128) << 64));
  let pow_2_64 = BLSScalar::from_u64(u64::max_value()).add(&BLSScalar::from_u32(1));
  let uid_shifted = BLSScalar::from_u64(uid).mul(&pow_2_64);
  let uid_amount = uid_shifted.add(&BLSScalar::from_u64(amount));
  PRF::new().eval(&BLSScalar::from(&secret_key.0),
                  &[uid_amount, asset_type.as_scalar(), pub_key_x, pub_key_y])
}

#[cfg(test)]
mod tests {
  use crate::anon_xfr::structs::{
    AXfrPubKey, AXfrSecKey, AnonAssetRecordTemplate, MTLeafInfo, MTNode, MTPath,
  };
  use crate::anon_xfr::{
    build_abar, decrypt_memo, gen_anon_xfr_body, open_abar, verify_anon_xfr_body,
  };
  use crate::setup::{NodeParams, UserParams, DEFAULT_BP_NUM_GENS};
  use crate::xfr::structs::AssetType;
  use algebra::bls12_381::BLSScalar;
  use algebra::groups::{Group, GroupArithmetic, One, Scalar, ScalarArithmetic, Zero};
  use algebra::jubjub::{JubjubGroup, JubjubScalar};
  use crypto::basics::hash::rescue::RescueInstance;
  use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  #[test]
  fn test_anon_xfr() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    //let user_params = UserParams::new(Some(1), 4100);
    let user_params = UserParams::from_file_if_exists(1, 4100, DEFAULT_BP_NUM_GENS, None).unwrap();

    let zero = BLSScalar::zero();
    let one = BLSScalar::one();
    let two = one.add(&one);

    // define input and current state
    let sk_in = AXfrSecKey(JubjubScalar::random(&mut prng));
    let pk_in = AXfrPubKey(JubjubGroup::get_base().mul(&sk_in.0));
    let dec_key_in = XSecretKey::new(&mut prng);
    let enc_key_in = XPublicKey::from(&dec_key_in);

    // simulate input abar
    let amount = 10u64;
    let asset_type = AssetType::from_identical_byte(0);
    let (in_abar, in_blind, key_rand_factor, in_memo) =
      build_abar(&mut prng,
                 &AnonAssetRecordTemplate { amount,
                                            asset_type,
                                            public_key: pk_in,
                                            encryption_key: enc_key_in });
    // simulate merklee tree state
    let rand_pk_in = &in_abar.public_key;
    let node = MTNode { siblings1: one,
                        siblings2: two,
                        is_left_child: 0u8,
                        is_right_child: 1u8 };
    let hash = RescueInstance::new();
    let pk_in_hash = hash.rescue_hash(&[rand_pk_in.0.get_x(), rand_pk_in.0.get_y(), zero, zero])[0];
    let leaf = hash.rescue_hash(&[/*uid=*/ two,
                                  in_abar.amount_type_commitment,
                                  pk_in_hash,
                                  zero])[0];
    let merkle_root = hash.rescue_hash(&[/*sib1[0]=*/ one, /*sib2[0]=*/ two, leaf, zero])[0];

    // output keys
    let sk_out = AXfrSecKey(JubjubScalar::random(&mut prng));
    let pk_out = AXfrPubKey(JubjubGroup::get_base().mul(&sk_out.0));
    let dec_key_out = XSecretKey::new(&mut prng);
    let enc_key_out = XPublicKey::from(&dec_key_out);

    let (body, merkle_root) = {
      // prover scope
      let mt_info = MTLeafInfo { path: MTPath { nodes: vec![node] },
                                 root: merkle_root,
                                 uid: 2 };

      let open_abar_in = open_abar(&in_abar, &in_memo, &sk_in, &dec_key_in, mt_info).unwrap();
      let rand_sk_in = sk_in.randomize(&open_abar_in.key_rand);
      assert_eq!(amount, open_abar_in.amount);
      assert_eq!(asset_type, open_abar_in.asset_type);
      assert_eq!(in_blind, open_abar_in.blind);
      assert_eq!(key_rand_factor, open_abar_in.key_rand);
      assert_eq!(rand_sk_in, open_abar_in.secret_key);

      let out_template = AnonAssetRecordTemplate { amount,
                                                   asset_type,
                                                   public_key: pk_out.clone(),
                                                   encryption_key: enc_key_out };
      let (body, _) =
        gen_anon_xfr_body(&mut prng, &user_params, &[open_abar_in], &[out_template]).unwrap();
      (body, merkle_root)
    };
    {
      // owner scope
      let memo = &body.memo[0];
      let (dec_amount, dec_asset_type, _, key_rand_factor) =
        decrypt_memo(memo, &dec_key_out, &body.outputs[0]).unwrap();
      let rand_pk = pk_out.randomize(&key_rand_factor);
      assert_eq!(amount, dec_amount);
      assert_eq!(asset_type, dec_asset_type);
      assert_eq!(rand_pk, body.outputs[0].public_key);
    }
    {
      // verifier scope
      let verifier_params = NodeParams::from(user_params);
      assert!(verify_anon_xfr_body(&verifier_params, &body, &merkle_root).is_ok())
    }
  }
}
