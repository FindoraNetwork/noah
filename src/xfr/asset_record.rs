use crate::algebra::groups::Scalar as ZeiScalar;
use crate::basic_crypto::elgamal::elgamal_encrypt;
use crate::basic_crypto::hybrid_encryption::{hybrid_decrypt, hybrid_encrypt};
use crate::errors::ZeiError;
use crate::utils::{
  u64_to_bigendian_u8array, u64_to_u32_pair, u8_bigendian_slice_to_u128, u8_bigendian_slice_to_u64,
};
use crate::xfr::lib::XfrType;
use crate::xfr::sig::{XfrPublicKey, XfrSecretKey};
use crate::xfr::structs::{AssetIssuerPubKeys, AssetRecord, BlindAssetRecord, OpenAssetRecord};
use bulletproofs::PedersenGens;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum AssetRecordType {
  PublicAmount_ConfidentialAssetType,
  ConfidentialAmount_PublicAssetType,
  ConfidentialAmount_ConfidentialAssetType,
  PublicAmount_PublicAssetType,
}

impl From<XfrType> for AssetRecordType {
  fn from(record: XfrType) -> AssetRecordType {
    match record {
      XfrType::PublicAmount_PublicAssetType_SingleAsset => {
        AssetRecordType::PublicAmount_PublicAssetType
      }
      XfrType::PublicAmount_ConfidentialAssetType_SingleAsset => {
        AssetRecordType::PublicAmount_ConfidentialAssetType
      }
      XfrType::ConfidentialAmount_PublicAssetType_SingleAsset => {
        AssetRecordType::ConfidentialAmount_PublicAssetType
      }
      XfrType::ConfidentialAmount_ConfidentialAssetType_SingleAsset => {
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType
      }
      XfrType::ConfidentialAmount_ConfidentialAssetType_MultiAsset => {
        AssetRecordType::ConfidentialAmount_ConfidentialAssetType
      }
      XfrType::PublicAmount_PublicAssetType_MultiAsset => {
        AssetRecordType::PublicAmount_PublicAssetType
      }
    }
  }
}

impl AssetRecordType {
  /// Return (true,_) if amount is confidential,
  /// Return (_,false) if type is confidential,
  pub fn get_booleans(self) -> (bool, bool) {
    // confidential amount, confidential asset type
    match self {
      AssetRecordType::PublicAmount_PublicAssetType => (false, false),
      AssetRecordType::ConfidentialAmount_PublicAssetType => (true, false),
      AssetRecordType::PublicAmount_ConfidentialAssetType => (false, true),
      AssetRecordType::ConfidentialAmount_ConfidentialAssetType => (true, true),
    }
  }

  pub fn from_booleans(conf_amt: bool, conf_type: bool) -> Self {
    match (conf_amt, conf_type) {
      (false, false) => AssetRecordType::PublicAmount_PublicAssetType,
      (true, false) => AssetRecordType::ConfidentialAmount_PublicAssetType,
      (false, true) => AssetRecordType::PublicAmount_ConfidentialAssetType,
      (true, true) => AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
    }
  }
}

fn sample_blind_asset_record<R: CryptoRng + RngCore>(
  prng: &mut R,
  pc_gens: &PedersenGens,
  asset_record: &AssetRecord,
  record_type: AssetRecordType,
  issuer_public_key: &Option<AssetIssuerPubKeys>)
  -> (BlindAssetRecord, (Scalar, Scalar), Scalar) {
  let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
  let type_scalar = Scalar::from(type_as_u128);
  let (derived_point, blind_share) = sample_point_and_blind_share(prng, &asset_record.public_key);
  let type_blind = compute_blind_factor(&derived_point, "asset_type");
  let amount_blind_low = compute_blind_factor(&derived_point, "amount_low");
  let amount_blind_high = compute_blind_factor(&derived_point, "amount_high");
  let (amount_low, amount_high) = u64_to_u32_pair(asset_record.amount);
  let mut amount_type_bytes = vec![];

  let (confidential_amount, confidential_asset) = match record_type {
    AssetRecordType::PublicAmount_PublicAssetType => (false, false),
    AssetRecordType::ConfidentialAmount_PublicAssetType => (true, false),
    AssetRecordType::PublicAmount_ConfidentialAssetType => (false, true),
    AssetRecordType::ConfidentialAmount_ConfidentialAssetType => (true, true),
  };

  // build amount fields
  let (bar_amount, bar_amount_commitments, amount_blinds) = if confidential_amount {
    let amount_bytes = u64_to_bigendian_u8array(asset_record.amount);
    amount_type_bytes.extend_from_slice(&amount_bytes[..]);

    let amount_commitment_low = pc_gens.commit(Scalar::from(amount_low), amount_blind_low);
    let amount_commitment_high = pc_gens.commit(Scalar::from(amount_high), amount_blind_high);

    (None,
     Some((amount_commitment_low.compress(), amount_commitment_high.compress())),
     (amount_blind_low, amount_blind_high))
  } else {
    (Some(asset_record.amount), None, (Scalar::default(), Scalar::default()))
  };

  // build asset type fields
  let (bar_type, bar_type_commitment, type_blind) = if confidential_asset {
    amount_type_bytes.extend_from_slice(&asset_record.asset_type);

    let type_commitment = pc_gens.commit(type_scalar, type_blind);
    (None, Some(type_commitment.compress()), type_blind)
  } else {
    (Some(asset_record.asset_type), None, Scalar::default())
  };

  //issuer asset tracking amount
  let issuer_lock_amount = match issuer_public_key {
    None => None,
    Some(issuer_pk) => {
      if confidential_amount {
        Some((elgamal_encrypt(&pc_gens.B,
                              &Scalar::from_u32(amount_low),
                              &amount_blind_low,
                              &issuer_pk.eg_ristretto_pub_key),
              elgamal_encrypt(&pc_gens.B,
                              &Scalar::from_u32(amount_high),
                              &amount_blind_high,
                              &issuer_pk.eg_ristretto_pub_key)))
      } else {
        None
      }
    }
  };
  //issuer asset tracking asset type
  let issuer_lock_type = match issuer_public_key {
    None => None,
    Some(issuer_pk) => {
      if confidential_asset {
        Some(elgamal_encrypt(&pc_gens.B,
                             &type_scalar,
                             &type_blind,
                             &issuer_pk.eg_ristretto_pub_key))
      } else {
        None
      }
    }
  };
  // compute lock of amount and/or type
  let lock = if !amount_type_bytes.is_empty() {
    Some(hybrid_encrypt(prng,
                        &asset_record.public_key.0,
                        amount_type_bytes.as_slice()).unwrap())
  } else {
    None
  };

  let blind_asset_record = BlindAssetRecord { issuer_public_key: issuer_public_key.clone(), //None if issuer tracking is not required
                                              issuer_lock_type,
                                              issuer_lock_amount,
                                              amount: bar_amount,
                                              asset_type: bar_type,
                                              public_key: asset_record.public_key,
                                              amount_commitments: bar_amount_commitments,
                                              asset_type_commitment: bar_type_commitment,
                                              blind_share,
                                              lock };

  (blind_asset_record, amount_blinds, type_blind)
}

/// build complete OpenAssetRecord from AssetRecord structure
pub fn build_open_asset_record<R: CryptoRng + RngCore>(prng: &mut R,
                                                       pc_gens: &PedersenGens,
                                                       asset_record: &AssetRecord,
                                                       record_type: AssetRecordType,
                                                       issuer_public_key: &Option<AssetIssuerPubKeys> //none if no tracking is required
) -> OpenAssetRecord {
  let (blind_asset_record, amount_blinds, type_blind) =
    sample_blind_asset_record(prng, pc_gens, asset_record, record_type, issuer_public_key);

  let open_asset_record = OpenAssetRecord { asset_record: blind_asset_record,
                                            amount: asset_record.amount,
                                            amount_blinds,
                                            asset_type: asset_record.asset_type,
                                            type_blind };

  open_asset_record
}

/// build BlindAssetRecord from AssetRecord structure
pub fn build_blind_asset_record<R: CryptoRng + RngCore>(prng: &mut R,
                                                        pc_gens: &PedersenGens,
                                                        asset_record: &AssetRecord,
                                                        record_type: AssetRecordType,
                                                        issuer_public_key: &Option<AssetIssuerPubKeys> //none if no tracking is required
) -> BlindAssetRecord {
  let (blind_asset_record, _, _) =
    sample_blind_asset_record(prng, pc_gens, asset_record, record_type, issuer_public_key);

  blind_asset_record
}

fn sample_point_and_blind_share<R: CryptoRng + RngCore>(
  prng: &mut R,
  public_key: &XfrPublicKey)
  -> (CompressedEdwardsY, CompressedEdwardsY) {
  let blind_key = Scalar::random(prng);
  let pk_point = public_key.get_curve_point().unwrap();
  let derived_point: EdwardsPoint = blind_key * pk_point;
  let blind_share = blind_key * ED25519_BASEPOINT_POINT;
  (derived_point.compress(), blind_share.compress())
}

fn derive_point_from_blind_share(blind_share: &CompressedEdwardsY,
                                 secret_key: &XfrSecretKey)
                                 -> Result<CompressedEdwardsY, ZeiError> {
  let blind_share_decompressed = blind_share.decompress()
                                            .ok_or(ZeiError::DecompressElementError)?;
  Ok(secret_key.as_scalar_multiply_by_curve_point(&blind_share_decompressed)
               .compress())
}

fn compute_blind_factor(point: &CompressedEdwardsY, aux: &str) -> Scalar {
  let mut hasher = Sha512::new();
  hasher.input(point.as_bytes());
  hasher.input(aux.as_bytes());
  Scalar::from_hash(hasher)
}

/// I use the address secret key to compute the blinding factors for commitments in a BlindAssetRecord
pub fn open_asset_record(input: &BlindAssetRecord,
                         secret_key: &XfrSecretKey)
                         -> Result<OpenAssetRecord, ZeiError> {
  let confidential_amount = input.amount.is_none();
  let confidential_asset = input.asset_type.is_none();
  let amount;
  let mut asset_type = [0u8; 16];
  let amount_blind_low;
  let amount_blind_high;
  let type_blind;
  let shared_point = derive_point_from_blind_share(&input.blind_share, secret_key)?;

  let mut i = 0;
  let amount_type = match &input.lock {
    None => vec![],
    Some(ctext) => hybrid_decrypt(ctext, &secret_key.0)?,
  };
  if confidential_amount {
    amount = u8_bigendian_slice_to_u64(&amount_type[0..8]);
    amount_blind_low = compute_blind_factor(&shared_point, "amount_low");
    amount_blind_high = compute_blind_factor(&shared_point, "amount_high");
    i += 8;
  } else {
    amount = input.amount.unwrap();
    amount_blind_low = Scalar::default();
    amount_blind_high = Scalar::default();
  }

  if confidential_asset {
    asset_type.copy_from_slice(&amount_type[i..i + 16]);
    type_blind = compute_blind_factor(&shared_point, "asset_type");
  } else {
    asset_type = input.asset_type.unwrap();
    type_blind = Scalar::default();
  }

  Ok(OpenAssetRecord { asset_type,
                       amount,
                       asset_record: input.clone(),
                       amount_blinds: (amount_blind_low, amount_blind_high),
                       type_blind })
}

#[cfg(test)]
mod test {
  use super::{build_blind_asset_record, build_open_asset_record, open_asset_record};
  use crate::algebra::bls12_381::{BLSScalar, BLSG1};
  use crate::algebra::groups::Group;
  use crate::basic_crypto::elgamal::{elgamal_keygen, ElGamalPublicKey};
  use crate::utils::{u64_to_u32_pair, u8_bigendian_slice_to_u128};
  use crate::xfr::asset_record::AssetRecordType;
  use crate::xfr::lib::tests::create_xfr;
  use crate::xfr::lib::XfrType;
  use crate::xfr::sig::XfrKeyPair;
  use crate::xfr::structs::{AssetIssuerPubKeys, AssetRecord, AssetType, OpenAssetRecord};
  use bulletproofs::PedersenGens;
  use curve25519_dalek::ristretto::RistrettoPoint;
  use curve25519_dalek::scalar::Scalar;
  use rand::Rng;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  fn do_test_build_open_asset_record(record_type: AssetRecordType, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let amount = 100u64;
    let asset_type = [0u8; 16];
    let keypair = XfrKeyPair::generate(&mut prng);
    let asset_record = AssetRecord { amount,
                                     asset_type,
                                     public_key: keypair.get_pk_ref().clone() };

    let issuer_public_key = match asset_tracking {
      true => {
        let (_sk, xfr_pub_key) = elgamal_keygen::<_, Scalar, RistrettoPoint>(&mut prng, &pc_gens.B);
        let (_sk, id_reveal_pub_key) =
          elgamal_keygen::<_, BLSScalar, BLSG1>(&mut prng, &BLSG1::get_base());
        Some(AssetIssuerPubKeys { eg_ristretto_pub_key:
                                    ElGamalPublicKey(xfr_pub_key.get_point()),
                                  eg_blsg1_pub_key: id_reveal_pub_key })
      }
      false => None,
    };

    let open_ar = build_open_asset_record(&mut prng,
                                          &pc_gens,
                                          &asset_record,
                                          record_type,
                                          &issuer_public_key);

    assert_eq!(amount, open_ar.amount);
    assert_eq!(asset_type, open_ar.asset_type);
    assert_eq!(keypair.get_pk_ref(), &open_ar.asset_record.public_key);

    let mut expected_bar_amount = None;
    let mut expected_bar_asset_type = None;
    let mut expected_bar_amount_commitment = None;
    let mut expected_bar_asset_type_commitment = None;

    let (confidential_amount, confidential_asset) = record_type.get_booleans();
    if confidential_amount {
      let (low, high) = u64_to_u32_pair(amount);
      let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0)
                                  .compress();
      let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1)
                                   .compress();
      expected_bar_amount_commitment = Some((commitment_low, commitment_high));
    } else {
      expected_bar_amount = Some(amount);
      //expected_bar_lock_amount_none = true;
    }

    if confidential_asset {
      let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
      let type_scalar = Scalar::from(type_as_u128);
      expected_bar_asset_type_commitment =
        Some(pc_gens.commit(type_scalar, open_ar.type_blind).compress());
    } else {
      expected_bar_asset_type = Some(asset_type);
      //expected_bar_lock_type_none = true;
    }
    assert_eq!(expected_bar_amount, open_ar.asset_record.amount);
    assert_eq!(expected_bar_amount_commitment,
               open_ar.asset_record.amount_commitments);
    /*assert_eq!(expected_bar_lock_amount_none,
    open_ar.asset_record.lock_amount.is_none());
    */
    assert_eq!(expected_bar_asset_type, open_ar.asset_record.asset_type);
    assert_eq!(expected_bar_asset_type_commitment,
               open_ar.asset_record.asset_type_commitment);
    assert_eq!(confidential_asset || confidential_amount,
               open_ar.asset_record.lock.is_some());
    /*assert_eq!(expected_bar_lock_type_none,
    open_ar.asset_record.lock_type.is_none());*/

    assert_eq!(asset_tracking,
               open_ar.asset_record.issuer_public_key.is_some());
    assert_eq!(asset_tracking && confidential_asset,
               open_ar.asset_record.issuer_lock_type.is_some());
    assert_eq!(asset_tracking && confidential_amount,
               open_ar.asset_record.issuer_lock_amount.is_some());
  }

  #[test]
  fn test_build_open_asset_record() {
    do_test_build_open_asset_record(AssetRecordType::PublicAmount_PublicAssetType, false);
    do_test_build_open_asset_record(AssetRecordType::PublicAmount_PublicAssetType, true);
    do_test_build_open_asset_record(AssetRecordType::PublicAmount_ConfidentialAssetType, false);
    do_test_build_open_asset_record(AssetRecordType::PublicAmount_ConfidentialAssetType, true);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_PublicAssetType, false);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_PublicAssetType, true);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                    false);
    do_test_build_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                    true);
  }

  fn do_test_open_asset_record(record_type: AssetRecordType, asset_tracking: bool) {
    let mut prng: ChaChaRng;
    prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let asset_type = [1u8; 16];
    let input_amount = [(10u64, asset_type), (20u64, asset_type)];
    let out_amount = [(30u64, asset_type)];

    let (xfr_note, _, _, _, outkeys) = create_xfr(&mut prng,
                                                  &input_amount,
                                                  &out_amount,
                                                  XfrType::from(record_type),
                                                  asset_tracking);

    let secret_key = outkeys.get(0).unwrap().get_sk_ref();
    let open_ar = open_asset_record(&xfr_note.body.outputs[0], secret_key).unwrap();

    assert_eq!(&open_ar.asset_record, &xfr_note.body.outputs[0]);
    assert_eq!(open_ar.amount, 30u64);
    assert_eq!(open_ar.asset_type, [1u8; 16]);

    let (confidential_amount, confidential_asset) = record_type.get_booleans();

    if confidential_amount {
      let (low, high) = u64_to_u32_pair(open_ar.amount);
      let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0)
                                  .compress();
      let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1)
                                   .compress();
      let derived_commitment = (commitment_low, commitment_high);
      assert_eq!(derived_commitment,
                 open_ar.asset_record.amount_commitments.unwrap());
    }

    if confidential_asset {
      let derived_commitment =
        pc_gens.commit(Scalar::from(u8_bigendian_slice_to_u128(&open_ar.asset_type[..])),
                       open_ar.type_blind)
               .compress();
      assert_eq!(derived_commitment,
                 open_ar.asset_record.asset_type_commitment.unwrap());
    }
  }

  #[test]
  fn test_open_asset_record() {
    do_test_open_asset_record(AssetRecordType::PublicAmount_PublicAssetType, false);
    do_test_open_asset_record(AssetRecordType::PublicAmount_ConfidentialAssetType, false);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_PublicAssetType, false);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                              false);
    do_test_open_asset_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                              true);
  }

  fn build_and_open_blind_record(record_type: AssetRecordType, amt: u64, asset_type: AssetType) {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let pc_gens = PedersenGens::default();

    let keypair = XfrKeyPair::generate(&mut prng);
    let (pubkey, privkey) = (keypair.get_pk_ref(), keypair.get_sk_ref());
    let ar = AssetRecord::new(amt, asset_type, pubkey.clone()).unwrap();

    let blind_rec = build_blind_asset_record(&mut prng, &pc_gens, &ar, record_type, &None);

    let open_rec = open_asset_record(&blind_rec, &privkey).unwrap();

    assert!(*open_rec.get_amount() == amt);
    assert!(*open_rec.get_asset_type() == asset_type);

    let oar_bytes = serde_json::to_string(&open_rec).unwrap();
    let oar_de: OpenAssetRecord = serde_json::from_str(oar_bytes.as_str()).unwrap();
    assert_eq!(open_rec, oar_de);
  }

  #[test]
  fn test_build_and_open_blind_record() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let asset_type: AssetType = prng.gen();
    let amt: u64 = prng.gen();

    build_and_open_blind_record(AssetRecordType::PublicAmount_PublicAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::PublicAmount_ConfidentialAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::ConfidentialAmount_PublicAssetType,
                                amt,
                                asset_type);
    build_and_open_blind_record(AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                amt,
                                asset_type);
  }
}
