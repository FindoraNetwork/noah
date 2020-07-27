use crate::algebra::bls12_381::{BLSScalar, BLSG1};
use crate::algebra::groups::{Group, GroupArithmetic, Scalar as ZeiScalar};
use crate::api::anon_creds::AttributeCiphertext;
use crate::basic_crypto::elgamal::{
  elgamal_decrypt, elgamal_decrypt_elem, elgamal_encrypt, elgamal_key_gen, ElGamalCiphertext,
  ElGamalDecKey, ElGamalEncKey,
};
use crate::errors::ZeiError;
use crate::utils::u64_to_u32_pair;
use crate::xfr::structs::AssetType;
use crate::xfr::structs::{
  asset_type_to_scalar, AssetTracerDecKeys, AssetTracerEncKeys, AssetTracerKeyPair, AssetTracerMemo,
};
use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

pub type RecordDataEncKey = ElGamalEncKey<RistrettoPoint>;
pub type RecordDataDecKey = ElGamalDecKey<Scalar>;
pub type RecordDataCiphertext = ElGamalCiphertext<RistrettoPoint>;

pub fn gen_asset_tracer_keypair<R: CryptoRng + RngCore>(prng: &mut R) -> AssetTracerKeyPair {
  let (record_data_dec_key, record_data_enc_key) =
    elgamal_key_gen(prng, &RistrettoPoint::get_base());
  let (attrs_dec_key, attrs_enc_key) = elgamal_key_gen(prng, &BLSG1::get_base());
  AssetTracerKeyPair { enc_key: AssetTracerEncKeys { record_data_enc_key,
                                                     attrs_enc_key },
                       dec_key: AssetTracerDecKeys { record_data_dec_key,
                                                     attrs_dec_key } }
}

impl AssetTracerMemo {
  /// Sample a new AssetTracerMemo
  pub fn new(tracer_enc_key: &AssetTracerEncKeys,
             amount_info: Option<(u32, u32, &Scalar, &Scalar)>, //amount low and high and blindings
             asset_type_info: Option<(Scalar, &Scalar)>,
             attributes: Option<Vec<AttributeCiphertext>>)
             -> AssetTracerMemo {
    let pc_gens = PedersenGens::default();
    let lock_amount =
      amount_info.map(|(amount_low, amount_high, blind_low, blind_high)| {
                   let ctext_amount_low = elgamal_encrypt(&pc_gens.B,
                                                          &Scalar::from_u32(amount_low),
                                                          blind_low,
                                                          &tracer_enc_key.record_data_enc_key);
                   let ctext_amount_high = elgamal_encrypt(&pc_gens.B,
                                                           &Scalar::from_u32(amount_high),
                                                           blind_high,
                                                           &tracer_enc_key.record_data_enc_key);
                   (ctext_amount_low, ctext_amount_high)
                 });

    let lock_asset_type = asset_type_info.map(|(type_scalar, blind)| {
                                           elgamal_encrypt(&pc_gens.B,
                                                           &type_scalar,
                                                           blind,
                                                           &tracer_enc_key.record_data_enc_key)
                                         });

    AssetTracerMemo { enc_key: tracer_enc_key.clone(),
                      lock_amount,
                      lock_asset_type,
                      lock_attributes: attributes }
  }

  /// Check is the amount encrypted in self.lock_amount is expected_amount
  /// If self.lock_amount is None, return Err(ZeiError::ParameterError)
  /// Otherwise, if decrypted amount is not expected amount, return Err(ZeiError::AssetTracingExtractionError), else Ok(())
  pub fn verify_amount(&self,
                       dec_key: &ElGamalDecKey<Scalar>,
                       expected_amount: u64)
                       -> Result<(), ZeiError> {
    let (low, high) = u64_to_u32_pair(expected_amount);
    if let Some((ctext_low, ctext_high)) = self.lock_amount.as_ref() {
      let decrypted_low = elgamal_decrypt_elem(ctext_low, dec_key);
      let decrypted_high = elgamal_decrypt_elem(ctext_high, dec_key);
      let base = RistrettoPoint::get_base();
      if base * Scalar::from(low) != decrypted_low || base * Scalar::from(high) != decrypted_high {
        Err(ZeiError::AssetTracingExtractionError)
      } else {
        Ok(())
      }
    } else {
      Err(ZeiError::ParameterError) // nothing to decrypt
    }
  }

  /// Decrypt amount in self.lock_amount via brute force check taking 2^33 Ristretto additions in the worst case.
  /// If self.lock_amount is None, return Err(ZeiError::ParameterError)
  /// Otherwise, return Scalar representing the amount
  pub fn extract_amount_brute_force(&self,
                                    dec_key: &ElGamalDecKey<Scalar>)
                                    -> Result<u64, ZeiError> {
    if let Some((ctext_low, ctext_high)) = self.lock_amount.as_ref() {
      let base = RistrettoPoint::get_base();
      let decrypted_low = elgamal_decrypt(&base, ctext_low, dec_key)?;
      let decrypted_high = elgamal_decrypt(&base, ctext_high, dec_key)?;
      let result = decrypted_low + decrypted_high * (1u64 << 32);
      Ok(result)
    } else {
      Err(ZeiError::ParameterError) // nothing to decrypt
    }
  }

  /// Decrypt asset_type in self.lock_asset_type via a linear scan over candidate_asset_types
  /// If self.lock_asset_type is None, return Err(ZeiError::ParameterError)
  /// Otherwise, if decrypted asset_type is not in the candidate list return Err(ZeiError::AssetTracingExtractionError),
  /// else return the decrypted asset_type.
  pub fn extract_asset_type(&self,
                            dec_key: &ElGamalDecKey<Scalar>,
                            candidate_asset_types: &[AssetType])
                            -> Result<AssetType, ZeiError> {
    if candidate_asset_types.is_empty() {
      return Err(ZeiError::ParameterError);
    }
    if let Some(ctext) = self.lock_asset_type.as_ref() {
      let decrypted = elgamal_decrypt_elem(ctext, dec_key);
      for candidate in candidate_asset_types.iter() {
        let scalar_candidate = asset_type_to_scalar(candidate);
        if decrypted == RistrettoPoint::get_base() * scalar_candidate {
          return Ok(*candidate);
        }
      }
      Err(ZeiError::AssetTracingExtractionError)
    } else {
      Err(ZeiError::ParameterError) // nothing to decrypt
    }
  }

  /// Check is the attributes encrypted in self.lock_attrs are the same as in expected_attributes
  /// If self.lock_attrs is None or if attribute length doesn't match expected list, return Err(ZeiError::ParameterError)
  /// Otherwise, it returns a boolean vector indicating true for every positive match and false otherwise.
  pub fn verify_identity_attributes(&self,
                                    dec_key: &ElGamalDecKey<BLSScalar>,
                                    expected_attributes: &[u32])
                                    -> Result<Vec<bool>, ZeiError> {
    if let Some(ctexts) = self.lock_attributes.as_ref() {
      if ctexts.len() != expected_attributes.len() {
        return Err(ZeiError::ParameterError);
      }
      let mut result = vec![];
      for (ctext, expected) in ctexts.iter().zip(expected_attributes.iter()) {
        let scalar_attr = BLSScalar::from_u32(*expected);
        let elem = elgamal_decrypt_elem(ctext, dec_key);
        if elem != BLSG1::get_base().mul(&scalar_attr) {
          result.push(false);
        } else {
          result.push(true);
        }
      }
      Ok(result)
    } else {
      Err(ZeiError::ParameterError) // nothing to decrypt
    }
  }

  /// Check is the attributes encrypted in self.lock_attrs are the same as in expected_attributes
  /// If self.lock_attrs is None or if attribute length doesn't match expected list, return Err(ZeiError::ParameterError)
  /// Otherwise, it returns a boolean vector indicating true for every positive match and false otherwise.
  pub fn extract_identity_attributes_brute_force(&self,
                                                 dec_key: &ElGamalDecKey<BLSScalar>)
                                                 -> Result<Vec<u32>, ZeiError> {
    if let Some(ctexts) = self.lock_attributes.as_ref() {
      let mut result = vec![];
      let base = BLSG1::get_base();
      for ctext in ctexts {
        let attr = elgamal_decrypt(&base, ctext, dec_key)? as u32;
        result.push(attr);
      }
      Ok(result)
    } else {
      Err(ZeiError::ParameterError)
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::algebra::groups::{Group, Scalar as ZeiScalar};
  use crate::basic_crypto::elgamal::{elgamal_encrypt, elgamal_key_gen};
  use crate::xfr::structs::{asset_type_to_scalar, AssetTracerEncKeys, AssetTracerMemo, AssetType};
  use curve25519_dalek::ristretto::RistrettoPoint;
  use rand_chacha::ChaChaRng;
  use rand_core::SeedableRng;

  use crate::algebra::bls12_381::{BLSScalar, BLSG1};
  use crate::api::anon_creds::ac_confidential_gen_encryption_keys;
  use crate::errors::ZeiError;
  use crate::utils::u64_to_u32_pair;
  use curve25519_dalek::scalar::Scalar;
  use itertools::Itertools;

  #[test]
  fn extract_amount_from_tracer_memo() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let ristretto_keypair = elgamal_key_gen(&mut prng, &RistrettoPoint::get_base());
    let blsg1_keypair = ac_confidential_gen_encryption_keys(&mut prng);
    let asset_tracer_pub_key = AssetTracerEncKeys { record_data_enc_key: ristretto_keypair.1,
                                                    attrs_enc_key: blsg1_keypair.1 };
    let memo = AssetTracerMemo { enc_key: asset_tracer_pub_key.clone(),
                                 lock_amount: None,
                                 lock_asset_type: None,
                                 lock_attributes: None };
    assert!(memo.verify_amount(&ristretto_keypair.0, 10).is_err());

    let amount = (1u64 << 40) + 500; // low and high are small u32 numbers
    let (low, high) = u64_to_u32_pair(amount);
    let base = RistrettoPoint::get_base();
    let memo =
      AssetTracerMemo { enc_key: asset_tracer_pub_key.clone(),
                        lock_amount:
                          Some((elgamal_encrypt(&base,
                                                &Scalar::from(low),
                                                &Scalar::from(191919u32),
                                                &asset_tracer_pub_key.record_data_enc_key),
                                elgamal_encrypt(&base,
                                                &Scalar::from(high),
                                                &Scalar::from(2222u32),
                                                &asset_tracer_pub_key.record_data_enc_key))),
                        lock_asset_type: None,
                        lock_attributes: None };
    assert!(memo.verify_amount(&ristretto_keypair.0, amount).is_ok());

    assert!(memo.extract_amount_brute_force(&ristretto_keypair.0)
                .is_ok());
  }

  #[test]
  fn extract_asset_type_from_tracer_memo() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let ristretto_keypair = elgamal_key_gen(&mut prng, &RistrettoPoint::get_base());
    let blsg1_keypair = ac_confidential_gen_encryption_keys(&mut prng);
    let asset_tracer_pub_key = AssetTracerEncKeys { record_data_enc_key: ristretto_keypair.1,
                                                    attrs_enc_key: blsg1_keypair.1 };
    let memo = AssetTracerMemo { enc_key: asset_tracer_pub_key.clone(),
                                 lock_amount: None,
                                 lock_asset_type: None,
                                 lock_attributes: None };
    assert!(memo.extract_asset_type(&ristretto_keypair.0, &[]).is_err());

    let asset_type = AssetType::from_identical_byte(2u8);
    let base = RistrettoPoint::get_base();
    let memo =
      AssetTracerMemo { enc_key: asset_tracer_pub_key.clone(),
                        lock_amount: None,
                        lock_asset_type:
                          Some(elgamal_encrypt(&base,
                                               &Scalar::from(asset_type_to_scalar(&asset_type)),
                                               &Scalar::from(191919u32),
                                               &asset_tracer_pub_key.record_data_enc_key)),
                        lock_attributes: None };
    assert_eq!(memo.extract_asset_type(&ristretto_keypair.0, &[]),
               Err(ZeiError::ParameterError));
    assert_eq!(memo.extract_asset_type(&ristretto_keypair.0,
                                       &[AssetType::from_identical_byte(0u8)]),
               Err(ZeiError::AssetTracingExtractionError));
    assert_eq!(memo.extract_asset_type(&ristretto_keypair.0,
                                       &[AssetType::from_identical_byte(0u8),
                                         AssetType::from_identical_byte(1u8)]),
               Err(ZeiError::AssetTracingExtractionError));
    assert!(memo.extract_asset_type(&ristretto_keypair.0,
                                    &[AssetType::from_identical_byte(0u8),
                                      AssetType::from_identical_byte(1u8),
                                      asset_type])
                .is_ok());
    assert!(memo.extract_asset_type(&ristretto_keypair.0,
                                    &[asset_type,
                                      AssetType::from_identical_byte(0u8),
                                      AssetType::from_identical_byte(1u8)])
                .is_ok());
    assert!(memo.extract_asset_type(&ristretto_keypair.0,
                                    &[AssetType::from_identical_byte(0u8),
                                      asset_type,
                                      AssetType::from_identical_byte(1u8)])
                .is_ok());
  }

  #[test]
  fn extract_identity_attributed_from_tracer_memo() {
    let mut prng = ChaChaRng::from_seed([0u8; 32]);
    let ristretto_keypair = elgamal_key_gen(&mut prng, &RistrettoPoint::get_base());
    let blsg1_keypair = ac_confidential_gen_encryption_keys(&mut prng);
    let asset_tracer_pub_key = AssetTracerEncKeys { record_data_enc_key: ristretto_keypair.1,
                                                    attrs_enc_key: blsg1_keypair.1 };

    let base = BLSG1::get_base();

    let attrs = [1u32, 2, 3];

    let ctexts = attrs.iter()
                      .map(|x| {
                        let scalar = BLSScalar::from_u32(*x);
                        elgamal_encrypt(&base,
                                        &scalar,
                                        &BLSScalar::from_u32(1000u32),
                                        &asset_tracer_pub_key.attrs_enc_key)
                      })
                      .collect_vec();

    let memo = AssetTracerMemo { enc_key: asset_tracer_pub_key.clone(),
                                 lock_amount: None,
                                 lock_asset_type: None,
                                 lock_attributes: Some(ctexts) };
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[1u32]),
               Err(ZeiError::ParameterError));
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[1u32, 2, 3, 4]),
               Err(ZeiError::ParameterError));
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[1u32, 2, 4]),
               Ok(vec![true, true, false]));
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[4u32, 2, 3]),
               Ok(vec![false, true, true]));
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[1u32, 2, 3]),
               Ok(vec![true, true, true]));
    assert_eq!(memo.verify_identity_attributes(&blsg1_keypair.0, &[3u32, 1, 2]),
               Ok(vec![false, false, false]));

    let attrs = memo.extract_identity_attributes_brute_force(&blsg1_keypair.0)
                    .unwrap();
    assert_eq!(attrs, vec![1u32, 2, 3]);
  }
}
