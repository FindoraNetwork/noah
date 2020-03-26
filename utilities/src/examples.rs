use bulletproofs::PedersenGens;

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use zei::api::anon_creds::Attr;
use zei::xfr::asset_record::{build_blind_asset_record, AssetRecordType};
use zei::xfr::lib::RecordData;
use zei::xfr::sig::XfrPublicKey;
use zei::xfr::structs::{
  AssetRecordTemplate, AssetType, BlindAssetRecord, OwnerMemo, XfrAmount, XfrAssetType,
};

// Simulate getting a BlindAssetRecord from Ledger
#[allow(clippy::clone_on_copy)]
pub fn non_conf_blind_asset_record_from_ledger(key: &XfrPublicKey,
                                               amount: u64,
                                               asset_type: AssetType)
                                               -> BlindAssetRecord {
  BlindAssetRecord { amount: XfrAmount::NonConfidential(amount),
                     asset_type: XfrAssetType::NonConfidential(asset_type),
                     public_key: key.clone() }
}

// Simulate getting a BlindAssetRecord from Ledger
#[allow(clippy::clone_on_copy)]
#[allow(clippy::blacklisted_name)]
pub fn conf_blind_asset_record_from_ledger(key: &XfrPublicKey,
                                           amount: u64,
                                           asset_type: AssetType)
                                           -> (BlindAssetRecord, OwnerMemo) {
  let mut prng = ChaChaRng::from_seed([1u8; 32]);
  let template = AssetRecordTemplate { amount,
                                       asset_type,
                                       public_key: key.clone(),
                                       asset_record_type:
                                         AssetRecordType::ConfidentialAmount_ConfidentialAssetType,
                                       asset_tracing_policies: Default::default() };
  let (bar, _, owner) =
    build_blind_asset_record(&mut prng, &PedersenGens::default(), &template, vec![]);

  (bar, owner.unwrap())
}

pub fn check_record_data(record_data: &RecordData,
                         expected_amount: u64,
                         expected_asset_type: AssetType,
                         expected_ids: Vec<Attr>,
                         expected_pk: &XfrPublicKey) {
  assert_eq!(record_data.0, expected_amount);
  assert_eq!(record_data.1, expected_asset_type);
  assert_eq!(record_data.2, expected_ids);
  assert_eq!(record_data.3, *expected_pk);
}
