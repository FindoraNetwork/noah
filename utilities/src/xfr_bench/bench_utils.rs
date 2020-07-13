use zei::setup::PublicParams;
use zei::xfr::lib::{verify_xfr_body, verify_xfr_note, XfrNotePoliciesRef};
use zei::xfr::structs::{AssetType, XfrBody, XfrNote, ASSET_TYPE_LENGTH};

use criterion::measurement::Measurement;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub const ASSET_TYPE_1: AssetType = AssetType([0u8; ASSET_TYPE_LENGTH]);
pub const ASSET_TYPE_2: AssetType = AssetType([1u8; ASSET_TYPE_LENGTH]);

pub const XFR_NOTE_SIZES: [usize; 3] = [1, 4, 16];

pub(crate) fn run_verify_xfr_note(xfr_note: &XfrNote, policies: &XfrNotePoliciesRef) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let mut params = PublicParams::new();
  assert!(verify_xfr_note(&mut prng, &mut params, xfr_note, policies).is_ok());
}

pub(crate) fn run_verify_xfr_body(xfr_body: &XfrBody, policies: &XfrNotePoliciesRef) {
  let mut prng = ChaChaRng::from_seed([0u8; 32]);
  let mut params = PublicParams::new();
  assert!(verify_xfr_body(&mut prng, &mut params, xfr_body, policies).is_ok());
}

pub(crate) fn get_string_measurement_type<B: Measurement>() -> String {
  if std::any::type_name::<B>() == "criterion::measurement::WallTime" {
    String::from("time")
  } else {
    String::from("cycles")
  }
}

pub(crate) fn make_title<B: Measurement>(desc: &str, n: usize) -> String {
  let title = format!("{desc} n={n} ({b_type})",
                      desc = desc,
                      n = n,
                      b_type = get_string_measurement_type::<B>());
  title
}
