use std::collections::HashMap;

pub static RISTRETTO_SRS: &'static [u8] =
    include_bytes!("../parameters/ristretto.bin");

#[cfg(not(feature = "no_srs"))]
pub static SRS: Option<&'static [u8]> = Some(include_bytes!("../parameters/srs.bin"));

#[cfg(feature = "no_srs")]
pub static SRS: Option<&'static [u8]> = None;

/*pub static VERIFIER_PARAMS_3_3: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_3_4: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_3_5: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_3_6: Option<&'static [u8]> = None;

pub static VERIFIER_PARAMS_4_3: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_4_4: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_4_5: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_4_6: Option<&'static [u8]> = None;

pub static VERIFIER_PARAMS_5_3: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_5_4: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_5_5: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_5_6: Option<&'static [u8]> = None;

pub static VERIFIER_PARAMS_6_3: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_6_4: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_6_5: Option<&'static [u8]> = None;
pub static VERIFIER_PARAMS_6_6: Option<&'static [u8]> = None;*/

lazy_static! {
    pub static ref VERIFIER_PARAMS: HashMap<(u64, u64), &'static [u8]> = {
        let m = HashMap::new();
        // m.insert((3, 3), VERIFIER_PARAMS_3_3);
        // m.insert(1, "bar");
        // m.insert(2, "baz");
        m
    };
}