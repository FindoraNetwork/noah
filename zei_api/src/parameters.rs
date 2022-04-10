use std::collections::HashMap;

pub static RISTRETTO_SRS: &'static [u8] = include_bytes!("../parameters/ristretto.bin");

#[cfg(not(feature = "no_srs"))]
pub static SRS: Option<&'static [u8]> = Some(include_bytes!("../parameters/srs.bin"));

#[cfg(feature = "no_srs")]
pub static SRS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/vk-common.bin"));

#[cfg(feature = "no_vk")]
pub static VERIFIER_COMMON_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static VERIFIER_SPECIALS_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/vk-specials.bin"));

#[cfg(feature = "no_vk")]
pub static VERIFIER_SPECIALS_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static ABAR_TO_BAR_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/abar-to-bar-vk.bin"));

#[cfg(feature = "no_vk")]
pub static ABAR_TO_BAR_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static BAR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/bar-to-abar-vk.bin"));

#[cfg(feature = "no_vk")]
pub static BAR_TO_ABAR_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(not(feature = "no_vk"))]
pub static ANON_FEE_VERIFIER_PARAMS: Option<&'static [u8]> =
    Some(include_bytes!("../parameters/anon-fee-vk.bin"));

#[cfg(feature = "no_vk")]
pub static ANON_FEE_VERIFIER_PARAMS: Option<&'static [u8]> = None;

#[cfg(feature = "no_vk")]
pub static LAGRANGE_BASES: HashMap<usize, &'static [u8]> = HashMap::default();

#[cfg(not(feature = "no_vk"))]
static LAGRANGE_BASE_8192: &'static [u8] = include_bytes!("../parameters/lagrange-srs-8192.bin");
#[cfg(not(feature = "no_vk"))]
static LAGRANGE_BASE_16384: &'static [u8] = include_bytes!("../parameters/lagrange-srs-16384.bin");
#[cfg(not(feature = "no_vk"))]
static LAGRANGE_BASE_32768: &'static [u8] = include_bytes!("../parameters/lagrange-srs-32768.bin");
#[cfg(not(feature = "no_vk"))]
static LAGRANGE_BASE_65536: &'static [u8] = include_bytes!("../parameters/lagrange-srs-65536.bin");

#[cfg(not(feature = "no_vk"))]
lazy_static! {
    pub static ref LAGRANGE_BASES: HashMap<usize, &'static [u8]> = {
        let mut m = HashMap::new();
        m.insert(8192,  LAGRANGE_BASE_8192);
        m.insert(16384, LAGRANGE_BASE_16384);
        m.insert(32768, LAGRANGE_BASE_32768);
        m.insert(65536, LAGRANGE_BASE_65536);
        m
    };
}
