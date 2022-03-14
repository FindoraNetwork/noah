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
