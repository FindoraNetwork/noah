use core::str::FromStr;
use num_bigint::BigUint;
use zei_algebra::bls12_381::BLSScalar;

pub const NUM_OF_LIMBS: usize = 6;
pub const BIT_PER_LIMB: usize = 43;
pub const NUM_OF_LIMBS_MUL: usize = NUM_OF_LIMBS * 2 - 1;

pub const NUM_OF_GROUPS: usize = 6;

pub mod fr;
pub use fr::SimFr;

pub mod fr_mul;
pub use fr_mul::SimFrMul;

/// This is the `BigUint` of the Ristretto scalar field modulus.
pub fn ristretto_scalar_field_in_biguint() -> BigUint {
    BigUint::from_str(
        "7237005577332262213973186563042994240857116359379907606001950938285454250989",
    )
    .unwrap()
}

/// This is the limbs of the Ristretto scalar field modulus.
pub fn ristretto_scalar_field_in_limbs() -> [BLSScalar; NUM_OF_LIMBS] {
    [
        BLSScalar::from_str("3411763647469").unwrap(),
        BLSScalar::from_str("7643343815244").unwrap(),
        BLSScalar::from_str("358561053323").unwrap(),
        BLSScalar::from_str("0").unwrap(),
        BLSScalar::from_str("0").unwrap(),
        BLSScalar::from_str("137438953472").unwrap(),
    ]
}

/// This is the limbs of the Ristretto scalar field modulus being adjusted
/// so that each limb is more than 2^43 (except the last one, 2^38).
///
/// We use it in subtraction, and we call it sub pad.
pub fn ristretto_scalar_field_sub_pad_in_limbs() -> [BLSScalar; NUM_OF_LIMBS] {
    [
        BLSScalar::from_str("10235290942407").unwrap(),
        BLSScalar::from_str("14133938423524").unwrap(),
        BLSScalar::from_str("9871776182178").unwrap(),
        BLSScalar::from_str("17592186044415").unwrap(),
        BLSScalar::from_str("17592186044414").unwrap(),
        BLSScalar::from_str("412316860414").unwrap(),
    ]
}

/// This is the `BigUint` representation of the sub pad.
pub fn ristretto_scalar_field_sub_pad_in_biguint() -> BigUint {
    BigUint::from_str(
        "21711016731996786641919559689128982722571349078139722818005852814856362752967",
    )
    .unwrap()
}
