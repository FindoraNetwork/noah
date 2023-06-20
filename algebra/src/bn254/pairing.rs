use crate::bn254::{BN254Gt, BN254Scalar, BN254G1, BN254G2};
use crate::traits::Pairing;
use ark_bn254::Bn254 as BN254Pairing;
use ark_ec::{
    bn::{G1Prepared, G2Prepared},
    pairing::Pairing as ArkPairing,
    CurveGroup,
};
use ark_std::vec::Vec;

/// The pairing engine for BN254
pub struct BN254PairingEngine;

impl Pairing for BN254PairingEngine {
    type ScalarField = BN254Scalar;
    type G1 = BN254G1;
    type G2 = BN254G2;
    type Gt = BN254Gt;

    #[inline]
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        BN254Gt(BN254Pairing::pairing(a.0, b.0).0)
    }

    #[inline]
    fn product_of_pairings(a: &[Self::G1], b: &[Self::G2]) -> Self::Gt {
        let c1: Vec<G1Prepared<_>> = a.iter().map(|x| x.0.into_affine().into()).collect();
        let c2: Vec<G2Prepared<_>> = b.iter().map(|x| x.0.into_affine().into()).collect();
        BN254Gt(BN254Pairing::multi_pairing(c1, c2).0)
    }
}
