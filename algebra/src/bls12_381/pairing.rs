use crate::bls12_381::g2::BLSG2;
use crate::bls12_381::gt::BLSGt;
use crate::bls12_381::{BLSScalar, BLSG1};
use crate::traits::Pairing;
use ark_bls12_381::Bls12_381 as Bls12381pairing;
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    pairing::Pairing as ArkPairing,
    CurveGroup,
};
use ark_std::vec::Vec;

/// The pairing engine for BLS12-381
pub struct BLSPairingEngine;

impl Pairing for BLSPairingEngine {
    type ScalarField = BLSScalar;
    type G1 = BLSG1;
    type G2 = BLSG2;
    type Gt = BLSGt;

    #[inline]
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        BLSGt(Bls12381pairing::pairing(a.0, b.0).0)
    }

    #[inline]
    fn product_of_pairings(a: &[Self::G1], b: &[Self::G2]) -> Self::Gt {
        let c1: Vec<G1Prepared<_>> = a.iter().map(|x| x.0.into_affine().into()).collect();
        let c2: Vec<G2Prepared<_>> = b.iter().map(|x| x.0.into_affine().into()).collect();
        BLSGt(Bls12381pairing::multi_pairing(c1, c2).0)
    }
}
