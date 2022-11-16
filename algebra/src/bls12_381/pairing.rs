use crate::bls12_381::g2::BLSG2;
use crate::bls12_381::gt::BLSGt;
use crate::bls12_381::{BLSScalar, BLSG1};
use crate::traits::Pairing;
use ark_bls12_381::Bls12_381 as Bls12381pairing;
use ark_ec::bls12::{G1Prepared, G2Prepared};
use ark_ec::{PairingEngine, ProjectiveCurve};

/// The pairing engine for BLS12-381
pub struct BLSPairingEngine;

impl Pairing for BLSPairingEngine {
    type ScalarField = BLSScalar;
    type G1 = BLSG1;
    type G2 = BLSG2;
    type Gt = BLSGt;

    #[inline]
    fn pairing(a: &Self::G1, b: &Self::G2) -> Self::Gt {
        BLSGt(Bls12381pairing::pairing(a.0, b.0))
    }

    #[inline]
    fn product_of_pairings(a: &[Self::G1], b: &[Self::G2]) -> Self::Gt {
        let c = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x.0.into_affine().into(), y.0.into_affine().into()))
            .collect::<Vec<(G1Prepared<_>, G2Prepared<_>)>>();
        BLSGt(Bls12381pairing::product_of_pairings(&c))
    }
}
