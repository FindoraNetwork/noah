use crate::bulletproofs::plume::Plume;
use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
use noah_algebra::new_ed25519_fq;
use noah_algebra::prelude::*;

/// The PLUME implementation for secp256k1.
pub struct PlumeEd25519;

impl Plume<Ed25519Point> for PlumeEd25519 {
    fn get_generator_g() -> Ed25519Point {
        Ed25519Point::get_base()
    }

    fn get_generator_h() -> Ed25519Point {
        Ed25519Point::new(
            &new_ed25519_fq!(
                "1758682557278622166727084222880667175348907971062636411700231506689670444406"
            ),
            &new_ed25519_fq!(
                "18728682362703376192931234188131080883036471711603517790343415579409605924262"
            ),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::bulletproofs::plume::ed25519::PlumeEd25519;
    use crate::bulletproofs::plume::Plume;
    use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
    use crate::hashing_to_the_curve::models::elligator::Elligator;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use digest::Digest;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::prelude::*;
    use rand_chacha::ChaChaRng;
    use sha3::Sha3_512;

    #[test]
    fn generator_h_correctness() {
        let mut hash = Sha3_512::new();
        Digest::update(&mut hash, b"Ed25519 PLUME Implementation");
        let h = hash.finalize();

        let mut res = [0u8; 32];
        res.copy_from_slice(&h[..32]);

        let mut prng = ChaChaRng::from_seed(res);
        let hash_for_map = Ed25519Fq::random(&mut prng);

        let p =
            Elligator::<Ed25519Point, Ed25519ElligatorParameters>::get_cofactor_uncleared_point(
                &hash_for_map,
            )
            .unwrap();

        let point =
            Elligator::<Ed25519Point, Ed25519ElligatorParameters>::convert_to_group(&p.0, &p.1)
                .unwrap();
        let point = point.double().double().double(); // clear the cofactor
        assert_eq!(PlumeEd25519::get_generator_h(), point);
        assert!(point.get_raw().is_in_correct_subgroup_assuming_on_curve());
    }
}
