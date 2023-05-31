use crate::bulletproofs::plume::Plume;
use crate::errors::Result;
use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
use crate::hashing_to_the_curve::models::elligator::{Elligator, ElligatorParameters};
use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point, Ed25519Scalar};
use noah_algebra::new_ed25519_fq;
use noah_algebra::prelude::*;
use noah_algebra::zorro::ZorroScalar;

pub struct PlumeEd25519;

impl Plume<Ed25519Point> for PlumeEd25519 {
    const GENERATOR_G: (Ed25519Fq, Ed25519Fq) = (
        new_ed25519_fq!("9"),
        new_ed25519_fq!(
            "14781619447589544791020593568409986887264606134616475288964881837755586237401"
        ),
    );
    const GENERATOR_H: (Ed25519Fq, Ed25519Fq) = (new_ed25519_fq!("1"), new_ed25519_fq!("1"));

    fn convert_to_the_curve(p: &Ed25519Point) -> Result<(Ed25519Fq, Ed25519Fq)> {
        let edwards_x = p.get_x();
        let edwards_y = p.get_y();

        let edwards_y_plus_1 = edwards_y + ZorroScalar::one();
        let edwards_y_sub_1 = ZorroScalar::one() - &edwards_y;
        let edwards_y_sub_1_inv = edwards_y_sub_1.inv()?;
        let edwards_x_inv = edwards_x.inv()?;

        let montgomery_x = edwards_y_plus_1 * edwards_y_sub_1_inv;
        let montgomery_y = SQRT_MINUS_486664 * montgomery_x * edwards_x_inv;

        #[cfg(debug_assertions)]
        {
            type M = Elligator<Ed25519Point, Ed25519ElligatorParameters>;
            assert!(M::is_x_on_curve(&montgomery_x));
        }

        Ok((montgomery_x, montgomery_y))
    }
}

#[cfg(test)]
mod test {
    use crate::anemoi_jive::{AnemoiJive, AnemoiJive381};
    use crate::bulletproofs::plume::ed25519::PlumeEd25519;
    use crate::bulletproofs::plume::Plume;
    use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
    use crate::hashing_to_the_curve::models::elligator::Elligator;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use digest::Digest;
    use noah_algebra::ed25519::{Ed25519Fq, Ed25519Point};
    use noah_algebra::prelude::*;
    use num_bigint::BigUint;
    use rand_chacha::ChaChaRng;
    use sha3::Sha3_512;

    #[test]
    fn generator_g_correctness() {
        let p = Ed25519Point::get_base();
        let (x, y) = PlumeEd25519::convert_to_the_curve(&p).unwrap();
        assert_eq!(PlumeEd25519::GENERATOR_G, (x, y));
    }

    #[test]
    fn generator_h_correctness() {
        let mut hash = Sha3_512::new();
        Digest::update(&mut hash, b"Ed25519 PLUME Implementation");
        let h = hash.finalize();

        let mut res = [0u8; 32];
        res.copy_from_slice(&h[..32]);

        let mut prng = ChaChaRng::from_seed(res);
        let hash_for_map = Ed25519Fq::rand(&mut prng);

        let p =
            Elligator::<Ed25519Point, Ed25519ElligatorParameters>::get_cofactor_uncleared_point(
                &hash_for_map,
            )
            .unwrap();
    }
}
