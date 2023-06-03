use crate::bulletproofs::plume::Plume;
use noah_algebra::new_secp256k1_fq;
use noah_algebra::prelude::*;
use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};

/// The PLUME implementation for secp256k1.
pub struct PlumeSecp256k1;

impl Plume<SECP256K1G1> for PlumeSecp256k1 {
    fn get_generator_g() -> SECP256K1G1 {
        SECP256K1G1::get_base()
    }

    fn get_generator_h() -> SECP256K1G1 {
        SECP256K1G1::new(
            &new_secp256k1_fq!(
                "46190662746725679415425739992994142449475516927403715234504411186769117430887"
            ),
            &new_secp256k1_fq!(
                "69436746129075925653002611114933784451034614444154979397886909819606273822058"
            ),
        )
    }
}

#[cfg(test)]
mod test {
    use crate::bulletproofs::plume::secp256k1::PlumeSecp256k1;
    use crate::bulletproofs::plume::Plume;
    use crate::hashing_to_the_curve::models::sswu::SSWUMap;
    use crate::hashing_to_the_curve::secp256k1::sswu::Secp256k1SSWUParameters;
    use crate::hashing_to_the_curve::traits::HashingToCurve;
    use digest::Digest;
    use noah_algebra::prelude::*;
    use noah_algebra::secp256k1::{SECP256K1Fq, SECP256K1G1};
    use rand_chacha::ChaChaRng;
    use sha3::Sha3_512;

    #[test]
    fn generator_h_correctness() {
        let mut hash = Sha3_512::new();
        Digest::update(&mut hash, b"Secp256k1 PLUME Implementation");
        let h = hash.finalize();

        let mut res = [0u8; 32];
        res.copy_from_slice(&h[..32]);

        let mut prng = ChaChaRng::from_seed(res);
        let hash_for_map = SECP256K1Fq::random(&mut prng);

        let p = SSWUMap::<SECP256K1G1, Secp256k1SSWUParameters>::get_cofactor_uncleared_point(
            &hash_for_map,
        )
        .unwrap();

        let point =
            SSWUMap::<SECP256K1G1, Secp256k1SSWUParameters>::convert_to_group(&p.0, &p.1).unwrap();
        assert_eq!(PlumeSecp256k1::get_generator_h(), point);
        assert!(point.get_raw().is_in_correct_subgroup_assuming_on_curve());
    }
}
