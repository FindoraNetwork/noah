use crate::errors::Result;
use crate::hashing_to_the_curve::traits::SimplifiedSWU;
use ark_ff::LegendreSymbol;
use noah_algebra::{new_secp256k1_fq, prelude::*, secp256k1::SECP256K1Fq};

/// The simplified SWU map for secp256k1.
pub struct Secp256k1SSWU;

const K10: SECP256K1Fq = new_secp256k1_fq!(
    "64328938465175664124206102782604393251816658147578091133031991115504908150983"
);
const K11: SECP256K1Fq = new_secp256k1_fq!(
    "3540463234204664767867377763959255381561641196938647754971861192896365225345"
);
const K12: SECP256K1Fq = new_secp256k1_fq!(
    "37676595701789655284650173187508961899444205326770530105295841645151729341026"
);
const K13: SECP256K1Fq = new_secp256k1_fq!(
    "64328938465175664124206102782604393251816658147578091133031991115504908150924"
);
const K20: SECP256K1Fq = new_secp256k1_fq!(
    "95592507323525948732419199626899895302164312317343489384240252208201861084315"
);
const K21: SECP256K1Fq = new_secp256k1_fq!(
    "107505182841474506714709588670204841388457878609653642868747406790547894725908"
);
// const K22: SECP256K1Fq = new_secp256k1_fq!("1");

const A_PRIME: SECP256K1Fq = new_secp256k1_fq!(
    "28734576633528757162648956269730739219262246272443394170905244663053633733939"
);

impl SimplifiedSWU<SECP256K1Fq> for Secp256k1SSWU {
    fn isogeny_x1(&self, t: &SECP256K1Fq) -> Result<SECP256K1Fq> {
        let t2 = t.square();
        let t4 = t2.square();

        let temp = t4.sub(&t2).inv()?.add(SECP256K1Fq::one());
        let a_prime_inv = A_PRIME.inv().unwrap();
        Ok(a_prime_inv.mul(SECP256K1Fq::from(1771u32)).mul(temp).neg())
    }

    fn isogeny_x2(&self, t: &SECP256K1Fq, x1: &SECP256K1Fq) -> Result<SECP256K1Fq> {
        let t2 = t.square();

        Ok(x1.mul(t2).inv()?)
    }

    fn is_x_on_isogeny_curve(&self, x: &SECP256K1Fq) -> bool {
        let mut y_squared = x.pow(&[3u64]).add(SECP256K1Fq::from(1771u32));
        y_squared = y_squared.add(A_PRIME.mul(x));

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }

    fn isogeny_map_x(&self, x: &SECP256K1Fq) -> Result<SECP256K1Fq> {
        let x_squared = x.pow(&[2u64]);
        let x_cubed = x_squared.mul(x);

        let numerator = K10
            .add(K11.mul(x))
            .add(K12.mul(x_squared))
            .add(K13.mul(x_cubed));
        let denominator = K20.add(K21.mul(x)).add(x_squared);

        Ok(numerator.mul(denominator.inv()?))
    }
}
