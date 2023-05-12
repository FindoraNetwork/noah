use crate::errors::Result;
use crate::hashing_to_the_curve::traits::SimplifiedSWUParameters;
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

impl SimplifiedSWUParameters<SECP256K1Fq> for Secp256k1SSWU {
    const C1: SECP256K1Fq = new_secp256k1_fq!(
        "5324262023205125242632636178842408935272934169651804884418803605709653231043"
    );
    const A: SECP256K1Fq = new_secp256k1_fq!(
        "28734576633528757162648956269730739219262246272443394170905244663053633733939"
    );
    const B: SECP256K1Fq = new_secp256k1_fq!("1771");
    const QNR: SECP256K1Fq = new_secp256k1_fq!("-1");

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
