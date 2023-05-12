use crate::errors::Result;
use crate::hashing_to_the_curve::traits::SimplifiedSWUParameters;
use noah_algebra::{ed25519::Ed25519Fq, new_ed25519_fq};

/// The simplified SWU map for ed25519.
pub struct Ed25519SSWU;

impl SimplifiedSWUParameters<Ed25519Fq> for Ed25519SSWU {
    const C1: Ed25519Fq = new_ed25519_fq!(
        "23090418627330554870558147835411017348134811420561311724956192453459391843510"
    );
    const A: Ed25519Fq = new_ed25519_fq!("6");
    const B: Ed25519Fq = new_ed25519_fq!(
        "35145622091990963912007590500565757691096108475092975709449221291113343398787"
    );
    const QNR: Ed25519Fq = new_ed25519_fq!("2");

    fn isogeny_map_x(&self, x: &Ed25519Fq) -> Result<Ed25519Fq> {
        Ok(*x)
    }
}
