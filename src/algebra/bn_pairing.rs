use std::ops::{Add, Sub, Neg, Mul};
use bn::Group;
use rand_04::Rng as Rng;


#[derive(Clone, PartialEq, Eq)]
pub struct PairingScalar(bn::Fr);

impl PairingScalar {
    pub(crate) fn random<R: Rng>(prng: &mut R) -> Self{
        PairingScalar(bn::Fr::random(prng))
    }
    /*
    pub(crate) fn zero() -> Self{
        PairingScalar(bn::Fr::zero())
    }
    pub(crate) fn one() -> Self{
        PairingScalar(bn::Fr::one())
    }
    */
}

impl Add<PairingScalar> for PairingScalar {
    type Output = PairingScalar;
    fn add(self, other: PairingScalar) -> PairingScalar {
        PairingScalar(self.0 + other.0)
    }
}

impl Add<&PairingScalar> for &PairingScalar {
    type Output = PairingScalar;
    fn add(self, other: &PairingScalar) -> PairingScalar {
        PairingScalar(self.0 + other.0)
    }
}

impl Sub<PairingScalar> for PairingScalar {
    type Output = PairingScalar;
    fn sub(self, other: PairingScalar) -> PairingScalar { PairingScalar(self.0 - other.0) }
}

impl Neg for PairingScalar {
    type Output = PairingScalar;

    fn neg(self) -> PairingScalar { PairingScalar(-self.0) }
}

impl Mul<&PairingScalar> for &PairingScalar {
    type Output = PairingScalar;

    fn mul(self, other: &PairingScalar) -> PairingScalar { PairingScalar(self.0 * other.0) }
}

impl Mul<PairingScalar> for PairingScalar {
    type Output = PairingScalar;

    fn mul(self, other: PairingScalar) -> PairingScalar { PairingScalar(self.0 * other.0) }
}

pub(crate) struct G1Elem(bn::G1);

impl G1Elem{
    pub(crate) fn random<R: Rng>(prng: &mut R) -> Self{
        G1Elem(bn::G1::random(prng))
    }
    /*
    pub(crate) fn zero() -> Self{
        G1Elem(bn::G1::zero())
    }
    */
    pub(crate) fn one() -> Self{
        G1Elem(bn::G1::one())
    }

    //pub(crate) fn to_str(&self) -> String{ rustc_serialize::json::encode(&self.0).unwrap()}
}

impl Add<&G1Elem> for G1Elem {
    type Output = G1Elem;
    fn add(self, other: &G1Elem) -> G1Elem { G1Elem(self.0 + other.0) }
}

impl Add<&G1Elem> for &G1Elem {
    type Output = G1Elem;
    fn add(self, other: &G1Elem) -> G1Elem { G1Elem(self.0 + other.0) }
}

impl Sub<&G1Elem> for G1Elem {
    type Output = G1Elem;

    fn sub(self, other: &G1Elem) -> G1Elem { G1Elem(self.0 - other.0) }
}

impl Neg for G1Elem {
    type Output = G1Elem;
    fn neg(self) -> G1Elem { G1Elem(-self.0) }
}

/*
impl Mul<&PairingScalar> for G1Elem {
    type Output = G1Elem;
    fn mul(self, other: &PairingScalar) -> G1Elem { G1Elem(self.0 * other.0) }
}
*/

impl Mul<&PairingScalar> for &G1Elem {
    type Output = G1Elem;
    fn mul(self, other: &PairingScalar) -> G1Elem { G1Elem(self.0 * other.0) }
}


pub(crate) struct G2Elem(bn::G2);

impl G2Elem{
    pub(crate) fn random<R: Rng>(prng: &mut R) -> Self{
        G2Elem(bn::G2::random(prng))
    }
    pub(crate) fn zero() -> Self{
        G2Elem(bn::G2::zero())
    }

    pub(crate) fn one() -> Self{
        G2Elem(bn::G2::one())
    }

    pub(crate) fn to_str(&self) -> String{
        rustc_serialize::json::encode(&self.0).unwrap()
    }
}

impl Add<&G2Elem> for G2Elem {
    type Output = G2Elem;
    fn add(self, other: &G2Elem) -> G2Elem { G2Elem(self.0 + other.0) }
}

impl Add<G2Elem> for G2Elem {
    type Output = G2Elem;
    fn add(self, other: G2Elem) -> G2Elem { G2Elem(self.0 + other.0) }
}

impl Sub<&G2Elem> for G2Elem {
    type Output = G2Elem;

    fn sub(self, other: &G2Elem) -> G2Elem { G2Elem(self.0 - other.0) }
}

impl Neg for G2Elem {
    type Output = G2Elem;
    fn neg(self) -> G2Elem { G2Elem(-self.0) }
}

impl Mul<&PairingScalar> for &G2Elem {
    type Output = G2Elem;
    fn mul(self, other: &PairingScalar) -> G2Elem { G2Elem(self.0 * other.0) }
}

/// Multiplicative pairing target group
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct GtElem(bn::Gt);
impl GtElem {
    //pub fn one() -> Self { GtElem(bn::Gt::one()) }
    pub fn pow(&self, exp: PairingScalar) -> Self { GtElem(self.0.pow(exp.0)) }
    //pub fn inverse(&self) -> Self { GtElem(self.0.inverse()) }
}

impl Mul<GtElem> for GtElem {
    type Output = GtElem;

    fn mul(self, other: GtElem) -> GtElem { GtElem(self.0 * other.0) }
}

pub(crate) fn pairing(e1: &G1Elem, e2: &G2Elem) -> GtElem{
    GtElem(bn::pairing(e1.0, e2.0))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_04::{SeedableRng, ChaChaRng};

    #[test]
    fn test_pairing(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed(&[0u32; 8]);

        let s1 = PairingScalar::random(&mut prng);
        let s2 = PairingScalar::random(&mut prng);

        let element_1 = &G1Elem::one() * &s1;
        let element_2 = &G2Elem::one() * &s2;

        let gt_element = pairing(&element_1, &element_2);

        let gt_element_2 = pairing(&G1Elem::one(), &G2Elem::one()).pow(&s1 * &s2);

        assert_eq!(true, gt_element.eq(&gt_element_2));

        let gt_element_3 = pairing(&G1Elem::one(), &(&G2Elem::one() * &( &s1 * &s2)));

        assert_eq!(true, gt_element.eq(&gt_element_3));

        let gt_element_4 = pairing(&(& G1Elem::one() * &(&s1 * &s2)), &G2Elem::one());

        assert_eq!(true, gt_element.eq(&gt_element_4));
    }
}