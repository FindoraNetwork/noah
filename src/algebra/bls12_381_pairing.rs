
use pairing::bls12_381::{Fr, G1, G2, Fq12};
use pairing::{CurveAffine, CurveProjective, PrimeField};
use rand_04::Rand;
use std::ops::{Add, Sub, Neg, Mul};
use pairing::Field;

#[derive(Clone, PartialEq, Eq)]
pub struct BLSScalar(Fr);
pub struct BLSG1Elem(G1);
pub struct BLSG2Elem(G2);
#[derive(Clone, PartialEq, Eq)]
pub struct BLSGtElem(Fq12);


impl BLSScalar {
    pub(crate) fn random<R:rand_04::Rng>(prng: &mut R) -> Self{
        BLSScalar(Fr::rand(prng))
    }
    /*
    pub(crate) fn zero() -> Self{
        BLSScalar(Fr::zero())
    }

    pub(crate) fn one() -> Self{
        BLSScalar(Fr::one())
    }
    */
}


impl Add<&BLSScalar> for &BLSScalar {
    type Output = BLSScalar;
    fn add(self, other: &BLSScalar) -> BLSScalar {
        let mut new_elem = self.0.clone();
        new_elem.add_assign(&other.0);
        BLSScalar(new_elem)
    }
}

impl Sub<&BLSScalar> for &BLSScalar {
    type Output = BLSScalar;
    fn sub(self, other: &BLSScalar) -> BLSScalar {
        let mut new_elem = self.0.clone();
        new_elem.sub_assign(&other.0);
        BLSScalar(new_elem)
    }
}

impl Neg for &BLSScalar {
    type Output = BLSScalar;

    fn neg(self) -> BLSScalar {
        let mut n = self.0.clone();
        n.negate();
        BLSScalar(n)
    }
}

impl Mul<&BLSScalar> for &BLSScalar {
    type Output = BLSScalar;
    fn mul(self, other: &BLSScalar) -> BLSScalar {
        let mut new_elem = self.0.clone();
        new_elem.mul_assign(&other.0);
        BLSScalar(new_elem)
    }
}


impl BLSG1Elem{
    pub(crate) fn random<R:rand_04::Rng>(prng: &mut R) -> Self{
        BLSG1Elem(G1::rand(prng))
    }
    /*
    pub(crate) fn zero() -> Self{
        BLSG1Elem(G1::zero())
    }
    */
    pub(crate) fn one() -> Self{
        BLSG1Elem(G1::one())
    }

    /*
    pub(crate) fn to_str(&self) -> String{
        rustc_serialize::json::encode(&self.0).unwrap()
    }
    */
}


impl Add<&BLSG1Elem> for &BLSG1Elem {
    type Output = BLSG1Elem;
    fn add(self, other: &BLSG1Elem) -> BLSG1Elem {
        let mut r = self.0.clone();
        r.add_assign(&other.0);
        BLSG1Elem(r)
    }
}


impl Sub<&BLSG1Elem> for &BLSG1Elem {
    type Output = BLSG1Elem;

    fn sub(self, other: &BLSG1Elem) -> BLSG1Elem {

        let mut r = self.0.clone();
        r.sub_assign(&other.0);
        BLSG1Elem(r)
    }
}

impl Neg for BLSG1Elem {
    type Output = BLSG1Elem;
    fn neg(self) -> BLSG1Elem {
        let mut r = self.0.clone();
        r.negate();
        BLSG1Elem(r)
    }
}

impl Mul<&BLSScalar> for &BLSG1Elem {
    type Output = BLSG1Elem;
    fn mul(self, other: &BLSScalar) -> BLSG1Elem {
        let mut r = self.0.clone();
        r.mul_assign(other.0);
        BLSG1Elem(r)
    }
}

impl BLSG2Elem{
    pub(crate) fn random<R:rand_04::Rng>(prng: &mut R) -> Self{
        BLSG2Elem(G2::rand(prng))
    }
    pub(crate) fn zero() -> Self{
        BLSG2Elem(G2::zero())
    }

    pub(crate) fn one() -> Self{
        BLSG2Elem(G2::one())
    }

    pub(crate) fn to_bytes(&self) -> [u8;96] {
        let a = (self.0).into_affine();
        let c: pairing::bls12_381::G2Compressed = a.into_compressed();
        let mut r = [0u8;96];
        r.copy_from_slice(c.as_ref());
        r
    }
}


impl Add<&BLSG2Elem> for &BLSG2Elem {
    type Output = BLSG2Elem;
    fn add(self, other: &BLSG2Elem) -> BLSG2Elem {
        let mut r = self.0.clone();
        r.add_assign(&other.0);
        BLSG2Elem(r)
    }
}


impl Sub<&BLSG2Elem> for &BLSG2Elem {
    type Output = BLSG2Elem;

    fn sub(self, other: &BLSG2Elem) -> BLSG2Elem {
        let mut r = self.0.clone();
        r.sub_assign(&other.0);
        BLSG2Elem(r)
    }
}

impl Neg for BLSG2Elem {
    type Output = BLSG2Elem;
    fn neg(self) -> BLSG2Elem {
        let mut r = self.0.clone();
        r.negate();
        BLSG2Elem(r)
    }
}

impl Mul<&BLSScalar> for &BLSG2Elem {
    type Output = BLSG2Elem;
    fn mul(self, other: &BLSScalar) -> BLSG2Elem {
        let mut r = self.0.clone();
        r.mul_assign(other.0);
        BLSG2Elem(r)
    }
}

/// Multiplicative pairing target group
impl BLSGtElem {
    /*
    pub fn one() -> Self {
        BLSGtElem(Fq12::one())
    }
    */
    pub(crate) fn pow(&self, exp: BLSScalar) -> Self {
        let r = self.0.pow(exp.0.into_repr().as_ref());
        BLSGtElem(r)
    }
    /*
    pub fn inverse(&self) -> Option<BLSGtElem> {
        let r = self.0.inverse();
        if r.is_some() {
            Some(BLSGtElem(r.unwrap()))
        }
        else {
            None
        }
    }*/
}

impl Mul<&BLSGtElem> for BLSGtElem {
    type Output = BLSGtElem;

    fn mul(self, other: &BLSGtElem) -> BLSGtElem {
        let mut r = self.0.clone();
        r.mul_assign(&other.0);
        BLSGtElem(r)
    }
}

pub(crate) fn pairing(e1: &BLSG1Elem, e2: &BLSG2Elem) -> BLSGtElem{
    let g1_affine = (e1.0).into_affine();
    let g2_affine = (e2.0).into_affine();
    BLSGtElem(g1_affine.pairing_with(&g2_affine))
}


#[cfg(test)]
mod test {
    use super::*;
    use rand_04::ChaChaRng;
    use rand_04::SeedableRng;


    #[test]
    fn test_pairing(){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed(&[0u32; 8]);

        let s1 = BLSScalar::random(&mut prng);
        let s2 = BLSScalar::random(&mut prng);

        let element_1 = &BLSG1Elem::one() * &s1;
        let element_2 = &BLSG2Elem::one() * &s2;

        let gt_element = pairing(&element_1, &element_2);

        let gt_element_2 = pairing(&BLSG1Elem::one(), &BLSG2Elem::one()).pow(&s1 * &s2);

        assert_eq!(true, gt_element.eq(&gt_element_2));

        let gt_element_3 = pairing(&BLSG1Elem::one(), &(&BLSG2Elem::one() * &( &s1 * &s2)));

        assert_eq!(true, gt_element.eq(&gt_element_3));

        let gt_element_4 = pairing(&(& BLSG1Elem::one() * &(&s1 * &s2)), &BLSG2Elem::one());

        assert_eq!(true, gt_element.eq(&gt_element_4));
    }
}

