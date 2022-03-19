use crate::field_simulation::{
    ristretto_scalar_field_in_biguint, ristretto_scalar_field_sub_pad_in_biguint,
    ristretto_scalar_field_sub_pad_in_limbs, SimFrMul, BIT_PER_LIMB, NUM_OF_LIMBS,
};
use algebra::bls12_381::BLSScalar;
use algebra::{ops::*, One, Zero};
use num_bigint::BigUint;
use num_integer::Integer;

/// `SimFr` is the simulated Ristretto scalar field element
/// over BLS12-381 scalar field.
#[derive(Clone)]
pub struct SimFr {
    pub limbs: [BLSScalar; NUM_OF_LIMBS],
    pub val: BigUint,
    pub num_of_additions_over_normal_form: BigUint,
}

impl Default for SimFr {
    fn default() -> Self {
        Self {
            limbs: [BLSScalar::zero(); NUM_OF_LIMBS],
            val: BigUint::zero(),
            num_of_additions_over_normal_form: BigUint::zero(),
        }
    }
}

impl Sub<&SimFr> for &SimFr {
    type Output = SimFr;

    fn sub(self, rhs: &SimFr) -> SimFr {
        // For simplicity, given that our use case involves only one subtraction,
        // we require the value to be subtracted by a simulated field element
        // with at most one addition.
        //
        assert!(
            rhs.num_of_additions_over_normal_form.is_one()
                || rhs.num_of_additions_over_normal_form.is_zero()
        );

        let mut res = SimFr::default();
        let r_limbs = ristretto_scalar_field_sub_pad_in_limbs();
        let r_biguint = ristretto_scalar_field_sub_pad_in_biguint();
        for i in 0..NUM_OF_LIMBS {
            res.limbs[i] = self.limbs[i].add(&r_limbs[i]).sub(&rhs.limbs[i]);
        }
        res.val = (&self.val).add(&r_biguint).sub(&rhs.val);
        res.num_of_additions_over_normal_form =
            (&self.num_of_additions_over_normal_form).add(&BigUint::from(3u32));

        res
    }
}

impl Mul<&SimFr> for &SimFr {
    type Output = SimFrMul;

    fn mul(self, rhs: &SimFr) -> SimFrMul {
        let mut mul_res = SimFrMul::default();
        for i in 0..NUM_OF_LIMBS {
            for j in 0..NUM_OF_LIMBS {
                mul_res.limbs[i + j].add_assign(&self.limbs[i].mul(&rhs.limbs[j]));
            }
        }
        mul_res.val = (&self.val).mul(&rhs.val);
        mul_res.prod_of_num_of_additions = (&self.num_of_additions_over_normal_form)
            .add(&BigUint::one())
            .mul((&rhs.num_of_additions_over_normal_form).add(&BigUint::one()));

        mul_res
    }
}

impl From<&BigUint> for SimFr {
    fn from(src: &BigUint) -> Self {
        let step = BigUint::from(1u32).shl(BIT_PER_LIMB);
        let p_biguint = ristretto_scalar_field_in_biguint();
        let (_, mut rem) = src.div_rem(&p_biguint);

        let mut res = SimFr::default();
        res.val = rem.clone();
        for i in 0..NUM_OF_LIMBS {
            let (new_rem, limb) = rem.div_rem(&step);
            rem = new_rem;
            res.limbs[i] = BLSScalar::from(&limb);
        }
        res.num_of_additions_over_normal_form = BigUint::zero();

        res
    }
}

impl Into<BigUint> for &SimFr {
    fn into(self) -> BigUint {
        let step = BigUint::from(1u32).shl(43i32);
        let mut res = BigUint::zero();
        for limb in self.limbs.iter().rev() {
            res.mul_assign(&step);
            res.add_assign(&limb.into());
        }
        assert_eq!(res, self.val);
        res
    }
}

impl SimFr {
    pub fn is_zero(&self) -> bool {
        let self_biguint: BigUint = self.into();
        let r_biguint = ristretto_scalar_field_in_biguint();

        let (_, rem) = self_biguint.div_rem(&r_biguint);
        rem.is_zero()
    }
}

#[cfg(test)]
mod test {
    use crate::field_simulation::{ristretto_scalar_field_in_biguint, SimFr};
    use num_bigint::{BigUint, RandBigInt};
    use num_integer::Integer;
    use num_traits::Zero;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::ops::{Add, Mul, Sub};

    #[test]
    fn test_sim_fr_biguint_conversion() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        for _ in 0..100 {
            let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
            let a_sim_fr = SimFr::from(&a);
            let a_recovered: BigUint = (&a_sim_fr).into();

            assert_eq!(a, a_recovered);
        }
    }

    #[test]
    fn test_sub() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        for _ in 0..100 {
            let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
            let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

            let a_sim_fr = SimFr::from(&a);
            let b_sim_fr = SimFr::from(&b);
            let sum_sim_fr = &a_sim_fr - &b_sim_fr;

            let (_, sum) = a.add(&r_biguint).sub(&b).div_rem(&r_biguint);
            let (_, sum_recovered) =
                <&SimFr as Into<BigUint>>::into(&sum_sim_fr).div_rem(&r_biguint);

            assert_eq!(sum, sum_recovered);
        }
    }

    #[test]
    fn test_mul() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        for _ in 0..100 {
            let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
            let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

            let a_sim_fr = SimFr::from(&a);
            let b_sim_fr = SimFr::from(&b);

            let prod_sim_fr_mul = a_sim_fr.mul(&b_sim_fr);
            let prod_sim_fr_mul_recovered: BigUint = (&prod_sim_fr_mul).into();

            let prod = &a * &b;

            assert_eq!(prod, prod_sim_fr_mul_recovered);
        }
    }
}
