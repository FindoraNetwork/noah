use crate::field_simulation::{
    ristretto_scalar_field_in_biguint, ristretto_scalar_field_in_limbs,
    ristretto_scalar_field_sub_pad_in_biguint, ristretto_scalar_field_sub_pad_in_limbs,
    SimFr, BIT_PER_LIMB, NUM_OF_GROUPS, NUM_OF_LIMBS, NUM_OF_LIMBS_MUL,
};
use algebra::bls12_381::BLSScalar;
use algebra::groups::{Scalar, ScalarArithmetic, Zero as ArkZero};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use std::ops::{AddAssign, MulAssign, Shl, Shr, Sub};

/// `SimFrMul` is the intermediate representation for
/// the product of two simulated Ristretto scalar field elements
/// over BLS12-381 scalar field.
#[derive(Clone)]
pub struct SimFrMul {
    pub limbs: [BLSScalar; NUM_OF_LIMBS_MUL],
    pub val: BigUint,
    pub prod_of_num_of_additions: BigUint,
}

impl Default for SimFrMul {
    fn default() -> Self {
        Self {
            limbs: [BLSScalar::zero(); NUM_OF_LIMBS_MUL],
            val: BigUint::zero(),
            prod_of_num_of_additions: BigUint::zero(),
        }
    }
}

impl Into<BigUint> for &SimFrMul {
    fn into(self) -> BigUint {
        let step = BigUint::from(1u32).shl(43i32);
        let mut res = BigUint::zero();
        for limb in self.limbs.iter().rev() {
            res.mul_assign(&step);
            res.add_assign(&limb.into());
        }
        assert_eq!(self.val, res);
        res
    }
}

impl Sub<&SimFr> for &SimFrMul {
    type Output = SimFrMul;

    fn sub(self, rhs: &SimFr) -> SimFrMul {
        // For simplicity, we require the value to be subtracted
        // by a simulated field element with at most four additions.
        //
        assert!(rhs.num_of_additions_over_normal_form <= BigUint::from(4u32));

        let mut res = self.clone();
        let r_limbs = ristretto_scalar_field_sub_pad_in_limbs();
        let r_biguint = ristretto_scalar_field_sub_pad_in_biguint();

        for i in 0..NUM_OF_LIMBS {
            res.limbs[i] = res.limbs[i]
                .add(&r_limbs[i])
                .add(&r_limbs[i])
                .add(&r_limbs[i])
                .add(&r_limbs[i])
                .sub(&rhs.limbs[i]);
        }
        res.val =
            &res.val + &r_biguint + &r_biguint + &r_biguint + &r_biguint - &rhs.val;
        res.prod_of_num_of_additions =
            &res.prod_of_num_of_additions + &BigUint::from(12u32);

        res
    }
}

impl SimFrMul {
    /// The `enforce_zero` function uses the techniques from two works:
    /// [KPS18]: A. E. Kosba, C. Papamanthou, and E. Shi.
    /// "xJsnark: a framework for efficient verifiable computation,"
    /// in S&P 2018
    ///
    /// [OWWB20]: A. Ozdemir, R. S. Wahby, B. Whitehat, and D. Boneh.
    /// "Scaling verifiable computation using efficient set accumulators,"
    /// in USENIX Security 2020
    ///
    /// And the code is from xJsnark, bellman-bignat, and arkworks-rs.
    ///
    pub fn enforce_zero(&self) {
        // For safety, since in our use case we are only doing very few algebraic operations,
        // we limit the `prod_of_num_of_additions` to be smaller than 32.
        let surfeit = self.prod_of_num_of_additions.bits() as usize;
        assert!(surfeit <= 5);

        let cur_val: BigUint = self.into();
        let r_biguint = ristretto_scalar_field_in_biguint();

        // The idea is to show that there exists `k * r` that is exactly the current number
        // in `SimFrMul`, by a few shifts.

        // compute `k`
        let (k, rem) = cur_val.div_rem(&r_biguint);
        assert!(rem.is_zero());
        assert!(k <= r_biguint.shl(5));

        // compute the limbs for `k * r`
        let r_limbs = ristretto_scalar_field_in_limbs().to_vec();
        let k_limbs = SimFr::from(&k).limbs.to_vec();

        let mut rk_limbs = vec![BLSScalar::zero(); NUM_OF_LIMBS_MUL];
        for i in 0..NUM_OF_LIMBS {
            for j in 0..NUM_OF_LIMBS {
                rk_limbs[i + j] = rk_limbs[i + j].add(&r_limbs[i].mul(&k_limbs[j]));
            }
        }

        // group the limbs of `self` and the limbs of `k * r` together
        // this step is for efficiency, so that carry adders have fewer steps
        let mut left_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut right_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut num_limbs_in_group = Vec::with_capacity(NUM_OF_GROUPS);

        let step = BLSScalar::from(&BigUint::from(1u32).shl(BIT_PER_LIMB));
        for chunk in self.limbs.chunks(2) {
            if chunk.len() == 2 {
                left_group.push(chunk[0].add(&chunk[1].mul(&step)));
            } else {
                left_group.push(chunk[0]);
            }
            num_limbs_in_group.push(chunk.len());
        }
        for chunk in rk_limbs.chunks(2) {
            if chunk.len() == 2 {
                right_group.push(chunk[0].add(&chunk[1].mul(&step)));
            } else {
                right_group.push(chunk[0]);
            }
        }

        // Perform the following checking
        //      left_group_limb + pad_limb + carry_in - right_group_limb
        //   =  carry shift by (BIT_PER_LIMB * num_limb_in_group) + remainder

        let mut carry_in = BLSScalar::zero();
        let mut accumulated_extra = BigUint::zero();
        for (group_id, ((left_group_limb, right_group_limb), num_limbs_in_this_group)) in
            left_group
                .iter()
                .zip(right_group.iter())
                .zip(num_limbs_in_group.iter())
                .enumerate()
        {
            let pad = BigUint::from(1u32).shl(
                (num_limbs_in_this_group + 1) * BIT_PER_LIMB
                    + num_limbs_in_this_group
                    + surfeit,
            );
            let pad_limb = BLSScalar::from(&pad);
            assert!(pad > <&BLSScalar as Into<BigUint>>::into(right_group_limb));

            // Compute the carry number for the next cycle
            let mut carry = left_group_limb
                .add(&carry_in)
                .add(&pad_limb)
                .sub(&right_group_limb);
            let carry_biguint: BigUint = (&carry).into();
            carry = BLSScalar::from(
                &carry_biguint.shr(num_limbs_in_this_group * BIT_PER_LIMB),
            );
            accumulated_extra += BigUint::from_bytes_le(&pad_limb.to_bytes());

            let (new_accumulated_extra, remainder_biguint) = accumulated_extra.div_rem(
                &BigUint::from(1u64).shl(BIT_PER_LIMB * num_limbs_in_this_group),
            );
            let remainder = BLSScalar::from(&remainder_biguint);

            let eqn_left = left_group_limb
                .add(&pad_limb)
                .add(&carry_in)
                .sub(&right_group_limb);

            let eqn_right = (&carry)
                .mul(
                    &(&BigUint::from(1u32).shl(BIT_PER_LIMB * num_limbs_in_this_group))
                        .into(),
                )
                .add(&remainder);

            assert_eq!(eqn_left, eqn_right);

            accumulated_extra = new_accumulated_extra;
            carry_in = carry;

            if group_id == left_group.len() - 1 {
                assert_eq!(carry, (&accumulated_extra).into());
            } else {
                // bound the size of carry
                assert!(BigUint::from(1u32)
                    .shl(surfeit + BIT_PER_LIMB * 2)
                    .gt(&(&carry).into()));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::field_simulation::{ristretto_scalar_field_in_biguint, SimFr};
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::Zero;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_enforce_zero_trivial() {
        let zero_fr = SimFr::from(&BigUint::zero());
        let zero_fr_mul = (&zero_fr) * (&zero_fr);

        zero_fr_mul.enforce_zero();
    }

    #[test]
    fn test_enforce_zero() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        for _ in 0..1000 {
            let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
            let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

            let a_fr = SimFr::from(&a);
            let b_fr = SimFr::from(&b);

            let ab_fr_mul = &a_fr * &b_fr;
            let ab_fr = &a * &b;
            assert_eq!(ab_fr, (&ab_fr_mul).into());

            let ab_fr_reduced = &ab_fr % &r_biguint;
            let ab_reduced = SimFr::from(&ab_fr_reduced);

            let zero_supposed = &ab_fr_mul - &ab_reduced;
            let zero_supposed_biguint: BigUint = (&zero_supposed).into();
            assert_eq!(BigUint::zero(), &zero_supposed_biguint % &r_biguint);
            zero_supposed.enforce_zero();
        }
    }

    #[test]
    #[should_panic]
    fn test_enforce_zero_panic() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
        let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

        let a_fr = SimFr::from(&a);
        let b_fr = SimFr::from(&b);

        let ab_fr_mul = &a_fr * &b_fr;
        let ab_fr = &a * &b;
        assert_eq!(ab_fr, (&ab_fr_mul).into());

        let ab_fr_reduced_manipulated = &ab_fr % &r_biguint + &BigUint::from(10u64);
        let ab_reduced_manipulated = SimFr::from(&ab_fr_reduced_manipulated);

        let zero_supposed_manipulated = &ab_fr_mul - &ab_reduced_manipulated;
        zero_supposed_manipulated.enforce_zero();
    }
}
