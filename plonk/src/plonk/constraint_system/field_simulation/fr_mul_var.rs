use crate::plonk::constraint_system::{
    field_simulation::SimFrVar, TurboConstraintSystem, VarIndex,
};
use num_bigint::BigUint;
use num_integer::Integer;
use std::{
    cmp::{max, min},
    ops::{Shl, Shr},
};
use zei_algebra::{bls12_381::BLSScalar, prelude::*};
use zei_crypto::field_simulation::{
    ristretto_scalar_field_in_biguint, ristretto_scalar_field_in_limbs,
    ristretto_scalar_field_sub_pad_in_limbs, SimFr, SimFrMul, BIT_IN_TOP_LIMB, BIT_PER_LIMB,
    NUM_OF_GROUPS, NUM_OF_LIMBS, NUM_OF_LIMBS_MUL,
};

/// `SimFrMulVar` is the variable for `SimFrMul` in
/// `TurboConstraintSystem<BLSScalar>`
#[derive(Clone)]
pub struct SimFrMulVar {
    /// the `SimFrMul` value.
    pub val: SimFrMul,
    /// the `SimFrMul` variables.
    pub var: [VarIndex; NUM_OF_LIMBS_MUL],
}

impl SimFrMulVar {
    /// Create a zero `SimFrMul`.
    pub fn new(cs: &mut TurboConstraintSystem<BLSScalar>) -> Self {
        Self {
            val: SimFrMul::default(),
            var: [cs.zero_var(); NUM_OF_LIMBS_MUL],
        }
    }

    /// the Sub operation.
    pub fn sub(&self, cs: &mut TurboConstraintSystem<BLSScalar>, other: &SimFrVar) -> SimFrMulVar {
        let mut res = self.clone();
        res.val = &self.val - &other.val;

        let zero_var = cs.zero_var();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let minus_one = one.neg();

        let r_limbs = ristretto_scalar_field_sub_pad_in_limbs();
        for i in 0..NUM_OF_LIMBS {
            res.var[i] = cs.new_variable(res.val.limbs[i]);

            // The following gate represents
            // res.var[i] := self.var[i] - other.var[i] + r_limbs[i] * 4

            cs.push_add_selectors(one, zero, minus_one, zero);
            cs.push_mul_selectors(zero, zero);
            cs.push_constant_selector(
                r_limbs[i]
                    .add(&r_limbs[i])
                    .add(&r_limbs[i])
                    .add(&r_limbs[i]),
            );
            cs.push_ecc_selector(zero);
            cs.push_rescue_selectors(zero, zero, zero, zero);
            cs.push_out_selector(one);

            cs.wiring[0].push(self.var[i]);
            cs.wiring[1].push(zero_var);
            cs.wiring[2].push(other.var[i]);
            cs.wiring[3].push(zero_var);
            cs.wiring[4].push(res.var[i]);
            cs.size += 1;
        }

        res
    }

    /// Enforce a zero constraint.
    pub fn enforce_zero(&self, cs: &mut TurboConstraintSystem<BLSScalar>) {
        let surfeit = self.val.prod_of_num_of_additions.bits() as usize;
        assert!(surfeit <= 5);

        let cur_val: BigUint = (&self.val).into();
        let r_biguint = ristretto_scalar_field_in_biguint();

        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        let minus_one = one.neg();

        let zero_var = cs.zero_var();

        let (k, rem) = cur_val.div_rem(&r_biguint);
        assert!(rem.is_zero());

        // For safety, make sure `k` is not too big.
        assert!(k.lt(&r_biguint.shl(5u32)));

        let r_limbs = ristretto_scalar_field_in_limbs().to_vec();
        let k_limbs = SimFr::from(&k).limbs.to_vec();
        let mut k_limbs_var = Vec::with_capacity(k_limbs.len());
        for i in 0..NUM_OF_LIMBS {
            let new_var = cs.new_variable(k_limbs[i]);
            if i == NUM_OF_LIMBS - 1 {
                cs.range_check(new_var, BIT_IN_TOP_LIMB + 5);
            } else {
                cs.range_check(new_var, BIT_PER_LIMB);
            }
            k_limbs_var.push(new_var);
        }

        let mut rk_limbs = vec![BLSScalar::zero(); NUM_OF_LIMBS_MUL];

        for i in 0..NUM_OF_LIMBS {
            for j in 0..NUM_OF_LIMBS {
                rk_limbs[i + j] = rk_limbs[i + j].add(&r_limbs[i].mul(&k_limbs[j]));
            }
        }

        let mut rk_limbs_var = Vec::with_capacity(NUM_OF_LIMBS_MUL);
        for i in 0..NUM_OF_LIMBS_MUL {
            let smallest_left = max(NUM_OF_LIMBS, i + 1) - NUM_OF_LIMBS;
            let largest_left = min(i, NUM_OF_LIMBS - 1);

            let left_array = (smallest_left..=largest_left).collect::<Vec<_>>();

            let mut res = cs.zero_var();
            for left_chuck in left_array.chunks(3) {
                let (first_index, first_multiple) =
                    { (k_limbs_var[i - left_chuck[0]], r_limbs[left_chuck[0]]) };

                let (second_index, second_multiple) = if left_chuck.len() > 1 {
                    (k_limbs_var[i - left_chuck[1]], r_limbs[left_chuck[1]])
                } else {
                    (zero_var, BLSScalar::zero())
                };

                let (third_index, third_multiple) = if left_chuck.len() > 2 {
                    (k_limbs_var[i - left_chuck[2]], r_limbs[left_chuck[2]])
                } else {
                    (zero_var, BLSScalar::zero())
                };

                res = cs.linear_combine(
                    &[res, first_index, second_index, third_index],
                    one,
                    first_multiple,
                    second_multiple,
                    third_multiple,
                );
            }

            rk_limbs_var.push(res);
        }

        // Now group several limbs together
        let mut left_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut right_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut left_var_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut right_var_group = Vec::with_capacity(NUM_OF_GROUPS);
        let mut num_limbs_in_group = Vec::with_capacity(NUM_OF_GROUPS);

        let step = BLSScalar::from(&BigUint::from(1u32).shl(BIT_PER_LIMB));

        for i in 0..NUM_OF_GROUPS {
            if i * 2 + 1 < NUM_OF_LIMBS_MUL {
                let res = self.val.limbs[2 * i].add(&self.val.limbs[2 * i + 1].mul(&step));
                left_group.push(res);

                let var = cs.linear_combine(
                    &[self.var[2 * i], zero_var, self.var[2 * i + 1], zero_var],
                    one,
                    zero,
                    step,
                    zero,
                );
                left_var_group.push(var);

                let res = rk_limbs[2 * i].add(&rk_limbs[2 * i + 1].mul(&step));
                right_group.push(res);

                let var = cs.linear_combine(
                    &[
                        rk_limbs_var[2 * i],
                        zero_var,
                        rk_limbs_var[2 * i + 1],
                        zero_var,
                    ],
                    one,
                    zero,
                    step,
                    zero,
                );
                right_var_group.push(var);

                num_limbs_in_group.push(2);
            } else {
                left_group.push(self.val.limbs[2 * i]);
                left_var_group.push(self.var[2 * i]);

                right_group.push(rk_limbs[2 * i]);
                right_var_group.push(rk_limbs_var[2 * i]);

                num_limbs_in_group.push(1);
            }
        }

        // Perform the following checking
        //      left_group_limb + pad_limb + carry_in - right_group_limb
        //   =  carry shift by (BIT_PER_LIMB * num_limb_in_group) + remainder

        let mut carry_in = BLSScalar::zero();
        let mut carry_in_var = cs.zero_var();
        let mut accumulated_extra = BigUint::zero();
        for (
            group_id,
            (
                (((left_group_limb, right_group_limb), left_group_limb_var), right_group_limb_var),
                num_limbs_in_this_group,
            ),
        ) in left_group
            .iter()
            .zip(right_group.iter())
            .zip(left_var_group.iter())
            .zip(right_var_group.iter())
            .zip(num_limbs_in_group.iter())
            .enumerate()
        {
            let pad = BigUint::from(1u32).shl(
                (num_limbs_in_this_group + 1) * BIT_PER_LIMB + num_limbs_in_this_group + surfeit,
            );
            let pad_limb = BLSScalar::from(&pad);
            assert!(pad > <&BLSScalar as Into<BigUint>>::into(right_group_limb));

            // Compute the carry number for the next cycle
            let mut carry = left_group_limb
                .add(&carry_in)
                .add(&pad_limb)
                .sub(&right_group_limb);
            let carry_biguint: BigUint = (&carry).into();
            carry = BLSScalar::from(&carry_biguint.shr(num_limbs_in_this_group * BIT_PER_LIMB));
            accumulated_extra += BigUint::from_bytes_le(&pad_limb.to_bytes());

            let carry_var = cs.new_variable(carry);

            let (new_accumulated_extra, remainder_biguint) = accumulated_extra
                .div_rem(&BigUint::from(1u64).shl(BIT_PER_LIMB * num_limbs_in_this_group));
            let remainder = BLSScalar::from(&remainder_biguint);

            let carry_shift =
                (&BigUint::from(1u32).shl(BIT_PER_LIMB * num_limbs_in_this_group)).into();
            {
                // The following gate represents
                // - left_group_limb - carry_in + right_group_limb_var
                // - pad_limb + carry_shift * carry_var + remainder = 0
                cs.push_add_selectors(minus_one, minus_one, one, carry_shift);
                cs.push_mul_selectors(zero, zero);
                cs.push_constant_selector(pad_limb.neg().add(&remainder));
                cs.push_ecc_selector(zero);
                cs.push_rescue_selectors(zero, zero, zero, zero);
                cs.push_out_selector(zero);

                cs.wiring[0].push(*left_group_limb_var);
                cs.wiring[1].push(carry_in_var);
                cs.wiring[2].push(*right_group_limb_var);
                cs.wiring[3].push(carry_var);
                cs.wiring[4].push(zero_var);
                cs.size += 1;
            }

            accumulated_extra = new_accumulated_extra;
            carry_in = carry;
            carry_in_var = carry_var;

            if group_id == left_group.len() - 1 {
                cs.insert_constant_gate(carry_var, (&accumulated_extra).into());
            } else {
                cs.range_check(carry_var, surfeit + BIT_PER_LIMB * 2);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::plonk::constraint_system::{
        field_simulation::SimFrVar, turbo::TurboConstraintSystem,
    };
    use num_bigint::{BigUint, RandBigInt};
    use rand_chacha::ChaCha20Rng;
    use zei_algebra::{bls12_381::BLSScalar, prelude::*};
    use zei_crypto::field_simulation::{ristretto_scalar_field_in_biguint, SimFr};

    #[test]
    fn test_enforce_zero_trivial() {
        let mut cs = TurboConstraintSystem::<BLSScalar>::new();

        let zero_fr = SimFr::from(&BigUint::zero());
        let zero_fr_val = SimFrVar::alloc_witness(&mut cs, &zero_fr);
        let zero_fr_mul_val = zero_fr_val.mul(&mut cs, &zero_fr_val);

        zero_fr_mul_val.enforce_zero(&mut cs);
    }

    #[test]
    fn test_enforce_zero() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        for _ in 0..1000 {
            let mut cs = TurboConstraintSystem::<BLSScalar>::new();

            let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
            let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

            let a_fr = SimFr::from(&a);
            let b_fr = SimFr::from(&b);

            let a_fr_val = SimFrVar::alloc_witness(&mut cs, &a_fr);
            let b_fr_val = SimFrVar::alloc_witness(&mut cs, &b_fr);

            let ab_fr_mul_val = a_fr_val.mul(&mut cs, &b_fr_val);

            let ab_fr = &a * &b;
            let ab_fr_reduced = &ab_fr % &r_biguint;
            let ab_reduced = SimFr::from(&ab_fr_reduced);
            let ab_reduced_val = SimFrVar::alloc_witness(&mut cs, &ab_reduced);

            let zero_supposed = ab_fr_mul_val.sub(&mut cs, &ab_reduced_val);
            zero_supposed.enforce_zero(&mut cs);
        }
    }

    #[test]
    #[should_panic]
    fn test_enforce_zero_panic() {
        let mut rng = ChaCha20Rng::from_entropy();
        let r_biguint = ristretto_scalar_field_in_biguint();

        let mut cs = TurboConstraintSystem::<BLSScalar>::new();

        let a = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);
        let b = rng.gen_biguint_range(&BigUint::zero(), &r_biguint);

        let a_fr = SimFr::from(&a);
        let b_fr = SimFr::from(&b);

        let a_fr_val = SimFrVar::alloc_witness(&mut cs, &a_fr);
        let b_fr_val = SimFrVar::alloc_witness(&mut cs, &b_fr);

        let ab_fr_mul_val = a_fr_val.mul(&mut cs, &b_fr_val);

        let ab_fr = &a * &b;
        let ab_fr_reduced_manipulated = &ab_fr % &r_biguint + &BigUint::from(10u64);
        let ab_reduced_manipulated = SimFr::from(&ab_fr_reduced_manipulated);
        let ab_reduced_manipulated_val = SimFrVar::alloc_witness(&mut cs, &ab_reduced_manipulated);

        let zero_supposed_manipulated = ab_fr_mul_val.sub(&mut cs, &ab_reduced_manipulated_val);
        zero_supposed_manipulated.enforce_zero(&mut cs);
    }
}
