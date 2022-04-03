use num_bigint::BigUint;
use num_integer::Integer;
use zei_algebra::bls12_381::BLSScalar;
use zei_algebra::prelude::*;
use zei_algebra::str::FromStr;

pub const NUM_OF_LIMBS: usize = 6;
pub const BIT_PER_LIMB: usize = 43;
pub const BIT_IN_TOP_LIMB: usize = 38;
pub const NUM_OF_LIMBS_MUL: usize = NUM_OF_LIMBS * 2 - 1;

pub const NUM_OF_GROUPS: usize = 6;

/// A precise indicator of the reducibility in a simulate element
#[derive(Eq, PartialEq, Clone)]
pub enum SimReducibility {
    StrictlyNotReducible,
    AtMostReducibleByOne,
    Others(BigUint),
}

impl<'a> From<&'a SimReducibility> for BigUint {
    fn from(src: &'a SimReducibility) -> Self {
        match src {
            SimReducibility::StrictlyNotReducible => BigUint::zero(),
            SimReducibility::AtMostReducibleByOne => BigUint::one(),
            SimReducibility::Others(x) => x.clone(),
        }
    }
}

/// This is the `BigUint` of the Ristretto scalar field modulus.
pub fn ristretto_scalar_field_in_biguint() -> BigUint {
    BigUint::from_str(
        "7237005577332262213973186563042994240857116359379907606001950938285454250989",
    )
    .unwrap()
}

/// This is the limbs of the Ristretto scalar field modulus.
pub fn ristretto_scalar_field_in_limbs() -> [BLSScalar; NUM_OF_LIMBS] {
    [
        BLSScalar::from_str("3411763647469").unwrap(),
        BLSScalar::from_str("7643343815244").unwrap(),
        BLSScalar::from_str("358561053323").unwrap(),
        BLSScalar::from_str("0").unwrap(),
        BLSScalar::from_str("0").unwrap(),
        BLSScalar::from_str("137438953472").unwrap(),
    ]
}

/// This is the limbs of the Ristretto scalar field modulus being adjusted
/// so that each limb is more than 2^43 (except the last one, 2^38).
///
/// We use it in subtraction, and we call it sub pad.
pub fn ristretto_scalar_field_sub_pad_in_limbs() -> [BLSScalar; NUM_OF_LIMBS] {
    [
        BLSScalar::from_str("10235290942407").unwrap(),
        BLSScalar::from_str("14133938423524").unwrap(),
        BLSScalar::from_str("9871776182178").unwrap(),
        BLSScalar::from_str("17592186044415").unwrap(),
        BLSScalar::from_str("17592186044414").unwrap(),
        BLSScalar::from_str("412316860414").unwrap(),
    ]
}

/// This is the `BigUint` representation of the sub pad.
pub fn ristretto_scalar_field_sub_pad_in_biguint() -> BigUint {
    BigUint::from_str(
        "21711016731996786641919559689128982722571349078139722818005852814856362752967",
    )
    .unwrap()
}

/// `SimFr` is the simulated Ristretto scalar field element
/// over BLS12-381 scalar field.
///
#[derive(Clone)]
pub struct SimFr {
    pub limbs: [BLSScalar; NUM_OF_LIMBS],
    pub val: BigUint,
    pub num_of_additions_over_normal_form: SimReducibility,
}

impl Default for SimFr {
    fn default() -> Self {
        Self {
            limbs: [BLSScalar::zero(); NUM_OF_LIMBS],
            val: BigUint::zero(),
            num_of_additions_over_normal_form: SimReducibility::StrictlyNotReducible,
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
            rhs.num_of_additions_over_normal_form == SimReducibility::StrictlyNotReducible
                || rhs.num_of_additions_over_normal_form == SimReducibility::AtMostReducibleByOne
        );

        let mut res = SimFr::default();
        let r_limbs = ristretto_scalar_field_sub_pad_in_limbs();
        let r_biguint = ristretto_scalar_field_sub_pad_in_biguint();

        for i in 0..NUM_OF_LIMBS {
            res.limbs[i] = self.limbs[i].add(&r_limbs[i]).sub(&rhs.limbs[i]);
        }
        res.val = (&self.val).add(&r_biguint).sub(&rhs.val);

        res.num_of_additions_over_normal_form = SimReducibility::Others(
            BigUint::from(&self.num_of_additions_over_normal_form) + BigUint::from(3u32),
        );

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
        mul_res.prod_of_num_of_additions = BigUint::from(&self.num_of_additions_over_normal_form)
            .add(&BigUint::one())
            .mul(&BigUint::from(&rhs.num_of_additions_over_normal_form).add(&BigUint::one()));

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
        res.num_of_additions_over_normal_form = SimReducibility::StrictlyNotReducible;

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
        assert!(BigUint::from(&rhs.num_of_additions_over_normal_form) <= BigUint::from(4u32));

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
        res.val = &res.val + &r_biguint + &r_biguint + &r_biguint + &r_biguint - &rhs.val;
        res.prod_of_num_of_additions = &res.prod_of_num_of_additions + &BigUint::from(12u32);

        res
    }
}

impl SimFrMul {
    /// The `enforce_zero` function uses the techniques from two works:
    ///
    /// [KPS18](https://akosba.github.io/papers/xjsnark.pdf):
    /// A. E. Kosba, C. Papamanthou, and E. Shi.
    /// "xJsnark: a framework for efficient verifiable computation,"
    /// in S&P 2018
    ///
    /// [OWWB20](https://eprint.iacr.org/2019/1494.pdf):
    /// A. Ozdemir, R. S. Wahby, B. Whitehat, and D. Boneh.
    /// "Scaling verifiable computation using efficient set accumulators,"
    /// in USENIX Security 2020
    ///
    /// And the code is from xJsnark, bellman-bignat, and arkworks-rs.
    ///
    pub fn enforce_zero(&self) {
        // For safety, since in our use case we are only doing very few algebraic operations,
        // we limit the `prod_of_num_of_additions` to be smaller than 32.
        assert!(self.prod_of_num_of_additions.bits() as usize <= 5);
        let surfeit = 5; // for safety

        let cur_val: BigUint = self.into();
        let r_biguint = ristretto_scalar_field_in_biguint();

        // The idea is to show that there exists `k * r` that is exactly the current number
        // in `SimFrMul`, by a few shifts.

        // compute `k`
        let (k, rem) = cur_val.div_rem(&r_biguint);
        assert!(rem.is_zero());
        assert!(k <= r_biguint.shl(5u32));

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
        for (group_id, ((left_group_limb, right_group_limb), num_limbs_in_this_group)) in left_group
            .iter()
            .zip(right_group.iter())
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

            let (new_accumulated_extra, remainder_biguint) = accumulated_extra
                .div_rem(&BigUint::from(1u64).shl(BIT_PER_LIMB * num_limbs_in_this_group));
            let remainder = BLSScalar::from(&remainder_biguint);

            let eqn_left = left_group_limb
                .add(&pad_limb)
                .add(&carry_in)
                .sub(&right_group_limb);

            let eqn_right = (&carry)
                .mul(&(&BigUint::from(1u32).shl(BIT_PER_LIMB * num_limbs_in_this_group)).into())
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
    use num_integer::Integer;
    use rand_chacha::ChaCha20Rng;
    use zei_algebra::prelude::*;

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
