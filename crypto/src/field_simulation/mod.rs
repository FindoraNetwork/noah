use noah_algebra::prelude::*;
use num_bigint::BigUint;
use num_integer::Integer;

mod bls12_381;
pub use bls12_381::*;

/// The trait for parameters for field simulation.
pub trait SimFrParams<F: Scalar>: Clone + Default {
    /// The number of limbs in the simulated field element representation.
    const NUM_OF_LIMBS: usize;
    /// The expected number of bits for non-top limbs.
    const BIT_PER_LIMB: usize;
    /// The expected number of bits for the top limb.
    const BIT_IN_TOP_LIMB: usize;
    /// The number of limbs in the intermediate representation.
    const NUM_OF_LIMBS_MUL: usize = Self::NUM_OF_LIMBS * 2 - 1;
    /// The number of groups used during the zero-checking algorithm.
    const NUM_OF_GROUPS: usize;

    /// This is the `BigUint` of the scalar field modulus.
    fn scalar_field_in_biguint() -> BigUint;

    /// This is the limbs of the scalar field modulus.
    fn scalar_field_in_limbs() -> Vec<F>;

    /// This is the limbs of the scalar field modulus being adjusted
    /// so that each limb is more than 2^{BIT_PER_LIMB} (except the last one, 2^{BIT_IN_TOP_LIMB}).
    ///
    /// We use it in subtraction, and we call it sub pad.
    fn scalar_field_sub_pad_in_limbs() -> Vec<F>;

    /// This is the `BigUint` representation of the sub pad.
    fn scalar_field_sub_pad_in_biguint() -> BigUint;
}

/// A precise indicator of the reducibility in a simulate element.
#[derive(Eq, PartialEq, Clone)]
pub enum SimReducibility {
    /// For public input or constant, the field element is in the normalized form.
    StrictlyNotReducible,
    /// For witness, meaning that the field element is either `x` or `x + p`.
    AtMostReducibleByOne,
    /// The field element might have been added this number of times.
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

/// `SimFr` is the simulated scalar field element over some scalar field.
#[derive(Clone)]
pub struct SimFr<F: Scalar, P: SimFrParams<F>> {
    /// The limbs of a simulated field element.
    pub limbs: Vec<F>,
    /// The actual value of the simulated field element.
    pub val: BigUint,
    /// The reducibility of this simulated field element.
    pub num_of_additions_over_normal_form: SimReducibility,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
}

impl<F: Scalar, P: SimFrParams<F>> Default for SimFr<F, P> {
    fn default() -> Self {
        Self {
            limbs: vec![F::zero(); P::NUM_OF_LIMBS],
            val: BigUint::zero(),
            num_of_additions_over_normal_form: SimReducibility::StrictlyNotReducible,
            params_phantom: PhantomData::default(),
        }
    }
}

impl<F: Scalar, P: SimFrParams<F>> Sub<&SimFr<F, P>> for &SimFr<F, P> {
    type Output = SimFr<F, P>;

    fn sub(self, rhs: &SimFr<F, P>) -> SimFr<F, P> {
        // For simplicity, given that our use case involves only one subtraction,
        // we require the value to be subtracted by a simulated field element
        // with at most one addition.
        //
        assert!(
            rhs.num_of_additions_over_normal_form == SimReducibility::StrictlyNotReducible
                || rhs.num_of_additions_over_normal_form == SimReducibility::AtMostReducibleByOne
        );

        let mut res = SimFr::<F, P>::default();
        let r_limbs = P::scalar_field_sub_pad_in_limbs();
        let r_biguint = P::scalar_field_sub_pad_in_biguint();

        for i in 0..P::NUM_OF_LIMBS {
            res.limbs[i] = self.limbs[i].add(&r_limbs[i]).sub(&rhs.limbs[i]);
        }
        res.val = (&self.val).add(&r_biguint).sub(&rhs.val);

        res.num_of_additions_over_normal_form = SimReducibility::Others(
            BigUint::from(&self.num_of_additions_over_normal_form) + BigUint::from(3u32),
        );

        res
    }
}

impl<F: Scalar, P: SimFrParams<F>> Mul<&SimFr<F, P>> for &SimFr<F, P> {
    type Output = SimFrMul<F, P>;

    fn mul(self, rhs: &SimFr<F, P>) -> SimFrMul<F, P> {
        let mut mul_res = SimFrMul::<F, P>::default();
        for i in 0..P::NUM_OF_LIMBS {
            for j in 0..P::NUM_OF_LIMBS {
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

impl<F: Scalar, P: SimFrParams<F>> From<&BigUint> for SimFr<F, P> {
    fn from(src: &BigUint) -> Self {
        let mut rem = src.clone();

        let step = BigUint::from(1u32).shl(P::BIT_PER_LIMB);

        let mut res = SimFr::<F, P>::default();
        res.val = rem.clone();
        for i in 0..P::NUM_OF_LIMBS {
            let (new_rem, limb) = rem.div_rem(&step);
            rem = new_rem;
            res.limbs[i] = F::from(&limb);
        }
        res.num_of_additions_over_normal_form = SimReducibility::StrictlyNotReducible;

        res
    }
}

impl<F: Scalar, P: SimFrParams<F>> Into<BigUint> for &SimFr<F, P> {
    fn into(self) -> BigUint {
        let step = BigUint::from(1u32).shl(P::BIT_PER_LIMB);
        let mut res = BigUint::zero();
        for limb in self.limbs.iter().rev() {
            res.mul_assign(&step);
            res.add_assign(&limb.clone().into());
        }
        assert_eq!(res, self.val);
        res
    }
}

impl<F: Scalar, P: SimFrParams<F>> SimFr<F, P> {
    /// Check if the *actual* value of the simulated field element is zero.
    /// Note: One cannot simply require each limb to be zero, because the limbs
    ///   could be representing k * p where k is a positive integer.
    pub fn is_zero(&self) -> bool {
        let self_biguint: BigUint = self.into();
        let r_biguint = P::scalar_field_in_biguint();

        let (_, rem) = self_biguint.div_rem(&r_biguint);
        rem.is_zero()
    }
}

/// `SimFrMul` is the intermediate representation for the product of two simulated
/// scalar field elements over some scalar field.
#[derive(Clone)]
pub struct SimFrMul<F: Scalar, P: SimFrParams<F>> {
    /// The limbs of this intermediate representation.
    pub limbs: Vec<F>,
    /// The actual value of this intermediate representation.
    pub val: BigUint,
    /// The product of the num of additions over two original field elements.
    pub prod_of_num_of_additions: BigUint,
    /// PhantomData for the parameters.
    pub params_phantom: PhantomData<P>,
}

impl<F: Scalar, P: SimFrParams<F>> Default for SimFrMul<F, P> {
    fn default() -> Self {
        Self {
            limbs: vec![F::zero(); P::NUM_OF_LIMBS_MUL],
            val: BigUint::zero(),
            prod_of_num_of_additions: BigUint::zero(),
            params_phantom: PhantomData::default(),
        }
    }
}

impl<F: Scalar, P: SimFrParams<F>> Into<BigUint> for &SimFrMul<F, P> {
    fn into(self) -> BigUint {
        let step = BigUint::from(1u32).shl(P::BIT_PER_LIMB);
        let mut res = BigUint::zero();
        for limb in self.limbs.iter().rev() {
            res.mul_assign(&step);
            res.add_assign(&limb.clone().into());
        }
        assert_eq!(self.val, res);
        res
    }
}

impl<F: Scalar, P: SimFrParams<F>> Add<&SimFrMul<F, P>> for &SimFrMul<F, P> {
    type Output = SimFrMul<F, P>;

    fn add(self, rhs: &SimFrMul<F, P>) -> SimFrMul<F, P> {
        let mut res = (*self).clone();

        for i in 0..P::NUM_OF_LIMBS_MUL {
            res.limbs[i] = res.limbs[i].add(&rhs.limbs[i]);
        }
        res.val = &res.val + &rhs.val;
        res.prod_of_num_of_additions =
            &res.prod_of_num_of_additions + &rhs.prod_of_num_of_additions;

        res
    }
}

impl<F: Scalar, P: SimFrParams<F>> Sub<&SimFr<F, P>> for &SimFrMul<F, P> {
    type Output = SimFrMul<F, P>;

    fn sub(self, rhs: &SimFr<F, P>) -> SimFrMul<F, P> {
        // For simplicity, we require the value to be subtracted
        // by a simulated field element with at most four additions.
        //
        assert!(BigUint::from(&rhs.num_of_additions_over_normal_form) <= BigUint::from(4u32));

        let mut res = (*self).clone();
        let r_limbs = P::scalar_field_sub_pad_in_limbs();
        let r_biguint = P::scalar_field_sub_pad_in_biguint();

        for i in 0..P::NUM_OF_LIMBS {
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

impl<F: Scalar, P: SimFrParams<F>> SimFrMul<F, P> {
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
        let r_biguint = P::scalar_field_in_biguint();

        // The idea is to show that there exists `k * r` that is exactly the current number
        // in `SimFrMul`, by a few shifts.

        // compute `k`
        let (k, rem) = cur_val.div_rem(&r_biguint);
        assert!(rem.is_zero());
        assert!(k <= r_biguint.clone().shl(5u32));

        // compute the limbs for `k * r`
        let r_limbs = P::scalar_field_in_limbs().to_vec();
        let k_limbs = SimFr::<F, P>::from(&k).limbs.to_vec();

        let mut rk_limbs = vec![F::zero(); P::NUM_OF_LIMBS_MUL];
        for i in 0..P::NUM_OF_LIMBS {
            for j in 0..P::NUM_OF_LIMBS {
                rk_limbs[i + j] = rk_limbs[i + j].add(&r_limbs[i].mul(&k_limbs[j]));
            }
        }

        // group the limbs of `self` and the limbs of `k * r` together
        // this step is for efficiency, so that carry adders have fewer steps
        let mut left_group = Vec::with_capacity(P::NUM_OF_GROUPS);
        let mut right_group = Vec::with_capacity(P::NUM_OF_GROUPS);
        let mut num_limbs_in_group = Vec::with_capacity(P::NUM_OF_GROUPS);

        let step = F::from(&BigUint::from(1u32).shl(P::BIT_PER_LIMB));
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

        let mut carry_in = F::zero();
        let mut accumulated_extra = BigUint::zero();
        for (group_id, ((left_group_limb, right_group_limb), num_limbs_in_this_group)) in left_group
            .iter()
            .zip(right_group.iter())
            .zip(num_limbs_in_group.iter())
            .enumerate()
        {
            let pad = BigUint::from(1u32).shl(
                (num_limbs_in_this_group + 1) * P::BIT_PER_LIMB + num_limbs_in_this_group + surfeit,
            );
            let pad_limb = F::from(&pad);
            assert!(pad > <F as Into<BigUint>>::into(right_group_limb.clone()));

            // Compute the carry number for the next cycle
            let mut carry = left_group_limb
                .add(&carry_in)
                .add(&pad_limb)
                .sub(&right_group_limb);
            let carry_biguint: BigUint = carry.into();
            carry = F::from(&carry_biguint.shr(num_limbs_in_this_group * P::BIT_PER_LIMB));
            accumulated_extra += BigUint::from_bytes_le(&pad_limb.to_bytes());

            let (new_accumulated_extra, remainder_biguint) = accumulated_extra
                .div_rem(&BigUint::from(1u64).shl(P::BIT_PER_LIMB * num_limbs_in_this_group));
            let remainder = F::from(&remainder_biguint);

            let eqn_left = left_group_limb
                .add(&pad_limb)
                .add(&carry_in)
                .sub(&right_group_limb);

            let eqn_right = (&carry)
                .mul(&(&BigUint::from(1u32).shl(P::BIT_PER_LIMB * num_limbs_in_this_group)).into())
                .add(&remainder);

            assert_eq!(eqn_left, eqn_right);

            accumulated_extra = new_accumulated_extra;
            carry_in = carry;

            if group_id == left_group.len() - 1 {
                assert_eq!(carry, (&accumulated_extra).into());
            } else {
                // bound the size of carry
                assert!(BigUint::from(1u32)
                    .shl(surfeit + P::BIT_PER_LIMB * 2)
                    .gt(&carry.into()));
            }
        }
    }
}
