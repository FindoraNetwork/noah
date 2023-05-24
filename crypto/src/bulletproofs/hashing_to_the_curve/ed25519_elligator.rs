use crate::errors::Result;
use crate::hashing_to_the_curve::ed25519::elligator::Ed25519ElligatorParameters;
use crate::hashing_to_the_curve::models::elligator::{ElligatorParameters, ElligatorTrace};
use ark_bulletproofs::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
use ark_ed25519::Fq;
use ark_ff::Field;
use noah_algebra::ed25519::Ed25519Point;

/// A trace variable.
#[allow(unused)]
struct TraceVar {
    a2_var: Variable<Fq>,
    a3_var: Variable<Fq>,
    b1_var: Variable<Fq>,
}

impl TraceVar {
    /// Create a new point variable from field variables.
    #[allow(unused)]
    pub(crate) fn new(a2_var: Variable<Fq>, a3_var: Variable<Fq>, b1_var: Variable<Fq>) -> Self {
        Self {
            a2_var,
            a3_var,
            b1_var,
        }
    }

    /// Allocate a point in Bulletproofs.
    #[allow(unused)]
    pub(crate) fn allocate<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        trace: &ElligatorTrace<Ed25519Point>,
    ) -> Result<Self> {
        let a2_var = cs.allocate(Some(trace.a2.get_raw()))?;
        let a3_var = cs.allocate(Some(trace.a3.get_raw()))?;

        let b1_elem = if trace.b1 { Fq::ONE } else { Fq::ZERO };

        let b1_var = cs.allocate(Some(b1_elem))?;
        Ok(Self::new(a2_var, a3_var, b1_var))
    }
}

/// A proof of scalar multiplication.
pub struct HashingGadget;

impl HashingGadget {
    #[allow(unused)]
    fn gadget<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        trace_var: &TraceVar,
        t_var: &Variable<Fq>,
        final_var: &Variable<Fq>,
    ) -> Result<()> {
        let (_, _, t_sq_var) = cs.multiply((*t_var).into(), (*t_var).into());

        let (_, _, a2_mul_a2_inv) = cs.multiply(
            t_sq_var * (Ed25519ElligatorParameters::QNR.get_raw()) + Fq::ONE,
            trace_var.a2_var.into(),
        );
        cs.constrain(a2_mul_a2_inv - Fq::ONE);

        let (_, _, b1_mul_minus_b1) = cs.multiply(
            trace_var.b1_var.into(),
            LinearCombination::from(trace_var.b1_var.clone()) + Fq::ONE,
        );
        cs.constrain(b1_mul_minus_b1.into());

        let x1_var = -trace_var.a2_var.clone() * Ed25519ElligatorParameters::A.get_raw();

        let (_, _, x1_sq_var) = cs.multiply(x1_var.clone(), x1_var.clone());
        let (_, _, x1_cubic_var) = cs.multiply(x1_sq_var.into(), x1_var.clone());

        let y_squared_var = x1_cubic_var
            + x1_sq_var * Ed25519ElligatorParameters::A.get_raw()
            + x1_var.clone() * Ed25519ElligatorParameters::B.get_raw();

        let (_, _, a3_sq_var) = cs.multiply(trace_var.a3_var.into(), trace_var.a3_var.into());
        let (_, _, y_squared_adjusted_var) = cs.multiply(
            y_squared_var,
            (-LinearCombination::from(trace_var.b1_var.clone()) + Fq::ONE)
                * Ed25519ElligatorParameters::QNR.get_raw(),
        );

        cs.constrain(a3_sq_var - y_squared_adjusted_var);

        let (_, _, b1_times_double_x1_plus_a) = cs.multiply(
            trace_var.b1_var.into(),
            LinearCombination::from(x1_var.clone()) * Fq::from(2u32)
                + Ed25519ElligatorParameters::A.get_raw(),
        );

        cs.constrain(
            LinearCombination::from((*final_var).clone())
                + Ed25519ElligatorParameters::A.get_raw()
                + x1_var.clone()
                - b1_times_double_x1_plus_a,
        );

        Ok(())
    }
}
