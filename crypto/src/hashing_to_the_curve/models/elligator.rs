use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use noah_algebra::marker::PhantomData;
use noah_algebra::prelude::*;

/// Trait for the Elligator
pub trait ElligatorParameters<G: CurveGroup> {
    /// Constant A of the curve for Elligator.
    const A: G::BaseType;

    /// Constant B of the curve for Elligator.
    const B: G::BaseType;

    /// A quadratic nonresidue.
    const QNR: G::BaseType;
}

/// The elligator.
pub struct Elligator<G: CurveGroup, P: ElligatorParameters<G>> {
    curve_phantom: PhantomData<G>,
    param_phantom: PhantomData<P>,
}

impl<G: CurveGroup, P: ElligatorParameters<G>> Elligator<G, P> {
    /// check whether candidate x lies on the curve
    fn is_x_on_curve(x: &G::BaseType) -> bool {
        let mut y_squared = *x * x * x;
        if !P::A.is_zero() {
            y_squared += &(*x * x * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(*x * &P::B);
        }

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }

    /// first candidate for solution x
    fn x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let temp = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;

        Ok(temp.mul(P::A).neg())
    }

    /// second candidate for solution x
    fn x2(x1: &G::BaseType) -> Result<G::BaseType> {
        Ok(P::A.add(x1).neg())
    }
}

impl<G: CurveGroup, P: ElligatorParameters<G>> HashingToCurve<G> for Elligator<G, P> {
    type Trace = ElligatorTrace<G>;

    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType> {
        let x1 = Self::x1(&t)?;
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }
        let x2 = Self::x2(&x1)?;
        return Ok(x2);
    }

    fn get_cofactor_uncleared_x_and_trace(t: &G::BaseType) -> Result<(G::BaseType, Self::Trace)> {
        let t_sq = t.square();
        let a2 = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;
        let x1 = a2.mul(P::A).neg();

        let mut y_squared: G::BaseType = *x * x * x;
        if !P::A.is_zero() {
            y_squared += &(*x * x * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(*x * &P::B);
        }

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        if b1 {
            let a3 = y_squared.sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            return Ok((x1, trace));
        } else {
            let x2 = Self::x2(&x1)?;
            let a3 = (*y_squared * Self::QNR).sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            return Ok((x2, trace));
        }
    }
}

/// Struct for the trace.
pub struct ElligatorTrace<G: CurveGroup> {
    /// a2 is A / (1 + qnr * t^2).
    pub a2: G::BaseType,
    /// b1 is the Legendre symbol of f(x1):
    /// false for quadratic nonresidue, true for quadratic residue
    pub b1: bool,
    /// a3 is the witness of square root (or adjusted square root).
    pub a3: G::BaseType,
}
