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
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType> {
        let x1 = Self::x1(&t)?;
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }
        let x2 = Self::x2(&x1)?;
        return Ok(x2);
    }
}
