use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use noah_algebra::marker::PhantomData;
use noah_algebra::prelude::*;

/// Trait for the parameters for Shallue-van de Woestijne map.
pub trait SWParameters<G: CurveGroup> {
    /// Constant Z0 of Shallue-van de Woestijne map
    const Z0: G::BaseType;
    /// Constant C1 of Shallue-van de Woestijne map
    const C1: G::BaseType;
    /// Constant C2 of Shallue-van de Woestijne map
    const C2: G::BaseType;
    /// Constant C3 of Shallue-van de Woestijne map
    const C3: G::BaseType;
    /// Constant C4 of Shallue-van de Woestijne map
    const C4: G::BaseType;
    /// Constant C5 of Shallue-van de Woestijne map
    const C5: G::BaseType;
    /// Constant C6 of Shallue-van de Woestijne map
    const C6: G::BaseType;
    /// Constant A of the curve
    const A: G::BaseType;
    /// Constant B of the curve
    const B: G::BaseType;
    /// Constant C of the curve
    const C: G::BaseType;
}

/// The Shallue-van de Woestijne map
#[derive(Default)]
pub struct SWMap<G: CurveGroup, P: SWParameters<G>> {
    curve_phantom: PhantomData<G>,
    param_phantom: PhantomData<P>,
}

impl<G: CurveGroup, P: SWParameters<G>> SWMap<G, P> {
    /// first candidate for solution x
    pub fn x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq_inv = t.square().inv()?;
        let c3t_sq_inv = P::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = P::C2.mul(temp.inv()?);
        Ok(P::C1.sub(&temp2))
    }

    /// second candidate for solution x
    pub fn x2(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq_inv = t.square().inv()?;
        let c3t_sq_inv = P::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = P::C2.mul(temp.inv()?);
        Ok(P::C4.add(&temp2))
    }

    /// third candidate for solution x
    pub fn x3(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let t_sq_inv = t_sq.inv()?;
        let c3t_sq_inv = P::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = t_sq.mul(temp.square());

        Ok(P::C5.add(P::C6.mul(temp2)))
    }

    /// check whether candidate x lies on the curve
    pub fn is_x_on_curve(x: &G::BaseType) -> bool {
        let mut rhs = x.pow(&[3u64]) + P::C;
        if !P::A.is_zero() {
            rhs += &(*x * x * P::A);
        }
        if !P::B.is_zero() {
            rhs += &(*x * P::B);
        }

        if rhs.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }
}

impl<G: CurveGroup, P: SWParameters<G>> HashingToCurve<G> for SWMap<G, P> {
    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType> {
        let x1 = Self::x1(&t)?;
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }
        let x2 = Self::x2(&t)?;
        if Self::is_x_on_curve(&x2) {
            return Ok(x2);
        }
        let x3 = Self::x3(&t)?;
        return Ok(x3);
    }
}
