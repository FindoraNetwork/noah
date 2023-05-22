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
    /// A quadratic nonresidue.
    const QNR: G::BaseType;
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
    pub fn x2(_t: &G::BaseType, x1: &G::BaseType) -> Result<G::BaseType> {
        Ok(P::C4.sub(&x1))
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
    type Trace = SWTrace<G>;

    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let a2 = t_sq.inv()?;
        let c3t_sq_inv = P::C3.mul(a2);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let a3 = temp.inv()?;

        let temp2 = P::C2.mul(a3);
        let x1 = P::C1.sub(&temp2);
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }

        let x2 = P::C4.sub(&x1);
        if Self::is_x_on_curve(&x2) {
            return Ok(x2);
        }

        let temp3 = t_sq.mul(temp.square());
        let x3 = P::C5.add(P::C6.mul(temp3));
        return Ok(x3);
    }

    fn get_cofactor_uncleared_x_and_trace(t: &G::BaseType) -> Result<(G::BaseType, Self::Trace)> {
        let t_sq = t.square();
        let a2 = t_sq.inv()?;
        let c3t_sq_inv = P::C3.mul(a2);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let a3 = temp.inv()?;

        let temp2 = P::C2.mul(a3);
        let x1 = P::C1.sub(&temp2);

        let mut y_squared_1 = x1 * x1 * x1 + P::C;
        if !P::A.is_zero() {
            y_squared_1 += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared_1 += &(x1 * P::B);
        }

        let b1 = y_squared_1.legendre() != LegendreSymbol::QuadraticNonResidue;

        let x2 = P::C4.sub(&x1);
        let mut y_squared_2 = x2 * x2 * x2 + P::C;
        if !P::A.is_zero() {
            y_squared_2 += &(x2 * x2 * P::A);
        }
        if !P::B.is_zero() {
            y_squared_2 += &(x2 * P::B);
        }

        let b2 = y_squared_2.legendre() != LegendreSymbol::QuadraticNonResidue;

        let a4 = if b1 {
            y_squared_1.sqrt().unwrap()
        } else {
            (y_squared_1 * P::QNR).sqrt().unwrap()
        };

        let a5 = if b2 {
            y_squared_2.sqrt().unwrap()
        } else {
            (y_squared_2 * P::QNR).sqrt().unwrap()
        };

        let trace = SWTrace::<G> {
            a2,
            a3,
            b1,
            b2,
            a4,
            a5,
        };

        if b1 {
            return Ok((x1, trace));
        }

        if b2 {
            return Ok((x2, trace));
        }

        let temp3 = t_sq.mul(temp.square());
        let x3 = P::C5.add(P::C6.mul(temp3));

        return Ok((x3, trace));
    }

    fn verify_trace(t: &G::BaseType, final_x: &G::BaseType, trace: &Self::Trace) -> bool {
        let t_sq = t.square();

        if !(trace.a2 * t_sq).is_one() {
            return false;
        }

        let a2 = trace.a2;

        let c3t_sq_inv = P::C3.mul(a2);
        let temp = G::BaseType::one().add(c3t_sq_inv);

        if !(trace.a3 * temp).is_one() {
            return false;
        }

        let a3 = trace.a3;

        let temp2 = P::C2.mul(a3);
        let x1 = P::C1.sub(&temp2);

        let mut y_squared_1 = x1 * x1 * x1 + P::C;
        if !P::A.is_zero() {
            y_squared_1 += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared_1 += &(x1 * P::B);
        }

        if trace.b1 {
            if y_squared_1 != trace.a4.square() {
                return false;
            }
        } else {
            if y_squared_1 * P::QNR != trace.a4.square() {
                return false;
            }
        }

        let x2 = P::C4.sub(&x1);
        let mut y_squared_2 = x2 * x2 * x2 + P::C;
        if !P::A.is_zero() {
            y_squared_2 += &(x2 * x2 * P::A);
        }
        if !P::B.is_zero() {
            y_squared_2 += &(x2 * P::B);
        }

        let b1 = trace.b1;

        if b1 {
            if *final_x != x1 {
                return false;
            } else {
                return true;
            }
        }

        if trace.b2 {
            if y_squared_2 != trace.a5.square() {
                return false;
            }
        } else {
            if y_squared_2 * P::QNR != trace.a5.square() {
                return false;
            }
        }

        let b2 = trace.b2;

        if b2 {
            if *final_x != x2 {
                return false;
            } else {
                return true;
            }
        }

        let temp3 = t_sq.mul(temp.square());
        let x3 = P::C5.add(P::C6.mul(temp3));

        if *final_x != x3 {
            return false;
        }

        return true;
    }
}

/// Struct for the trace for the Shallue-van de Woestijne map.
pub struct SWTrace<G: CurveGroup> {
    /// a2 = 1/t^2
    pub a2: G::BaseType,
    /// a3 = 1/(1 + C3 * a2)
    pub a3: G::BaseType,
    /// b1 is the Legendre symbol of f(x1):
    /// false for quadratic nonresidue, true for quadratic residue
    pub b1: bool,
    /// b2 is the Legendre symbol of f(x2).
    pub b2: bool,
    /// a4 is the witness of square root (or adjusted square root) about f(x1).
    pub a4: G::BaseType,
    /// a5 is the witness of square root (or adjusted square root) about f(x2).
    pub a5: G::BaseType,
}
