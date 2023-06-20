use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use noah_algebra::prelude::*;

/// Trait for the Elligator
pub trait ElligatorParameters<G: CurveGroup> {
    /// Constant A of the curve for Elligator.
    const A: G::BaseType;

    /// Constant B of the curve for Elligator.
    const B: G::BaseType;

    /// A quadratic nonresidue.
    const QNR: G::BaseType;

    /// Convert to the default group element.
    fn convert_to_group(x: &G::BaseType, y: &G::BaseType) -> Result<G>;

    /// Convert from the default group element.
    fn convert_from_group(p: &G) -> Result<(G::BaseType, G::BaseType)>;
}

/// The elligator.
pub struct Elligator<G: CurveGroup, P: ElligatorParameters<G>> {
    curve_phantom: PhantomData<G>,
    param_phantom: PhantomData<P>,
}

impl<G: CurveGroup, P: ElligatorParameters<G>> Elligator<G, P> {
    /// check whether candidate x lies on the curve
    pub(crate) fn is_x_on_curve(x: &G::BaseType) -> bool {
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
}

impl<G: CurveGroup, P: ElligatorParameters<G>> HashingToCurve<G> for Elligator<G, P> {
    type Trace = ElligatorTrace<G>;

    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let temp = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;

        let x1 = temp.mul(P::A).neg();
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }
        let x2 = P::A.add(x1).neg();
        return Ok(x2);
    }

    fn get_cofactor_uncleared_x_and_trace(t: &G::BaseType) -> Result<(G::BaseType, Self::Trace)> {
        let t_sq = t.square();
        let a2 = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;
        let x1 = a2.mul(P::A).neg();

        let mut y_squared: G::BaseType = x1 * x1 * x1;
        if !P::A.is_zero() {
            y_squared += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(x1 * &P::B);
        }

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        return if b1 {
            let a3 = y_squared.sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            Ok((x1, trace))
        } else {
            let x2 = P::A.add(x1).neg();
            let a3 = (y_squared * P::QNR).sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            Ok((x2, trace))
        };
    }

    fn get_cofactor_uncleared_point(t: &G::BaseType) -> Result<(G::BaseType, G::BaseType)> {
        let t_sq = t.square();
        let temp = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;

        let x1 = temp.mul(P::A).neg();

        let mut y_squared: G::BaseType = x1 * x1 * x1;
        if !P::A.is_zero() {
            y_squared += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(x1 * &P::B);
        }

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        return if b1 {
            let y = y_squared.sqrt().unwrap();
            Ok((x1, y))
        } else {
            let x2 = P::A.add(x1).neg();

            let mut y_squared: G::BaseType = x2 * x2 * x2;
            if !P::A.is_zero() {
                y_squared += &(x2 * x2 * P::A);
            }
            if !P::B.is_zero() {
                y_squared += &(x2 * &P::B);
            }

            let y = y_squared.sqrt().unwrap();
            Ok((x2, y))
        };
    }

    fn get_cofactor_uncleared_point_and_trace(
        t: &G::BaseType,
    ) -> Result<(G::BaseType, G::BaseType, Self::Trace)> {
        let t_sq = t.square();
        let a2 = t_sq.mul(P::QNR).add(G::BaseType::one()).inv()?;
        let x1 = a2.mul(P::A).neg();

        let mut y_squared: G::BaseType = x1 * x1 * x1;
        if !P::A.is_zero() {
            y_squared += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(x1 * &P::B);
        }

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        return if b1 {
            let a3 = y_squared.sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            Ok((x1, a3, trace))
        } else {
            let x2 = P::A.add(x1).neg();

            let mut y_squared: G::BaseType = x2 * x2 * x2;
            if !P::A.is_zero() {
                y_squared += &(x2 * x2 * P::A);
            }
            if !P::B.is_zero() {
                y_squared += &(x2 * &P::B);
            }
            let y = y_squared.sqrt().unwrap();

            let a3 = (y_squared * P::QNR).sqrt().unwrap();
            let trace = Self::Trace { a2, b1, a3 };
            Ok((x2, y, trace))
        };
    }

    fn verify_trace(t: &G::BaseType, final_x: &G::BaseType, trace: &Self::Trace) -> bool {
        let t_sq = t.square();
        let a2_inv = t_sq.mul(P::QNR).add(G::BaseType::one());

        if !(trace.a2 * a2_inv).is_one() {
            return false;
        }

        let a2 = trace.a2;
        let x1 = a2.mul(P::A).neg();

        let mut y_squared: G::BaseType = x1 * x1 * x1;
        if !P::A.is_zero() {
            y_squared += &(x1 * x1 * P::A);
        }
        if !P::B.is_zero() {
            y_squared += &(x1 * &P::B);
        }

        if trace.b1 {
            if y_squared != trace.a3.square() {
                return false;
            }
        } else {
            if y_squared * P::QNR != trace.a3.square() {
                return false;
            }
        }

        let b1 = trace.b1;

        if b1 {
            if *final_x != x1 {
                return false;
            } else {
                return true;
            }
        }

        let x2 = P::A.add(x1).neg();

        if *final_x != x2 {
            return false;
        }

        return true;
    }

    fn convert_to_group(x: &G::BaseType, y: &G::BaseType) -> Result<G> {
        P::convert_to_group(x, y)
    }

    fn convert_from_group(p: &G) -> Result<(G::BaseType, G::BaseType)> {
        P::convert_from_group(p)
    }
}

/// Struct for the trace for the elligator.
pub struct ElligatorTrace<G: CurveGroup> {
    /// a2 is A / (1 + qnr * t^2).
    pub a2: G::BaseType,
    /// b1 is the Legendre symbol of f(x1):
    /// false for quadratic nonresidue, true for quadratic residue
    pub b1: bool,
    /// a3 is the witness of square root (or adjusted square root).
    pub a3: G::BaseType,
}
