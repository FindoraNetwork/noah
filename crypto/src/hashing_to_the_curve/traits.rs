use crate::errors::Result;
use noah_algebra::prelude::*;
use std::marker::PhantomData;

/// Trait for hashing to the curve.
pub trait HashingToCurve<G: CurveGroup> {
    /// get the x coordinate directly
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType>;
}

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
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType> {
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

/// Trait for the parameters for the simplified SWU map.
pub trait SimplifiedSWUParameters<G: CurveGroup> {
    /// The -b/a of the isogeny curve.
    const C1: G::BaseType;
    /// The A of the isogeny curve.
    const A: G::BaseType;
    /// The B of the isogeny curve.
    const B: G::BaseType;
    /// A quadratic nonresidue.
    const QNR: G::BaseType;

    /// The isogeny map for x.
    fn isogeny_map_x(x: &G::BaseType) -> Result<G::BaseType>;
}

/// The simplified SWU map
#[derive(Default)]
pub struct SimplifiedSWUMap<G: CurveGroup, P: SimplifiedSWUParameters<G>> {
    curve_phantom: PhantomData<G>,
    param_phantom: PhantomData<P>,
}

/// Trait for the simplified SWU map.
impl<G: CurveGroup, P: SimplifiedSWUParameters<G>> SimplifiedSWUMap<G, P> {
    /// first candidate for solution x
    pub fn isogeny_x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let temp = t4.add(&t2).inv()?.add(G::BaseType::one());
        Ok(P::C1.mul(temp))
    }

    /// second candidate for solution x
    pub fn isogeny_x2(t: &G::BaseType, x1: &G::BaseType) -> Result<G::BaseType> {
        let t2 = t.square();
        Ok(x1.mul(t2).mul(P::QNR))
    }

    /// check whether candidate x lies on the curve
    pub fn is_x_on_isogeny_curve(x: &G::BaseType) -> bool {
        let mut y_squared = (*x * x * x).add(P::B);
        y_squared = y_squared.add(P::A.mul(x));

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }

    /// map x back to the original curve
    pub fn isogeny_map_x(x: &G::BaseType) -> Result<G::BaseType> {
        P::isogeny_map_x(x)
    }
}

impl<G: CurveGroup, P: SimplifiedSWUParameters<G>> HashingToCurve<G> for SimplifiedSWUMap<G, P> {
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType> {
        let x1 = Self::isogeny_x1(&t)?;
        if Self::is_x_on_isogeny_curve(&x1) {
            return Self::isogeny_map_x(&x1);
        }
        let x2 = Self::isogeny_x2(&t, &x1)?;
        return Self::isogeny_map_x(&x2);
    }
}

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
