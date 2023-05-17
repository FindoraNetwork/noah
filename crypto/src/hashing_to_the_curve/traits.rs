use crate::errors::Result;
use noah_algebra::prelude::*;

/// Trait for the Shallue-van de Woestijne map
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

    /// first candidate for solution x
    fn x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq_inv = t.square().inv()?;
        let c3t_sq_inv = Self::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = Self::C2.mul(temp.inv()?);
        Ok(Self::C1.sub(&temp2))
    }

    /// second candidate for solution x
    fn x2(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq_inv = t.square().inv()?;
        let c3t_sq_inv = Self::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = Self::C2.mul(temp.inv()?);
        Ok(Self::C4.add(&temp2))
    }

    /// third candidate for solution x
    fn x3(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let t_sq_inv = t_sq.inv()?;
        let c3t_sq_inv = Self::C3.mul(t_sq_inv);
        let temp = G::BaseType::one().add(c3t_sq_inv);
        let temp2 = t_sq.mul(temp.square());

        Ok(Self::C5.add(Self::C6.mul(temp2)))
    }

    /// check whether candidate x lies on the curve
    fn is_x_on_curve(x: &G::BaseType) -> bool;

    /// get the x coordinate directly
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

/// Trait for the simplified SWU map
pub trait SimplifiedSWUParameters<G: CurveGroup> {
    /// The -b/a of the isogeny curve.
    const C1: G::BaseType;
    /// The A of the isogeny curve.
    const A: G::BaseType;
    /// The B of the isogeny curve.
    const B: G::BaseType;
    /// A quadratic nonresidue.
    const QNR: G::BaseType;

    /// first candidate for solution x
    fn isogeny_x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t2 = t.square().mul(Self::QNR);
        let t4 = t2.square();

        let temp = t4.add(&t2).inv()?.add(G::BaseType::one());
        Ok(Self::C1.mul(temp))
    }

    /// second candidate for solution x
    fn isogeny_x2(t: &G::BaseType, x1: &G::BaseType) -> Result<G::BaseType> {
        let t2 = t.square();
        Ok(x1.mul(t2).mul(Self::QNR))
    }

    /// check whether candidate x lies on the curve
    fn is_x_on_isogeny_curve(x: &G::BaseType) -> bool {
        let mut y_squared = (*x * x * x).add(Self::B);
        y_squared = y_squared.add(Self::A.mul(x));

        if y_squared.legendre() == LegendreSymbol::QuadraticNonResidue {
            false
        } else {
            true
        }
    }

    /// map x back to the original curve
    fn isogeny_map_x(x: &G::BaseType) -> Result<G::BaseType>;

    /// get the x coordinate directly
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
    /// Constant A of the curve for Elligator
    const A: G::BaseType;

    /// A quadratic nonresidue
    const QNR: G::BaseType;

    /// first candidate for solution x
    fn x1(t: &G::BaseType) -> Result<G::BaseType> {
        let t_sq = t.square();
        let temp = t_sq.mul(Self::QNR).add(G::BaseType::one()).inv()?;

        Ok(temp.mul(Self::A).neg())
    }

    /// second candidate for solution x
    fn x2(x1: &G::BaseType) -> Result<G::BaseType> {
        Ok(Self::A.add(x1).neg())
    }

    /// check whether candidate x lies on the curve
    fn is_x_on_curve(x: &G::BaseType) -> bool;

    /// get the x coordinate directly
    fn get_x_coordinate_without_cofactor_clearing(t: &G::BaseType) -> Result<G::BaseType> {
        let x1 = Self::x1(&t)?;
        if Self::is_x_on_curve(&x1) {
            return Ok(x1);
        }
        let x2 = Self::x2(&x1)?;
        return Ok(x2);
    }
}
