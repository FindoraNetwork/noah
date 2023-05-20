use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use noah_algebra::marker::PhantomData;
use noah_algebra::prelude::*;

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
