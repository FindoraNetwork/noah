use crate::errors::Result;
use crate::hashing_to_the_curve::traits::HashingToCurve;
use noah_algebra::prelude::*;

/// Trait for the parameters for the simplified SWU map.
pub trait SSWUParameters<G: CurveGroup> {
    /// The -b/a of the isogeny curve.
    const C1: G::BaseType;
    /// The A of the isogeny curve.
    const A: G::BaseType;
    /// The B of the isogeny curve.
    const B: G::BaseType;
    /// A quadratic nonresidue.
    const QNR: G::BaseType;
    /// The A of the original curve.
    const A_ORG: G::BaseType;
    /// The B of the original curve.
    const B_ORG: G::BaseType;

    /// Degree of the isogeny map.
    const ISOGENY_DEGREE: u32;

    /// Get a numerator term in the isogeny parameters.
    fn get_isogeny_numerator_term<'a>(i: usize) -> &'a G::BaseType;

    /// Get a denominator term in the isogeny parameters.
    fn get_isogeny_denominator_term<'a>(i: usize) -> &'a G::BaseType;

    /// Convert to the default group element.
    fn convert_to_group(x: &G::BaseType, y: &G::BaseType) -> Result<G>;

    /// Convert from the default group element.
    fn convert_from_group(p: &G) -> Result<(G::BaseType, G::BaseType)>;
}

/// The simplified SWU map
#[derive(Default)]
pub struct SSWUMap<G: CurveGroup, P: SSWUParameters<G>> {
    curve_phantom: PhantomData<G>,
    param_phantom: PhantomData<P>,
}

/// Trait for the simplified SWU map.
impl<G: CurveGroup, P: SSWUParameters<G>> SSWUMap<G, P> {
    /// map the point from the isogenous curve to the original curve.
    pub fn isogeny_map_x(x: &G::BaseType) -> Result<G::BaseType> {
        let degree = P::ISOGENY_DEGREE;

        if degree == 0 {
            return Ok(*x);
        }

        let mut numerator: G::BaseType = *P::get_isogeny_numerator_term(0);
        let mut denominator: G::BaseType = *P::get_isogeny_denominator_term(0);

        let mut cur = *x;
        for i in 1u32..degree {
            numerator = numerator + cur * P::get_isogeny_numerator_term(i as usize);
            denominator = denominator + cur * P::get_isogeny_denominator_term(i as usize);

            cur *= x;
        }
        numerator = numerator + cur * P::get_isogeny_numerator_term(degree as usize);

        Ok(numerator.mul(denominator.inv()?))
    }

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

    /// check whether candidate x lies on the isogeny curve
    pub fn is_x_on_isogeny_curve(x: &G::BaseType) -> bool {
        let mut y_squared = (*x * x * x).add(P::B);
        y_squared = y_squared.add(P::A.mul(x));

        y_squared.legendre() != LegendreSymbol::QuadraticNonResidue
    }

    /// check whether candidate x lies on the original curve
    pub fn is_x_on_original_curve(x: &G::BaseType) -> bool {
        let mut y_squared = (*x * x * x).add(P::B_ORG);
        y_squared = y_squared.add(P::A_ORG.mul(x));

        y_squared.legendre() != LegendreSymbol::QuadraticNonResidue
    }
}

impl<G: CurveGroup, P: SSWUParameters<G>> HashingToCurve<G> for SSWUMap<G, P> {
    type Trace = SSWUTrace<G>;

    fn get_cofactor_uncleared_x(t: &G::BaseType) -> Result<G::BaseType> {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let a3 = t4.add(&t2).inv()?;

        let x1 = P::C1.mul(&a3.add(G::BaseType::one()));
        if Self::is_x_on_isogeny_curve(&x1) {
            return Self::isogeny_map_x(&x1);
        }
        let x2 = x1.mul(t2);
        Self::isogeny_map_x(&x2)
    }

    fn get_cofactor_uncleared_x_and_trace(t: &G::BaseType) -> Result<(G::BaseType, Self::Trace)> {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let a3 = t4.add(&t2).inv()?;

        let x1 = P::C1.mul(&a3.add(G::BaseType::one()));

        let mut y_squared = (x1 * x1 * x1).add(P::B);
        y_squared = y_squared.add(P::A.mul(x1));

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        if b1 {
            let a4 = y_squared.sqrt().unwrap();
            let trace = Self::Trace { a3, b1, a4 };
            Ok((Self::isogeny_map_x(&x1)?, trace))
        } else {
            let x2 = x1.mul(t2);
            let a4 = (y_squared * P::QNR).sqrt().unwrap();
            let trace = Self::Trace { a3, b1, a4 };
            Ok((Self::isogeny_map_x(&x2)?, trace))
        }
    }

    fn get_cofactor_uncleared_point(t: &G::BaseType) -> Result<(G::BaseType, G::BaseType)> {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let a3 = t4.add(&t2).inv()?;

        let x1 = P::C1.mul(&a3.add(G::BaseType::one()));

        let mut y_squared = (x1 * x1 * x1).add(P::B);
        y_squared = y_squared.add(P::A.mul(x1));

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        if b1 {
            let x1_org = Self::isogeny_map_x(&x1)?;
            let mut y_squared_org = (x1_org * x1_org * x1_org).add(P::B_ORG);
            y_squared_org = y_squared_org.add(P::A_ORG.mul(x1_org));

            let y_org = y_squared_org.sqrt().unwrap();
            Ok((x1_org, y_org))
        } else {
            let x2 = x1.mul(t2);

            let x2_org = Self::isogeny_map_x(&x2)?;
            let mut y_squared_org = (x2_org * x2_org * x2_org).add(P::B_ORG);
            y_squared_org = y_squared_org.add(P::A_ORG.mul(x2_org));

            let y_org = y_squared_org.sqrt().unwrap();
            Ok((x2_org, y_org))
        }
    }

    fn get_cofactor_uncleared_point_and_trace(
        t: &G::BaseType,
    ) -> Result<(G::BaseType, G::BaseType, Self::Trace)> {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let a3 = t4.add(&t2).inv()?;

        let x1 = P::C1.mul(&a3.add(G::BaseType::one()));

        let mut y_squared = (x1 * x1 * x1).add(P::B);
        y_squared = y_squared.add(P::A.mul(x1));

        let b1 = y_squared.legendre() != LegendreSymbol::QuadraticNonResidue;

        if b1 {
            let a4 = y_squared.sqrt().unwrap();
            let trace = Self::Trace { a3, b1, a4 };

            let x1_org = Self::isogeny_map_x(&x1)?;
            let mut y_squared_org = (x1_org * x1_org * x1_org).add(P::B_ORG);
            y_squared_org = y_squared_org.add(P::A_ORG.mul(x1_org));

            let y_org = y_squared_org.sqrt().unwrap();

            Ok((x1_org, y_org, trace))
        } else {
            let x2 = x1.mul(t2);
            let a4 = (y_squared * P::QNR).sqrt().unwrap();
            let trace = Self::Trace { a3, b1, a4 };

            let x2_org = Self::isogeny_map_x(&x2)?;
            let mut y_squared_org = (x2_org * x2_org * x2_org).add(P::B_ORG);
            y_squared_org = y_squared_org.add(P::A_ORG.mul(x2_org));

            let y_org = y_squared_org.sqrt().unwrap();

            Ok((x2_org, y_org, trace))
        }
    }

    fn verify_trace(t: &G::BaseType, final_x: &G::BaseType, trace: &Self::Trace) -> bool {
        let t2 = t.square().mul(P::QNR);
        let t4 = t2.square();

        let a3_inv = t4.add(&t2);
        if !(trace.a3 * a3_inv).is_one() {
            return false;
        }

        let a3 = trace.a3;

        let x1 = P::C1.mul(&a3.add(G::BaseType::one()));

        let mut y_squared = (x1 * x1 * x1).add(P::B);
        y_squared = y_squared.add(P::A.mul(x1));

        if trace.b1 {
            if y_squared != trace.a4.square() {
                return false;
            }
        } else if y_squared * P::QNR != trace.a4.square() {
            return false;
        }

        let b1 = trace.b1;

        if b1 {
            return *final_x == Self::isogeny_map_x(&x1).unwrap()
        }

        let x2 = x1.mul(t2);

        if *final_x != Self::isogeny_map_x(&x2).unwrap() {
            return false;
        }

        true
    }

    fn convert_to_group(x: &G::BaseType, y: &G::BaseType) -> Result<G> {
        P::convert_to_group(x, y)
    }

    fn convert_from_group(p: &G) -> Result<(G::BaseType, G::BaseType)> {
        P::convert_from_group(p)
    }
}

/// Struct for the trace for the simplified SWU map.
pub struct SSWUTrace<G: CurveGroup> {
    /// a3 = 1 / (qnr^2 * t^4 + qnr * t^2)
    pub a3: G::BaseType,
    /// b1 is the Legendre symbol of f(x1):
    /// false for quadratic nonresidue, true for quadratic residue
    pub b1: bool,
    /// a4 is the witness of square root (or adjusted square root).
    pub a4: G::BaseType,
}
