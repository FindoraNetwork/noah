use crate::errors::Result;
use noah_algebra::traits::Scalar;

/// Trait for the Shallue-van de Woestijne map
pub trait SW<S: Scalar> {
    /// Constant Z0 of Shallue-van de Woestijne map
    const Z0: S;
    /// Constant C1 of Shallue-van de Woestijne map
    const C1: S;
    /// Constant C2 of Shallue-van de Woestijne map
    const C2: S;
    /// Constant C3 of Shallue-van de Woestijne map
    const C3: S;
    /// Constant C4 of Shallue-van de Woestijne map
    const C4: S;
    /// Constant C5 of Shallue-van de Woestijne map
    const C5: S;
    /// Constant C6 of Shallue-van de Woestijne map
    const C6: S;

    /// first candidate for solution x
    fn x1(&self, t: &S) -> Result<S> {
        let t_sq_inv = t.square().inv()?;
        let c3t_sq_inv = Self::C3.mul(t_sq_inv);
        let temp = S::one().add(c3t_sq_inv);
        let temp2 = Self::C2.mul(temp.inv()?);
        Ok(Self::C1.sub(&temp2))
    }

    /// second candidate for solution x
    fn x2(&self, x1: &S) -> S {
        Self::C4.sub(x1)
    }

    /// third candidate for solution x
    fn x3(&self, t: &S) -> Result<S> {
        let t_sq = t.square();
        let t_sq_inv = t_sq.inv()?;
        let c3t_sq_inv = Self::C3.mul(t_sq_inv);
        let temp = S::one().add(c3t_sq_inv);
        let temp2 = t_sq.mul(temp.square());

        Ok(Self::C5.add(Self::C6.mul(temp2)))
    }

    /// check whether candidate x lies on the curve
    fn is_x_on_curve(&self, x: &S) -> bool;
}

/// Trait for the simplified SWU map
pub trait SimplifiedSWU<S: Scalar> {
    /// first candidate for solution x
    fn isogeny_x1(&self, t: &S) -> Result<S>;

    /// second candidate for solution x
    fn isogeny_x2(&self, t: &S, x1: &S) -> Result<S>;

    /// check whether candidate x lies on the curve
    fn is_x_on_isogeny_curve(&self, x: &S) -> bool;

    /// map x back to the original curve
    fn isogeny_map_x(&self, x: &S) -> Result<S>;
}
