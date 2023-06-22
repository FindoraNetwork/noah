use crate::plonk::constraint_system::ecc::{ExtendedPointVar, PointVar};
use crate::plonk::constraint_system::{TurboCS, VarIndex};
use noah_algebra::prelude::*;
use noah_algebra::traits::TECurve;

/// Given a base point [G] and a scalar s, denote as s[G] the scalar multiplication
/// The function compute
/// {4^i * [G]}_{i=0..n-1}, {2 * 4^i * [G]}_{i=0..n-1}, and {3 * 4^i * [G]}_{i=0..n-1}
/// [G] is represented in extended form because doubling/addition is more efficient.
fn compute_base_multiples<T: TECurve>(base: T, n: usize) -> Vec<Vec<T>> {
    let mut bases = vec![vec![], vec![], vec![]];
    let mut point = base;
    for i in 0..n {
        let point2 = point.double();
        let point3 = point2.add(&point);
        bases[0].push(point);
        bases[2].push(point3);
        if i < n - 1 {
            point = point2.double();
        }
        bases[1].push(point2);
    }
    bases
}

impl<S: Scalar> TurboCS<S> {
    /// Given public base points [G0 = identity, G1, G2, G3] and
    /// 2 boolean variables b0, b1 \in {0, 1}, returns G_{b0 + 2 * b1}
    ///
    /// x-coordinate constraint:
    /// x = b0 * (1-b1) * G1.x + (1-b0) * b1 * G2.x + b0 * b1 * G3.x
    /// wiring: w1 = b0, w2 = b1, w_out = x
    /// selectors: q1 = G1.x, q2 = G2.x, qm1 = G3.x - G2.x - G1.x, qo = 1
    ///
    /// y-coordinate constraint:
    /// y = (1-b0) * (1-b1) + b0 * (1-b1) * G1.y + (1-b0) * b1 * G2.y + b0 * b1 * G3.y
    /// wiring: w1 = b0, w2 = b1, w_out = y
    /// selectors: q1 = G1.y - 1, q2 = G2.y - 1, qm1 = G3.y - G2.y - G1.y + 1, qc = 1, qo = 1
    fn select_constant_points<T: TECurve<BaseType = S>>(
        &mut self,
        g1: &T,
        g2: &T,
        g3: &T,
        b0_var: VarIndex,
        b1_var: VarIndex,
    ) -> ExtendedPointVar<T> {
        assert!(b0_var < self.num_vars, "b0 variable index out of bound");
        assert!(b1_var < self.num_vars, "b1 variable index out of bound");
        let one = S::one();
        let zero = S::zero();
        let p_out_ext: T = match (self.witness[b0_var] == one, self.witness[b1_var] == one) {
            (false, false) => T::get_identity(),
            (true, false) => *g1,
            (false, true) => *g2,
            (true, true) => *g3,
        };
        let p_out_var = self.new_point_variable(p_out_ext);

        // x-coordinate constraint

        self.push_mul_selectors(g3.get_x().sub(&g1.get_x().add(&g2.get_x())), zero);
        self.push_add_selectors(g1.get_x(), g2.get_x(), zero, zero);
        self.push_constant_selector(zero);
        self.push_ecc_selector(zero);
        self.push_out_selector(one);

        self.wiring[0].push(b0_var);
        self.wiring[1].push(b1_var);
        self.wiring[2].push(0);
        self.wiring[3].push(0);
        self.wiring[4].push(p_out_var.0);
        self.finish_new_gate();

        // y-coordinate constraint
        self.push_add_selectors(g1.get_y().sub(&one), g2.get_y().sub(&one), zero, zero);
        self.push_mul_selectors(g3.get_y().add(&one).sub(&g1.get_y().add(&g2.get_y())), zero);
        self.push_constant_selector(one);
        self.push_ecc_selector(zero);
        self.push_out_selector(one);

        self.wiring[0].push(b0_var);
        self.wiring[1].push(b1_var);
        self.wiring[2].push(0);
        self.wiring[3].push(0);
        self.wiring[4].push(p_out_var.1);
        self.finish_new_gate();

        ExtendedPointVar(p_out_var, p_out_ext)
    }

    ///  Constant-base scalar multiplication:
    ///  Given a base point `[G]` and an `n_bits`-bit secret scalar `s`, returns `s * [G]`.
    /// `n_bits` should be a positive even number.
    pub fn const_base_scalar_mul<T: TECurve<BaseType = S>>(
        &mut self,
        base: T,
        scalar_var: VarIndex,
        n_bits: usize,
    ) -> PointVar {
        assert_eq!(n_bits & 1, 0, "n_bits is odd");
        assert!(n_bits > 0, "n_bits is not positive");

        let b_scalar_var = self.range_check(scalar_var, n_bits);
        let bases = compute_base_multiples(base, n_bits >> 1);
        self.scalar_mul_with_const_bases(&bases[0], &bases[1], &bases[2], &b_scalar_var)
    }

    /// Constant-base scalar multiplication with precomputed bases.
    /// To compute `s[G]` from base point G and secret scalar s, we set
    /// ```text
    /// bases0 = [identity]_{i=0..n-1},
    /// bases1 = [4^i * G]_{i=0..n-1},
    /// bases2 = [2 * 4^i * G]_{i=0..n-1}
    /// bases3 = [3 * 4^i * G]_{i=0..n-1}
    /// ```
    /// The binary representation of the secret scalar s: `[b0, ..., b_{2*n-1}]`
    /// Then
    /// ```text
    /// s[G] = \sum_{i=0..n-1} (b_{2*i} + 2 * b_{2*i+1}) * [4^i * G]
    ///           = \sum_{i=0..n-1} bases_{b_{2*i} + 2 * b_{2*i+1}}[i]
    /// ```
    pub fn scalar_mul_with_const_bases<T: TECurve<BaseType = S>>(
        &mut self,
        bases1: &[T],
        bases2: &[T],
        bases3: &[T],
        b_scalar_var: &[VarIndex],
    ) -> PointVar {
        let n_bits = b_scalar_var.len();
        assert_eq!(n_bits & 1, 0, "n_bits is odd");
        assert!(n_bits > 0, "n_bits is not positive");
        let n_bits_half = n_bits >> 1;
        assert_eq!(n_bits_half, bases1.len(), "bases1 has wrong size");
        assert_eq!(n_bits_half, bases2.len(), "bases2 has wrong size");
        assert_eq!(n_bits_half, bases3.len(), "bases3 has wrong size");

        let mut p_var_ext = self.select_constant_points(
            &bases1[0],
            &bases2[0],
            &bases3[0],
            b_scalar_var[0],
            b_scalar_var[1],
        );
        for i in 1..n_bits_half {
            let tmp_var_ext = self.select_constant_points(
                &bases1[i],
                &bases2[i],
                &bases3[i],
                b_scalar_var[2 * i],
                b_scalar_var[2 * i + 1],
            );
            p_var_ext = self.ecc_add(&p_var_ext.0, &tmp_var_ext.0, &p_var_ext.1, &tmp_var_ext.1);
        }
        p_var_ext.0
    }
}

#[cfg(test)]
mod test {
    use crate::plonk::constraint_system::TurboCS;
    use noah_algebra::{
        baby_jubjub::BabyJubjubPoint, jubjub::JubjubPoint, prelude::*, traits::TECurve,
    };

    #[test]
    fn test_ecc_add() {
        ecc_add::<JubjubPoint>();
        ecc_add::<BabyJubjubPoint>();
    }

    fn ecc_add<T: TECurve>() {
        let mut cs = TurboCS::new();
        let p1_ext = T::get_base();
        let p2_ext = p1_ext.double();
        let p3_ext = p1_ext.add(&p2_ext);
        let p1_var = cs.new_point_variable(p1_ext);
        let p2_var = cs.new_point_variable(p2_ext);
        let p3_var = cs.new_point_variable(p3_ext);
        // check that addition works for two identical points.
        cs.insert_ecc_add_gate::<T>(&p1_var, &p1_var, &p2_var);
        cs.insert_ecc_add_gate::<T>(&p1_var, &p2_var, &p3_var);
        let witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness[..], &[]).unwrap();

        let p3_double_ext = p3_ext.double();
        assert!(cs
            .verify_witness(
                &[
                    p1_ext.get_x(),
                    p1_ext.get_y(),
                    p2_ext.get_x(),
                    p2_ext.get_y(),
                    p3_double_ext.get_x(),
                    p3_double_ext.get_y()
                ],
                &[]
            )
            .is_err())
    }

    #[test]
    fn test_scalar_mul() {
        scalar_mul::<JubjubPoint>();
        scalar_mul::<BabyJubjubPoint>();
    }

    fn scalar_mul<T: TECurve>() {
        let mut cs = TurboCS::new();

        // compute secret scalar
        let scalar_bytes = [
            17, 144, 47, 113, 34, 14, 11, 207, 13, 116, 200, 201, 17, 33, 101, 116, 0, 59, 51, 1,
            2, 39, 13, 56, 69, 175, 41, 111, 134, 180, 0, 0,
        ];
        let scalar = T::BaseType::from_bytes(&scalar_bytes).unwrap();
        let jubjub_scalar = T::ScalarType::from_bytes(&scalar_bytes).unwrap(); // safe unwrap
        let base_ext = T::get_base();
        let p_out_ext = base_ext.mul(&jubjub_scalar);
        let p_out_plus_ext = p_out_ext.add(&base_ext);

        // build circuit
        let scalar_var = cs.new_variable(scalar);
        let p_out_var = cs.const_base_scalar_mul(base_ext, scalar_var, 256);
        let mut witness = cs.get_and_clear_witness();
        cs.verify_witness(&witness[..], &[]).unwrap();

        // wrong witness: point = GENERATOR * (jubjub_scalar + 1)
        witness[p_out_var.0] = p_out_plus_ext.get_x();
        witness[p_out_var.1] = p_out_plus_ext.get_y();
        assert!(cs.verify_witness(&witness[..], &[]).is_err());
    }

    #[test]
    fn test_scalar_mul_with_zero_scalar() {
        scalar_mul_with_zero_scalar::<JubjubPoint>();
        scalar_mul_with_zero_scalar::<BabyJubjubPoint>();
    }

    fn scalar_mul_with_zero_scalar<T: TECurve>() {
        let mut cs = TurboCS::new();
        let base_ext = T::get_base();
        let scalar_var = cs.new_variable(T::BaseType::zero());
        let p_out_var = cs.const_base_scalar_mul(base_ext, scalar_var, 64);
        let mut witness = cs.get_and_clear_witness();

        // check p_out is an identity point
        assert_eq!(witness[p_out_var.0], T::BaseType::zero());
        assert_eq!(witness[p_out_var.1], T::BaseType::one());
        cs.verify_witness(&witness[..], &[]).unwrap();

        // wrong witness: p_out = GENERATOR
        witness[p_out_var.0] = base_ext.get_x();
        witness[p_out_var.1] = base_ext.get_y();
        assert!(cs.verify_witness(&witness[..], &[]).is_err());
    }
}
