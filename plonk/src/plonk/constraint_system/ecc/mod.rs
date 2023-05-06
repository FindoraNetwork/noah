/// Module for ECC where the base is a constant to the circuit.
pub mod const_base_ecc;

/// Module for ECC where the base is not a constant.
pub mod nonconst_base_ecc;

use crate::plonk::constraint_system::{TurboCS, VarIndex};
use noah_algebra::bls12_381::BLSScalar;
use noah_algebra::jubjub::JubjubPoint;
use noah_algebra::prelude::*;

/// The witness indices for x/y-coordinates of a point
pub struct PointVar(VarIndex, VarIndex);

/// PointVar plus the corresponding Jubjub point
pub struct ExtendedPointVar(PointVar, JubjubPoint);

impl ExtendedPointVar {
    /// Return the point variable.
    pub fn get_var(&self) -> &PointVar {
        &self.0
    }

    /// Return the point value.
    pub fn get_point(&self) -> &JubjubPoint {
        &self.1
    }

    /// Return the point variable
    pub fn into_point_var(self) -> PointVar {
        self.0
    }
}

impl PointVar {
    /// Crate a point variable.
    pub fn new(x_var: VarIndex, y_var: VarIndex) -> PointVar {
        PointVar(x_var, y_var)
    }

    /// Return x-coordinate of the point variable.
    pub fn get_x(&self) -> VarIndex {
        self.0
    }

    /// Return y-coordinate of the point variable.
    pub fn get_y(&self) -> VarIndex {
        self.1
    }
}

/// `d = -(10240/10241)` in little-endian byte order
const EDWARDS_D: [u8; 32] = [
    0xb1, 0x3e, 0x34, 0xd6, 0xd6, 0x5f, 0x06, 0x01, 0x26, 0x9d, 0x57, 0x37, 0x6d, 0x7f, 0x2d, 0x29,
    0xd4, 0x7f, 0xbd, 0xe6, 0x07, 0x92, 0xfd, 0xf5, 0x48, 0x2b, 0xfa, 0x4b, 0xe7, 0x18, 0x93, 0x2a,
];

impl TurboCS<BLSScalar> {
    /// Create variables for a point.
    pub fn new_point_variable(&mut self, point: JubjubPoint) -> PointVar {
        let x = self.new_variable(point.get_x());
        let y = self.new_variable(point.get_y());
        PointVar(x, y)
    }

    /// Insert constraint for a public IO point to be decided online.
    pub fn prepare_pi_point_variable(&mut self, point_var: PointVar) {
        self.prepare_pi_variable(point_var.0);
        self.prepare_pi_variable(point_var.1);
    }

    /// Insert a curve addition gate: (x1, y1) + (x2, y2) = (x3, y3)
    ///
    /// x-coordinate constraint:
    /// x3 = x1 * y2 + y1 * x2 - d * x1 * y1 * x2 * y2 * x3
    /// wirings: w1 = x1, w2 = y2, w3 = x2, w4 = y1, w_out = x3
    /// selectors: qm1 = 1, qm2 = 1, q_ecc = -d, qo = 1
    ///
    /// y-coordinate constraint:
    /// y3 = x1 * x2 + y1 * y2 + d * x1 * y1 * x2 * y2 * y3
    /// wirings: w1 = x1, w2 = x2, w3 = y1, w4 = y2, w_out = y3
    /// selectors: qm1 = 1, qm2 = 1, q_ecc = d, qo = 1
    fn insert_ecc_add_gate(&mut self, p1_var: &PointVar, p2_var: &PointVar, p_out_var: &PointVar) {
        assert!(p1_var.0 < self.num_vars, "p1.x variable index out of bound");
        assert!(p1_var.1 < self.num_vars, "p1.y variable index out of bound");
        assert!(p2_var.0 < self.num_vars, "p2.x variable index out of bound");
        assert!(p2_var.1 < self.num_vars, "p2.y variable index out of bound");
        assert!(
            p_out_var.0 < self.num_vars,
            "p_out.x variable index out of bound"
        );
        assert!(
            p_out_var.1 < self.num_vars,
            "p_out.y variable index out of bound"
        );

        let edwards_d = BLSScalar::from_bytes(&EDWARDS_D[..]).unwrap();
        // x-coordinate constraint
        let zero = BLSScalar::zero();
        let one = BLSScalar::one();
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(one, one);
        self.push_constant_selector(zero);
        self.push_ecc_selector(edwards_d.neg());
        self.push_out_selector(one);

        self.wiring[0].push(p1_var.0);
        self.wiring[1].push(p2_var.1);
        self.wiring[2].push(p2_var.0);
        self.wiring[3].push(p1_var.1);
        self.wiring[4].push(p_out_var.0);
        self.size += 1;

        // y-coordinate constraint
        self.push_add_selectors(zero, zero, zero, zero);
        self.push_mul_selectors(one, one);
        self.push_constant_selector(zero);
        self.push_ecc_selector(edwards_d);
        self.push_out_selector(one);

        self.wiring[0].push(p1_var.0);
        self.wiring[1].push(p2_var.0);
        self.wiring[2].push(p1_var.1);
        self.wiring[3].push(p2_var.1);
        self.wiring[4].push(p_out_var.1);
        self.finish_new_gate();
    }

    /// Given two elliptic curve point variables `[P1]` and `[P2]`, returns `[P1] + [P2]`
    pub fn ecc_add(
        &mut self,
        p1_var: &PointVar,
        p2_var: &PointVar,
        p1_ext: &JubjubPoint,
        p2_ext: &JubjubPoint,
    ) -> ExtendedPointVar {
        assert!(p1_var.0 < self.num_vars, "p1.x variable index out of bound");
        assert!(p1_var.1 < self.num_vars, "p1.y variable index out of bound");
        assert!(p2_var.0 < self.num_vars, "p2.x variable index out of bound");
        assert!(p2_var.1 < self.num_vars, "p2.y variable index out of bound");
        let p_out_ext = p1_ext.add(&p2_ext);
        let p_out_var = self.new_point_variable(p_out_ext);
        self.insert_ecc_add_gate(p1_var, p2_var, &p_out_var);
        ExtendedPointVar(p_out_var, p_out_ext)
    }
}
