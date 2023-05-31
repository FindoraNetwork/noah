use noah_algebra::prelude::*;
use crate::errors::Result;

pub mod ed25519;
pub mod secp256k1;

#[derive(Clone, Default)]
pub struct PlumeWitness<G: CurveGroup> {
    pub pk: G,
    pub sigma: G,
    pub msg_hash: G::BaseType,
    pub h_randomizer: G::BaseType,
}

#[derive(Clone, Default)]
pub struct PlumeProof<G: CurveGroup> {
    pub proof_star: Vec<u8>,
    pub h: G::BaseType,
    pub sigma_star_div_by_cofactor: G,
    pub point_r_1_div_by_cofactor: G,
    pub point_r_2_div_by_cofactor: G,
    pub s: G::ScalarType,
}

#[derive(Clone, Default)]
pub struct PlumeDelegationInput<G: CurveGroup> {
    pub sigma_star: G,
    pub point_r1: G,
    pub point_r2: G,
    pub s: G::ScalarType,
    pub beta: G::ScalarType,
}

#[derive(Clone, Default)]
pub struct PlumeDelegationResult<G: CurveGroup> {
    pub lhs_1: G,
    pub lhs_2: G,
    pub s_inv_point_h: Vec<G>,
    pub point_h: Vec<G>,
    pub beta_point_h: Vec<G>,
}

pub trait Plume<G: CurveGroup> {
    const GENERATOR_G: G;
    const GENERATOR_H: G;

    fn do_delegation(input: &PlumeDelegationInput<G>) -> Result<PlumeDelegationResult<G>> {
        let beta_point_r1 = Self::scalar_mul(&input.point_r1, &input.beta);
        let sigma_star_plus_beta_point_r1 = Self::point_add(&input.sigma_star, &beta_point_r1);

        let s_inv = input.s.inv()?;
        let lhs_1 = Self::scalar_mul(&sigma_star_plus_beta_point_r1, &s_inv);

        let beta_point_r2 = Self::scalar_mul(&input.point_r2, &input.beta);
        let s_point_g = Self::scalar_mul(&Self::GENERATOR_G, &input.s);
        let lhs_2 = Self::point_sub(&beta_point_r2, &s_point_g);

        let s_inv_point_h_base = Self::scalar_mul(&Self::GENERATOR_H, &s_inv);
        let point_h_base = Self::GENERATOR_H;
        let beta_point_h_base = Self::scalar_mul(&Self::GENERATOR_H, &input.beta);

        let mut s_inv_point_h = Vec::new();
        let mut point_h = Vec::new();
        let mut beta_point_h = Vec::new();

        let num_scalar_bits = G::ScalarType::get_field_size_biguint().bits();

        let mut cur = s_inv_point_h_base;
        s_inv_point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = Self::point_double(&cur)?;
            s_inv_point_h.push(cur);
        }

        let mut cur = point_h_base;
        point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = Self::point_double(&cur)?;
            point_h.push(cur);
        }

        let mut cur = beta_point_h_base;
        beta_point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = Self::point_double(&cur)?;
            beta_point_h.push(cur);
        }

        let res = PlumeDelegationResult::<G> {
            lhs_1,
            lhs_2,
            s_inv_point_h,
            point_h,
            beta_point_h,
        };
        Ok(res)
    }
}
