//! Module for the PLUME protocol.

use crate::errors::Result;
use noah_algebra::prelude::*;

/// The module for the PLUME implementation over ed25519.
pub mod ed25519;

/// The module for the PLUME implementation over secp256k1.
pub mod secp256k1;

/// The committed input for the PLUME protocol, which would be bridged between the Plonk proof.
#[derive(Clone, Default)]
pub struct PlumeCommittedInput<G: CurveGroup> {
    /// The public key of the signature.
    pub pk: G,
    /// The signature.
    pub sigma: G,
    /// The hash of the message.
    pub msg_hash: G::BaseType,
    /// The hash commitment blinding factors.
    pub h_blinding_factors: Vec<G::ScalarType>,
}

/// A PLUME proof.
#[derive(Clone, Default)]
pub struct PlumeProof<G: CurveGroup> {
    /// The Bulletproof.
    pub proof_star: Vec<u8>,
    /// The hash commitments.
    pub h: Vec<G>,
    /// The randomized signature, divided by the cofactor if there is any.
    pub sigma_star_div_by_cofactor: G,
    /// The R1 point, divided by the cofactor if there is any.
    pub point_r_1_div_by_cofactor: G,
    /// The R2 point, divided by the cofactor if there is any.
    pub point_r_2_div_by_cofactor: G,
    /// The response to the challenge.
    pub s: G::ScalarType,
}

/// The struct of the input to the delegation (precomputation) algorithm.
#[derive(Clone, Default)]
pub struct PlumeDelegationInput<G: CurveGroup> {
    /// The randomized signature.
    pub sigma_star: G,
    /// The R1 point.
    pub point_r1: G,
    /// The R2 point.
    pub point_r2: G,
    /// The response to the challenge.
    pub s: G::ScalarType,
    /// The challenge.
    pub beta: G::ScalarType,
}

/// The struct of the delegation (precomputation) result for PLUME.
#[derive(Clone, Default)]
pub struct PlumeDelegationResult<G: CurveGroup> {
    /// The precomputed first left-hand-side result.
    pub lhs_1: G,
    /// The precomputed second left-hand-side result.
    pub lhs_2: G,
    /// The precomputed powers of point s^{-1} H.
    pub s_inv_point_h: Vec<G>,
    /// The precomputed powers of point H.
    pub point_h: Vec<G>,
    /// The precomputed powers of point beta H.
    pub beta_point_h: Vec<G>,
}

/// The trait for a Plume implementation.
pub trait Plume<G: CurveGroup> {
    /// Return the point G, the generator for the public key of the signature scheme.
    fn get_generator_g() -> G;
    /// Return the point H, the generator specifically for the randomizer used in the PLUME protocol.
    fn get_generator_h() -> G;

    /// Compute the delegated verification.
    fn do_delegation(input: &PlumeDelegationInput<G>) -> Result<PlumeDelegationResult<G>> {
        let beta_point_r1 = input.point_r1.mul(&input.beta);
        let sigma_star_plus_beta_point_r1 = beta_point_r1 + &input.sigma_star;

        let s_inv = input.s.inv()?;
        let lhs_1 = sigma_star_plus_beta_point_r1.mul(&s_inv);

        let beta_point_r2 = input.point_r2.mul(&input.beta);
        let s_point_g = Self::get_generator_g().mul(&input.s);
        let lhs_2 = beta_point_r2 - &s_point_g;

        let point_h_base = Self::get_generator_h();

        let s_inv_point_h_base = point_h_base.mul(&s_inv);
        let beta_point_h_base = point_h_base.mul(&input.beta);

        let mut s_inv_point_h = Vec::new();
        let mut point_h = Vec::new();
        let mut beta_point_h = Vec::new();

        let num_scalar_bits = G::ScalarType::get_field_size_biguint().bits();

        let mut cur = s_inv_point_h_base;
        s_inv_point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = cur.double();
            s_inv_point_h.push(cur);
        }

        let mut cur = point_h_base;
        point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = cur.double();
            point_h.push(cur);
        }

        let mut cur = beta_point_h_base;
        beta_point_h.push(cur);
        for _ in 1..num_scalar_bits {
            cur = cur.double();
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
