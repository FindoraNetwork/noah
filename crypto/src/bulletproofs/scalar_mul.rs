//! Module for the Bulletproof scalar mul proof scheme

use crate::basic::pedersen_comm::PedersenCommitmentSecq256k1;
use ark_bulletproofs_secq256k1::BulletproofGens;
use ark_bulletproofs_secq256k1::{
    curve::secp256k1::{Fq, FrParameters, G1Affine},
    curve::secq256k1::G1Affine as G1AffineBig,
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
use digest::Digest;
use merlin::Transcript;
use noah_algebra::secq256k1::SECQ256K1Scalar;
use noah_algebra::{
    prelude::*,
    secp256k1::{SECP256K1Scalar, SECP256K1G1},
    secq256k1::SECQ256K1G1,
};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha3::Sha3_512;

/// A scalar variable.
pub struct ScalarVar(Variable);

/// A point variable.
pub struct PointVar {
    x_var: Variable,
    y_var: Variable,
}

impl PointVar {
    /// Create a new point variable from field variables.
    pub fn new(x_var: Variable, y_var: Variable) -> Self {
        Self { x_var, y_var }
    }

    /// Allocate a point in Bulletproofs.
    pub fn allocate<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        x: &Option<Fq>,
        y: &Option<Fq>,
    ) -> Result<Self> {
        let x_var = cs.allocate((*x).clone()).c(d!(NoahError::R1CSProofError))?;
        let y_var = cs.allocate((*y).clone()).c(d!(NoahError::R1CSProofError))?;

        Ok(Self { x_var, y_var })
    }
}

/// A proof of scalar multiplication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalarMulProof(#[serde(with = "noah_obj_serde")] pub(crate) R1CSProof);

impl PartialEq for ScalarMulProof {
    fn eq(&self, other: &ScalarMulProof) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for ScalarMulProof {}

impl ScalarMulProof {
    fn gadget<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        public_key_var: &PointVar,
        secret_key_var: &ScalarVar,
        public_key: &Option<G1Affine>,
        secret_key: &Option<Fq>,
    ) -> Result<()> {
        assert_eq!(public_key.is_some(), secret_key.is_some());

        // 1. Initialize the point.
        let dummy_point = {
            let mut hash = Sha3_512::new();
            Digest::update(&mut hash, b"ScalarMul Initial Group Element");
            let h = hash.finalize();

            let mut res = [0u8; 32];
            res.copy_from_slice(&h[..32]);

            let mut prng = ChaChaRng::from_seed(res);
            G1Affine::rand(&mut prng)
        };

        let mut cur = if public_key.is_some() {
            Some(dummy_point.clone())
        } else {
            None
        };

        let mut cur_var = if public_key.is_some() {
            PointVar::allocate(
                cs,
                &Some(dummy_point.x.clone()),
                &Some(dummy_point.y.clone()),
            )?
        } else {
            PointVar::allocate(cs, &None, &None)?
        };

        cs.constrain(cur_var.x_var - dummy_point.x.clone());
        cs.constrain(cur_var.y_var - dummy_point.y.clone());

        // 2. Compute the bit decomposition of `secret_key`.
        let (bits, bits_var) = if let Some(secret_key) = secret_key {
            let mut bits = secret_key.into_repr().to_bits_le();
            let mut bits_var = Vec::new();

            bits.truncate(FrParameters::MODULUS_BITS as usize);

            for bit in bits.iter() {
                let (bit_var, one_minus_bit_var, product) = cs
                    .allocate_multiplier(Some((Fq::from(*bit), Fq::from(1 - (*bit as u8)))))
                    .c(d!(NoahError::R1CSProofError))?;
                cs.constrain(product.into());
                cs.constrain(bit_var + one_minus_bit_var - Fq::one());

                bits_var.push(bit_var);
            }

            let wrapped_bits = bits.iter().map(|f| Some(*f)).collect::<Vec<Option<bool>>>();
            (wrapped_bits, bits_var)
        } else {
            let mut wrapped_bits = Vec::new();
            let mut bits_var = Vec::new();

            for _ in 0..FrParameters::MODULUS_BITS {
                let (bit_var, one_minus_bit_var, product) = cs
                    .allocate_multiplier(None)
                    .c(d!(NoahError::R1CSProofError))?;
                cs.constrain(product.into());
                cs.constrain(bit_var + one_minus_bit_var - Fq::one());

                wrapped_bits.push(None);
                bits_var.push(bit_var);
            }

            (wrapped_bits, bits_var)
        };

        let mut lc = Vec::new();
        let mut multiplier = Fq::one();
        for bit_var in bits_var.iter() {
            lc.push((*bit_var, multiplier.clone()));
            multiplier.double_in_place();
        }

        let sum = LinearCombination::from_iter(lc.iter());
        cs.constrain(sum - secret_key_var.0);

        // 4. Generate the points.
        let points = {
            let mut v = Vec::new();
            let mut cur = SECP256K1G1::get_base().get_raw().into_projective();
            for _ in 0..FrParameters::MODULUS_BITS {
                v.push(cur.into_affine());
                ProjectiveCurve::double_in_place(&mut cur);
            }
            v
        };

        // 5. Add the points.
        for ((bit, bit_var), point) in bits.iter().zip(bits_var.iter()).zip(points.iter()) {
            let (next, next_var) = Self::point_add_constant(cs, &cur_var, &cur, &point)?;
            let (new_cur, new_cur_var) =
                Self::point_select(cs, bit_var, bit, &next_var, &next, &cur_var, &cur)?;

            cur = new_cur;
            cur_var = new_cur_var;
        }

        // 6. Check if the points are equal.
        let (_, rhs_var) = Self::point_add_constant(cs, public_key_var, public_key, &dummy_point)?;
        cs.constrain(cur_var.x_var - rhs_var.x_var);
        cs.constrain(cur_var.y_var - rhs_var.y_var);

        Ok(())
    }

    fn point_add_constant<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        left_var: &PointVar,
        left: &Option<G1Affine>,
        right: &G1Affine,
    ) -> Result<(Option<G1Affine>, PointVar)> {
        let (s_var, res_var, res) = if let Some(left) = left {
            let s = (left.y - &right.y) * (left.x - &right.x).inverse().unwrap();
            let s_var = cs.allocate(Some(s)).c(d!(NoahError::R1CSProofError))?;

            let new_x = s * &s - &left.x - &right.x;
            let new_y = s * (left.x - &new_x) - &left.y;

            let res_var = PointVar::allocate(cs, &Some(new_x), &Some(new_y))?;
            let res = left.add(right.clone());

            (s_var, res_var, Some(res))
        } else {
            let s_var = cs.allocate(None).c(d!(NoahError::R1CSProofError))?;
            let res_var = PointVar::allocate(cs, &None, &None).c(d!(NoahError::R1CSProofError))?;

            (s_var, res_var, None)
        };

        let (_, _, s_squared_var) = cs.multiply(s_var.into(), s_var.into());
        let (_, _, s_delta_x_var) = cs.multiply(s_var.into(), right.x - res_var.x_var);

        cs.constrain(s_squared_var - left_var.x_var - right.x - res_var.x_var);
        cs.constrain(s_delta_x_var - right.y - res_var.y_var);

        Ok((res, res_var))
    }

    fn point_select<CS: RandomizableConstraintSystem>(
        cs: &mut CS,
        bit_var: &Variable,
        bit: &Option<bool>,
        yes_var: &PointVar,
        yes: &Option<G1Affine>,
        no_var: &PointVar,
        no: &Option<G1Affine>,
    ) -> Result<(Option<G1Affine>, PointVar)> {
        let (res, res_var) = if let Some(bit) = bit {
            let res = if *bit { yes.unwrap() } else { no.unwrap() };
            let res_var = PointVar::allocate(cs, &Some(res.x), &Some(res.y))?;

            (Some(res), res_var)
        } else {
            let res_var = PointVar::allocate(cs, &None, &None)?;

            (None, res_var)
        };

        let (_, _, x_delta) = cs.multiply(bit_var.clone().into(), yes_var.x_var - no_var.x_var);
        let (_, _, y_delta) = cs.multiply(bit_var.clone().into(), yes_var.y_var - no_var.y_var);

        cs.constrain(res_var.x_var - no_var.x_var - x_delta);
        cs.constrain(res_var.y_var - no_var.y_var - y_delta);

        Ok((res, res_var))
    }
}

impl ScalarMulProof {
    /// Attempt to construct a proof that `output` is a permutation of `input`.
    ///
    /// Returns a tuple `(proof, x_comm || y_comm || scalar_fq_comm )`.
    pub fn prove<'a, 'b, R: CryptoRng + RngCore>(
        prng: &mut R,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        public_key: &SECP256K1G1,
        secret_key: &SECP256K1Scalar,
    ) -> Result<(ScalarMulProof, Vec<SECQ256K1G1>, Vec<SECQ256K1Scalar>)> {
        let pc_gens = PedersenCommitmentSecq256k1::default();

        let public_key = public_key.get_raw();
        let secret_key = secret_key.get_raw();

        let base = SECP256K1G1::get_base();

        // 1. Sanity-check if the statement is valid.
        assert_eq!(base.get_raw().mul(secret_key.into_repr()), public_key,);

        // 2. Apply a domain separator to the transcript.
        transcript.append_message(b"dom-sep", b"ScalarMulProof");

        // 3. Initialize the prover.
        let pc_gens_for_prover = ark_bulletproofs_secq256k1::PedersenGens::from(&pc_gens);
        let mut prover = Prover::new(&pc_gens_for_prover, transcript);

        // 4. Allocate `public_key`.
        let x_blinding = Fq::rand(prng);
        let y_blinding = Fq::rand(prng);
        let (x_comm, x_var) = prover.commit(public_key.x, x_blinding.clone());
        let (y_comm, y_var) = prover.commit(public_key.y, y_blinding.clone());

        let public_key_var = PointVar::new(x_var, y_var);

        // 5. Allocate `secret_key`.
        // We can do this because Fq is larger than Fr.
        let secret_key_fq = Fq::from_le_bytes_mod_order(&secret_key.into_repr().to_bytes_le());

        let secret_key_blinding = Fq::rand(prng);
        let (secret_key_comm, secret_key_var) =
            prover.commit(secret_key_fq, secret_key_blinding.clone());

        let secret_key_var = ScalarVar(secret_key_var);

        ScalarMulProof::gadget(
            &mut prover,
            &public_key_var,
            &secret_key_var,
            &Some(public_key.clone()),
            &Some(secret_key_fq.clone()),
        )?;

        let proof = prover
            .prove(prng, &bp_gens)
            .c(d!(NoahError::R1CSProofError))?;

        Ok((
            ScalarMulProof(proof),
            vec![
                SECQ256K1G1::from_raw(x_comm.clone()),
                SECQ256K1G1::from_raw(y_comm.clone()),
                SECQ256K1G1::from_raw(secret_key_comm.clone()),
            ],
            vec![
                SECQ256K1Scalar::from_raw(x_blinding),
                SECQ256K1Scalar::from_raw(y_blinding),
                SECQ256K1Scalar::from_raw(secret_key_blinding),
            ],
        ))
    }
}

impl ScalarMulProof {
    /// Attempt to verify a `ScalarMulProof`.
    pub fn verify<'a, 'b>(
        &self,
        bp_gens: &'b BulletproofGens,
        transcript: &'a mut Transcript,
        commitments: &Vec<SECQ256K1G1>,
    ) -> Result<()> {
        let pc_gens = PedersenCommitmentSecq256k1::default();
        let commitments = commitments
            .iter()
            .map(|x| x.get_raw())
            .collect::<Vec<G1AffineBig>>();

        // Apply a domain separator to the transcript.
        transcript.append_message(b"dom-sep", b"ScalarMulProof");

        let mut verifier = Verifier::new(transcript);

        let x_var = verifier.commit(commitments[0].clone());
        let y_var = verifier.commit(commitments[1].clone());
        let s_var = verifier.commit(commitments[2].clone());

        let public_key_var = PointVar::new(x_var, y_var);
        let secret_key_var = ScalarVar(s_var);

        ScalarMulProof::gadget(
            &mut verifier,
            &public_key_var,
            &secret_key_var,
            &None,
            &None,
        )
        .c(d!(NoahError::R1CSProofError))?;

        let pc_gens_for_verifier = ark_bulletproofs_secq256k1::PedersenGens::from(&pc_gens);
        verifier
            .verify(&self.0, &pc_gens_for_verifier, &bp_gens)
            .c(d!(NoahError::R1CSProofError))?;
        Ok(())
    }
}

#[test]
fn scalar_mul_test() {
    use ark_bulletproofs_secq256k1::curve::secp256k1::Fr;

    let bp_gens = BulletproofGens::new(2048, 1);

    let mut rng = rand::thread_rng();

    let secert_key = Fr::rand(&mut rng);
    let public_key = G1Affine::prime_subgroup_generator()
        .mul(secert_key.into_repr())
        .into_affine();

    let (proof, commitments, _) = {
        let mut prover_transcript = Transcript::new(b"ScalarMulProofTest");
        ScalarMulProof::prove(
            &mut rng,
            &bp_gens,
            &mut prover_transcript,
            &SECP256K1G1::from_raw(public_key),
            &SECP256K1Scalar::from_raw(secert_key),
        )
        .unwrap()
    };

    {
        let mut verifier_transcript = Transcript::new(b"ScalarMulProofTest");
        assert!(proof
            .verify(&bp_gens, &mut verifier_transcript, &commitments,)
            .is_ok());
    }
}
