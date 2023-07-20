use crate::errors::Result;
use ark_bulletproofs::curve::zorro::G1Affine as G1AffineBig;
use ark_bulletproofs::r1cs::{
    LinearCombination, Prover, RandomizableConstraintSystem, Variable, Verifier,
};
use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_ec::{AffineRepr, CurveGroup, Group as ArkGroup};
use ark_ed25519::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use digest::Digest;
use merlin::Transcript;
use noah_algebra::ed25519::{Ed25519Point, Ed25519Scalar, ED25519_D};
use noah_algebra::prelude::*;
use noah_algebra::zorro::{PedersenCommitmentZorro, ZorroG1, ZorroProof, ZorroScalar};
use rand_chacha::ChaChaRng;
use sha3::Sha3_512;

/// A scalar variable.
struct ScalarVar(Variable<Fq>);

/// A point variable.
struct PointVar {
    x_var: Variable<Fq>,
    y_var: Variable<Fq>,
}

impl PointVar {
    /// Create a new point variable from field variables.
    pub(crate) fn new(x_var: Variable<Fq>, y_var: Variable<Fq>) -> Self {
        Self { x_var, y_var }
    }

    /// Allocate a point in Bulletproofs.
    pub(crate) fn allocate<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        x: &Option<Fq>,
        y: &Option<Fq>,
    ) -> Result<Self> {
        let x_var = cs.allocate((*x))?;
        let y_var = cs.allocate((*y))?;

        Ok(Self { x_var, y_var })
    }
}

/// A proof of scalar multiplication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScalarMulProof(#[serde(with = "noah_obj_serde")] pub(crate) ZorroProof);

impl PartialEq for ScalarMulProof {
    fn eq(&self, other: &ScalarMulProof) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for ScalarMulProof {}

impl ScalarMulProof {
    fn gadget<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        public_key_var: &PointVar,
        secret_key_var: &ScalarVar,
        public_key: &Option<EdwardsAffine>,
        secret_key: &Option<Fr>,
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
            EdwardsAffine::rand(&mut prng)
        };

        let mut cur = if public_key.is_some() {
            Some(dummy_point)
        } else {
            None
        };

        let mut cur_var = if public_key.is_some() {
            PointVar::allocate(
                cs,
                &Some(dummy_point.x),
                &Some(dummy_point.y),
            )?
        } else {
            PointVar::allocate(cs, &None, &None)?
        };

        cs.constrain(cur_var.x_var - dummy_point.x);
        cs.constrain(cur_var.y_var - dummy_point.y);

        // 2. Compute the bit decomposition of `secret_key`.
        let (bits, bits_var) = if let Some(secret_key) = secret_key {
            let mut bits = secret_key.into_bigint().to_bits_le();
            let mut bits_var = Vec::new();

            bits.truncate(Fr::MODULUS_BIT_SIZE as usize);

            for bit in bits.iter() {
                let (bit_var, one_minus_bit_var, product) =
                    cs.allocate_multiplier(Some((Fq::from(*bit), Fq::from(1 - (*bit as u8)))))?;
                cs.constrain(product.into());
                cs.constrain(bit_var + one_minus_bit_var - Fq::one());

                bits_var.push(bit_var);
            }

            let wrapped_bits = bits.iter().map(|f| Some(*f)).collect::<Vec<Option<bool>>>();
            (wrapped_bits, bits_var)
        } else {
            let mut wrapped_bits = Vec::new();
            let mut bits_var = Vec::new();

            for _ in 0..Fr::MODULUS_BIT_SIZE {
                let (bit_var, one_minus_bit_var, product) = cs.allocate_multiplier(None)?;
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
            lc.push((*bit_var, multiplier));
            multiplier.double_in_place();
        }

        let sum = LinearCombination::from_iter(lc.iter());
        cs.constrain(sum - secret_key_var.0);

        // 4. Generate the points.
        let points = {
            let mut v = Vec::new();
            let mut cur = Ed25519Point::get_base().get_raw().into_group();
            for _ in 0..Fr::MODULUS_BIT_SIZE {
                v.push(cur.into_affine());
                EdwardsProjective::double_in_place(&mut cur);
            }
            v
        };

        // 5. Add the points.
        for ((bit, bit_var), point) in bits.iter().zip(bits_var.iter()).zip(points.iter()) {
            let (next, next_var) = Self::point_add_constant(cs, &cur_var, &cur, point)?;
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

    fn point_add_constant<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        left_var: &PointVar,
        left: &Option<EdwardsAffine>,
        right: &EdwardsAffine,
    ) -> Result<(Option<EdwardsAffine>, PointVar)> {
        let (res_var, res) = if let Some(left) = left {
            let res = left.add(right).into_affine();
            let res_var = PointVar::allocate(cs, &Some(res.x), &Some(res.y))?;
            (res_var, Some(res))
        } else {
            let res_var = PointVar::allocate(cs, &None, &None)?;
            (res_var, None)
        };

        let (_, _, left_xy_var) = cs.multiply(left_var.x_var.into(), left_var.y_var.into());
        let (_, _, left_xy_res_x_var) = cs.multiply(left_xy_var.into(), res_var.x_var.into());
        let (_, _, left_xy_res_y_var) = cs.multiply(left_xy_var.into(), res_var.y_var.into());

        let d = ED25519_D;

        cs.constrain(
            res_var.x_var - left_var.x_var * right.y - left_var.y_var * right.x
                + left_xy_res_x_var * d * right.x * right.y,
        );
        cs.constrain(
            res_var.y_var
                - left_var.x_var * right.x
                - left_var.y_var * right.y
                - left_xy_res_y_var * d * right.x * right.y,
        );

        Ok((res, res_var))
    }

    fn point_select<CS: RandomizableConstraintSystem<Fq>>(
        cs: &mut CS,
        bit_var: &Variable<Fq>,
        bit: &Option<bool>,
        yes_var: &PointVar,
        yes: &Option<EdwardsAffine>,
        no_var: &PointVar,
        no: &Option<EdwardsAffine>,
    ) -> Result<(Option<EdwardsAffine>, PointVar)> {
        let (res, res_var) = if let Some(bit) = bit {
            let res = if *bit { yes.unwrap() } else { no.unwrap() };
            let res_var = PointVar::allocate(cs, &Some(res.x), &Some(res.y))?;

            (Some(res), res_var)
        } else {
            let res_var = PointVar::allocate(cs, &None, &None)?;

            (None, res_var)
        };

        let (_, _, x_delta) = cs.multiply((*bit_var).into(), yes_var.x_var - no_var.x_var);
        let (_, _, y_delta) = cs.multiply((*bit_var).into(), yes_var.y_var - no_var.y_var);

        cs.constrain(res_var.x_var - no_var.x_var - x_delta);
        cs.constrain(res_var.y_var - no_var.y_var - y_delta);

        Ok((res, res_var))
    }
}

impl ScalarMulProof {
    /// Attempt to construct a proof that `output` is a permutation of `input`.
    ///
    /// Returns a tuple `(proof, x_comm || y_comm || scalar_fq_comm )`.
    pub fn prove<R: CryptoRng + RngCore>(
        prng: &mut R,
        bp_gens: &BulletproofGens<G1AffineBig>,
        transcript: &mut Transcript,
        public_key: &Ed25519Point,
        secret_key: &Ed25519Scalar,
    ) -> Result<(ScalarMulProof, Vec<ZorroG1>, Vec<ZorroScalar>)> {
        let pc_gens = PedersenCommitmentZorro::default();

        let public_key = public_key.get_raw();
        let secret_key = secret_key.get_raw();
        let base = Ed25519Point::get_base();

        // 1. Sanity-check if the statement is valid.
        assert_eq!(
            base.get_raw().mul_bigint(&secret_key.into_bigint()),
            public_key
        );

        // 2. Apply a domain separator to the transcript.
        transcript.append_message(b"dom-sep", b"ScalarMulProof");

        // 3. Initialize the prover.
        let pc_gens_for_prover = PedersenGens::<G1AffineBig>::from(&pc_gens);
        let mut prover = Prover::new(&pc_gens_for_prover, transcript);

        // 4. Allocate `public_key`.
        let x_blinding = Fq::rand(prng);
        let y_blinding = Fq::rand(prng);
        let (x_comm, x_var) = prover.commit(public_key.x, x_blinding);
        let (y_comm, y_var) = prover.commit(public_key.y, y_blinding);

        let public_key_var = PointVar::new(x_var, y_var);

        // 5. Allocate `secret_key`.
        // We can do this because Fq is larger than Fr.
        let secret_key_fq = Fq::from_le_bytes_mod_order(&secret_key.into_bigint().to_bytes_le());

        let secret_key_blinding = Fq::rand(prng);
        let (secret_key_comm, secret_key_var) = prover.commit(secret_key_fq, secret_key_blinding);

        let secret_key_var = ScalarVar(secret_key_var);

        ScalarMulProof::gadget(
            &mut prover,
            &public_key_var,
            &secret_key_var,
            &Some(public_key),
            &Some(secret_key),
        )?;

        let proof = prover.prove(prng, bp_gens)?;

        Ok((
            ScalarMulProof(proof),
            vec![
                ZorroG1::from_raw(x_comm),
                ZorroG1::from_raw(y_comm),
                ZorroG1::from_raw(secret_key_comm),
            ],
            vec![
                ZorroScalar::from_raw(x_blinding),
                ZorroScalar::from_raw(y_blinding),
                ZorroScalar::from_raw(secret_key_blinding),
            ],
        ))
    }
}

impl ScalarMulProof {
    /// Attempt to verify a `ScalarMulProof`.
    pub fn verify(
        &self,
        bp_gens: &BulletproofGens<G1AffineBig>,
        transcript: &mut Transcript,
        commitments: &Vec<ZorroG1>,
    ) -> Result<()> {
        let pc_gens = PedersenCommitmentZorro::default();
        let commitments = commitments
            .iter()
            .map(|x| x.get_raw())
            .collect::<Vec<G1AffineBig>>();

        // Apply a domain separator to the transcript.
        transcript.append_message(b"dom-sep", b"ScalarMulProof");

        let mut verifier = Verifier::new(transcript);

        let x_var = verifier.commit(commitments[0]);
        let y_var = verifier.commit(commitments[1]);
        let s_var = verifier.commit(commitments[2]);

        let public_key_var = PointVar::new(x_var, y_var);
        let secret_key_var = ScalarVar(s_var);

        ScalarMulProof::gadget(
            &mut verifier,
            &public_key_var,
            &secret_key_var,
            &None,
            &None,
        )?;

        let pc_gens_for_verifier = PedersenGens::<G1AffineBig>::from(&pc_gens);
        verifier.verify(&self.0, &pc_gens_for_verifier, bp_gens)?;
        Ok(())
    }
}

#[test]
fn scalar_mul_test() {
    let bp_gens = BulletproofGens::new(2048, 1);

    let mut rng = rand::thread_rng();

    let secert_key = Fr::rand(&mut rng);
    let public_key = EdwardsAffine::generator()
        .mul_bigint(secert_key.into_bigint())
        .into_affine();

    let (proof, commitments, _) = {
        let mut prover_transcript = Transcript::new(b"ScalarMulProofTest");
        ScalarMulProof::prove(
            &mut rng,
            &bp_gens,
            &mut prover_transcript,
            &Ed25519Point::from_raw(public_key),
            &Ed25519Scalar::from_raw(secert_key),
        )
        .unwrap()
    };

    {
        let mut verifier_transcript = Transcript::new(b"ScalarMulProofTest");
        proof
            .verify(&bp_gens, &mut verifier_transcript, &commitments)
            .unwrap();
    }
}
