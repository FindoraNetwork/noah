use bulletproofs::PedersenGens;
use crate::errors::Error as ZeiError;
use crate::proofs::{compute_challenge, compute_sub_challenge};
use crate::serialization;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};


/*
 * This file contains code for Chaum-Pedersen proof of equality of commitments.
 * Proof algorithm:
   a) Let C1 = pedersen(a, r1) = C2 = pedersen(a, r2), (G,H) pedersen base points
   b) Sample random scalars r3, r4 and r5
   c) Compute new commitments on C3 = pedersen(r3,r4) and C4 = (r3,r5)
   d) Compute challenge c = HASH(C1,C2,C3,C4)
   e) Compute response z1 = cm + r3, z2 = cr1 + r4, z3 = cr2 + r5
   f) Output proof = C1,C2,z1,z2,z3

 * Verify algorithm:
   a) Compute challenge c = HASH(C1,C2,C3,C4)
   b) Output true iff c3 + c*c1 = z1*G + z2*H AND c4 + c*c2 == z1*G + z3*H

 * Proof equality for multiple commitments
   a) {challenge_i = HASH(C1,...,Cn, i)}
   b) {di = challenge_i * (C1 - Ci)}
   c) {zi = challenge_i * (r1 - ri)}
   d) Ouput Chaum-Pedersen Zero-Knowledge proof that D = \sum di commits to 0
      (using blinding z = sum zi}
   (Current implementation uses equality proof above with (D,  Commit(0, 0)) commitment pair)
 */

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenCommitmentEqProof {
    /// I represent a Chaum-Perdersen equality of commitment proof
    #[serde(with = "serialization::compressed_ristretto")]
    c3: CompressedRistretto,
    #[serde(with = "serialization::compressed_ristretto")]
    c4: CompressedRistretto,
    #[serde(with = "serialization::scalar")]
    z1: Scalar,
    #[serde(with = "serialization::scalar")]
    z2: Scalar,
    #[serde(with = "serialization::scalar")]
    z3: Scalar,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Default)]
pub struct ChaumPedersenCommitmentEqProofMultiple {
    /// I represent a Chaum-Perdersen equality of commitment proof
    c1_eq_c2: ChaumPedersenCommitmentEqProof,
    zero: ChaumPedersenCommitmentEqProof,
}

pub fn chaum_pedersen_prove_eq<R: CryptoRng + Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    value: &Scalar,
    commitment1: &CompressedRistretto,
    commitment2: &CompressedRistretto,
    blinding_factor1: &Scalar,
    blinding_factor2: &Scalar) -> ChaumPedersenCommitmentEqProof
{
    /*! I compute a Chaum-Pedersen proof that two commitments are to the same value */

    let r1 = blinding_factor1;
    let r2 = blinding_factor2;
    let r3 = Scalar::random(prng);
    let r4 = Scalar::random(prng);
    let r5 = Scalar::random(prng);

    let c3 = pedersen_gens.commit(r3, r4).compress();
    let c4 = pedersen_gens.commit(r3, r5).compress();

    let c = compute_challenge(&[*commitment1, *commitment2, c3, c4]);

    let z1 = c*value + r3;
    let z2 = c*r1 + r4;
    let z3 = c*r2 + r5;

    ChaumPedersenCommitmentEqProof{
        c3,c4,z1,z2,z3
    }
}

pub fn chaum_pedersen_verify_eq(
    pc_gens: &PedersenGens,
    c1: &CompressedRistretto, c2: &CompressedRistretto,
    proof:&ChaumPedersenCommitmentEqProof) -> Result<bool, ZeiError> {

    /*! I verify a chaum-pedersen equality proof. Return Ok(true) in case of success, Ok(false)
     in case of verification failure, and Err(Error::DeserializationError) in case some CompressedRistretto can not be
     decompressed*/

    let c1_d = c1.decompress()?;
    let c2_d = c2.decompress()?;
    let c3_d = proof.c3.decompress()?;
    let c4_d = proof.c4.decompress()?;
    let z1 = proof.z1;
    let z2 = proof.z2;
    let z3 = proof.z3;
    let g = &pc_gens.B;
    let h = &pc_gens.B_blinding;


    let c = compute_challenge(&[*c1, *c2, proof.c3, proof.c4]);

    let mut vrfy_ok = c3_d + c*c1_d == z1*g + z2*h;
    vrfy_ok = vrfy_ok && c4_d + c*c2_d == z1*g + z3*h;
    Ok(vrfy_ok)

}

//Helper functions for the proof of multiple commitments equality below
fn get_fake_zero_commitment() -> CompressedRistretto {
    /*! I return a fake compressed commitment to zero, eg The identity*/
    RistrettoPoint::identity().compress()
}

fn get_fake_zero_commitment_blinding() -> Scalar {
    /*! I return the blinding used in the get_fake_zero_commitment*/
    Scalar::zero()
}

pub fn chaum_pedersen_prove_multiple_eq<R: CryptoRng +  Rng>(
    prng: &mut R,
    pedersen_gens: &PedersenGens,
    value: &Scalar,
    commitments: &[CompressedRistretto],
    blinding_factors: &[Scalar],
    ) -> Result<ChaumPedersenCommitmentEqProofMultiple, ZeiError>
{
    /*! I produce a proof that all commitments are to the same value.
     *
     */
    if commitments.len() <= 1 || commitments.len() != blinding_factors.len(){
        return Err(ZeiError::ParameterError);
    }
    let proof_c1_c2 = chaum_pedersen_prove_eq(
        prng, pedersen_gens, value, &commitments[0], &commitments[1],
        &blinding_factors[0], &blinding_factors[1]);

    let k = compute_challenge(commitments);
    let mut d = RistrettoPoint::identity();
    let mut z = Scalar::from(0u8);
    let c1 = commitments.get(0)?;
    let c1_decompressed = (*c1).decompress()?;
    let r1 = blinding_factors.get(0)?;
    for i in 3..commitments.len(){
        let ci = commitments.get(i)?;
        let ai = compute_sub_challenge(&k, i as u32);
        let ci_decompressed = ci.decompress()?;
        let di = ai * (c1_decompressed - ci_decompressed);
        let ri = blinding_factors.get(i)?;
        let zi = ai * (*r1 - *ri);
        d = d + di;
        z = z + zi;
    }

    //TODO can we produce proof to zero commitment in a more direct way?
    //produce fake commitment to 0 for chaum pedersen commitment
    let proof_zero = chaum_pedersen_prove_eq(prng,
                                        pedersen_gens,
                                        &Scalar::from(0u8),
                                        &d.compress(),
                                        &get_fake_zero_commitment(),
                                        &z,
                                        &get_fake_zero_commitment_blinding());
    Ok(ChaumPedersenCommitmentEqProofMultiple{
        c1_eq_c2: proof_c1_c2,
        zero: proof_zero,
    })
}

pub fn chaum_pedersen_verify_multiple_eq(
    pedersen_gens: &PedersenGens,
    commitments: &[CompressedRistretto],
    proof: &ChaumPedersenCommitmentEqProofMultiple) -> Result<bool, ZeiError>
{
    /*! I verify a proof that all commitments are to the same value.
     * Return Ok(true) in case of success, Ok(false) in case of verification failure,
     * and Err(Error::DeserializationError) in case some CompressedRistretto can not be
     decompressed
     */
    let k = compute_challenge(commitments);
    let mut d = RistrettoPoint::identity();
    let c1 = commitments.get(0)?;
    let c1_decompressed = c1.decompress()?;
    for i in 3..commitments.len(){
        let ci = commitments.get(i)?;
        let ai = compute_sub_challenge(&k, i as u32);
        let ci_decompressed = ci.decompress()?;
        let di = ai * (c1_decompressed - ci_decompressed);
        d = d + di;
    }


    //TODO can we produce proof to zero commitment in a more direct way?
    //produce fake commitment to 0 for chaum pedersen commitment
    let mut vrfy_ok = chaum_pedersen_verify_eq(
        pedersen_gens, &commitments[0], &commitments[1], &proof.c1_eq_c2)?;
    vrfy_ok = vrfy_ok && chaum_pedersen_verify_eq(
        pedersen_gens,
        &d.compress(),
        &get_fake_zero_commitment(),
        &proof.zero,
    )?;

    Ok(vrfy_ok)
}


#[cfg(test)]
mod test {
    use super::*;
    use bulletproofs::PedersenGens;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;

    #[test]
    pub fn test_chaum_perdersen_equality_commitment() {
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();

        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, chaum_pedersen_verify_eq(
            &pc_gens,
            &c1,
            &c2,
            &proof).unwrap());

        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value2,
            &c1,
            &c2,
            &bf1,
            &bf2);

        assert_eq!(false, chaum_pedersen_verify_eq(&pc_gens,
                                                   &c1,
                                                   &c2,
                                                   &proof).unwrap());


        let c3 = pedersen_bases.commit(value1, bf2).compress();
        let proof = chaum_pedersen_prove_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            &c1,
            &c3,
            &bf1,
            &bf2);

        assert_eq!(true, chaum_pedersen_verify_eq(
            &pc_gens,
            &c1,
            &c3,
            &proof).unwrap());
    }

    #[test]
    fn test_chaum_perdersen_multiple_eq_proof(){
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let bf3 = Scalar::from(1000u32);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();
        let c3 = pedersen_bases.commit(value1, bf3).compress();

        let com_vec = &[c1,c2,c3];
        let blind_vec = vec![bf1,bf2,bf3];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            com_vec,
            &blind_vec).unwrap();

        assert_eq!(false, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            com_vec,
            &proof).unwrap());

        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value1, bf2).compress();
        let c3 = pedersen_bases.commit(value1, bf3).compress();

        let com_vec = &[c1,c2,c3];
        let blind_vec = vec![bf1,bf2,bf3];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            com_vec,
            &blind_vec).unwrap();

        assert_eq!(true, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            com_vec,
            &proof).unwrap());
    }

    #[test]
    fn test_chaum_perdersen_multiple_eq_proof_using_two(){
        let mut csprng: ChaChaRng;
        csprng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let value1 = Scalar::from(16u8);
        let value2 = Scalar::from(32u8);
        let bf1 = Scalar::from(10u8);
        let bf2 = Scalar::from(100u8);
        let pedersen_bases = PedersenGens::default();
        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value2, bf2).compress();

        let com_vec = &[c1,c2];
        let blind_vec = vec![bf1,bf2];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            com_vec,
            &blind_vec).unwrap();

        assert_eq!(false, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            com_vec,
            &proof).unwrap(),
        "Values were different");

        let c1 = pedersen_bases.commit(value1, bf1).compress();
        let c2 = pedersen_bases.commit(value1, bf2).compress();

        let com_vec = &[c1,c2];
        let blind_vec = vec![bf1,bf2];

        let proof = chaum_pedersen_prove_multiple_eq(
            &mut csprng,
            &pc_gens,
            &value1,
            com_vec,
            &blind_vec).unwrap();
        assert_eq!(true, chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            com_vec,
            &proof).unwrap(),
                   "Values are the same");
    }
}
