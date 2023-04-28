use super::anemoi_jive::AnemoiJive;
use noah_algebra::{
    prelude::*,
    traits::{Coordinate, Group, Scalar},
};
use rand_core::{CryptoRng, RngCore};

/// The schnorr signing key is also called private key.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrSigningKey<S: Scalar>(S);

/// The schnorr verifying key is also called public key.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrVerifyingKey<G: Group>(G);

/// The schnorr signature.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrSignature<S: Scalar, E: Scalar> {
    /// The s element of the signature.
    pub schnorr_s: S,
    /// the e element of the signature.
    pub schnorr_e: E,
}

/// The keypair for schnorr signature.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrKeyPair<S: Scalar, G: Group<ScalarType = S>> {
    /// The verifying key.
    pub(crate) verifying_key: SchnorrVerifyingKey<G>,
    /// The secret key.
    pub(crate) signing_key: SchnorrSigningKey<S>,
}

impl<S: Scalar, G: Group<ScalarType = S>> SchnorrKeyPair<S, G> {
    /// Sample the key pair.
    pub fn sample<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let signing_key = S::random(prng);
        let verifying_key = G::get_base().mul(&signing_key);

        Self {
            verifying_key: SchnorrVerifyingKey(verifying_key),
            signing_key: SchnorrSigningKey(signing_key),
        }
    }

    /// Get the verifying key.
    pub fn get_verifying_key(&self) -> SchnorrVerifyingKey<G> {
        self.verifying_key
    }

    /// Get the signing key.
    pub fn get_signing_key(&self) -> SchnorrSigningKey<S> {
        self.signing_key
    }
}

impl<S: Scalar> SchnorrSigningKey<S> {
    /// Sign the message with the signing key.
    pub fn sign<M, H, G, R>(&self, prng: &mut R, msg: &[M]) -> SchnorrSignature<S, M>
    where
        M: Scalar,
        H: AnemoiJive<M, 2, 12>,
        G: Group<ScalarType = S> + Coordinate<ScalarField = M>,
        R: CryptoRng + RngCore,
    {
        let k = S::random(prng);
        let point_r = G::get_base().mul(&k);

        let mut input = vec![M::zero(), point_r.get_x(), point_r.get_y()];
        input.extend_from_slice(msg);

        let e = H::eval_variable_length_hash(&input);

        // This will perform a modular reduction.
        let e_converted = S::from(&e.into());

        let s = k - &(self.0 * &e_converted);

        SchnorrSignature {
            schnorr_s: s,
            schnorr_e: e,
        }
    }

    /// Get the raw scalar element.
    pub fn get_raw(&self) -> S {
        self.0
    }

    /// Reconstruct from the raw scalar element.
    pub fn from_raw(raw: S) -> Self {
        Self(raw)
    }

    /// Compute the corresponding verifying key.
    pub fn to_verifying_key<G: Group<ScalarType = S>>(&self) -> SchnorrVerifyingKey<G> {
        SchnorrVerifyingKey(G::get_base().mul(&self.0))
    }
}

impl<M: Scalar, S: Scalar, G: Group<ScalarType = S> + Coordinate<ScalarField = M>>
    SchnorrVerifyingKey<G>
{
    /// Verify the signature with the verifying key.
    pub fn verify<H>(&self, signature: &SchnorrSignature<S, M>, msg: &[M]) -> Result<()>
    where
        H: AnemoiJive<M, 2, 12>,
    {
        let e_converted = S::from(&signature.schnorr_e.into());

        let point_r_recovered = G::get_base().mul(&signature.schnorr_s) + &self.0.mul(&e_converted);

        let mut input = vec![
            M::zero(),
            point_r_recovered.get_x(),
            point_r_recovered.get_y(),
        ];
        input.extend_from_slice(msg);

        let e: M = H::eval_variable_length_hash(&input);

        if e != signature.schnorr_e {
            Err(eg!(NoahError::SignatureError))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use noah_algebra::{
        bls12_381::BLSScalar,
        jubjub::{JubjubPoint, JubjubScalar},
        rand_helper::test_rng,
        traits::Scalar,
    };

    use crate::basic::anemoi_jive::AnemoiJive381;

    use super::SchnorrKeyPair;

    #[test]
    fn test_schnorr_signature() {
        let mut rng = test_rng();

        let key_pair = SchnorrKeyPair::<JubjubScalar, JubjubPoint>::sample(&mut rng);

        let verifying_key = key_pair.get_verifying_key();
        let signing_key = key_pair.get_signing_key();

        let msg = vec![
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
        ];

        let sign = signing_key.sign::<BLSScalar, AnemoiJive381, JubjubPoint, _>(&mut rng, &msg);

        assert!(verifying_key.verify::<AnemoiJive381>(&sign, &msg).is_ok());

        let msg = &msg[..4];
        assert!(verifying_key.verify::<AnemoiJive381>(&sign, msg).is_err());
    }
}
