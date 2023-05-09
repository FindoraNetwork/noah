use crate::anemoi_jive::AnemoiJive;
use noah_algebra::{
    prelude::*,
    traits::{CurveGroup, Scalar},
};
use rand_core::{CryptoRng, RngCore};

/// The Schnorr signing key is often also called private key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrSigningKey<G: CurveGroup>(pub G::ScalarType);

/// The Schnorr verifying key is also often called public key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrVerifyingKey<G: CurveGroup>(pub G);

/// The Schnorr signature.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrSignature<G: CurveGroup> {
    /// The s element of the signature.
    pub schnorr_s: G::ScalarType,
    /// the e element of the signature.
    pub schnorr_e: G::BaseType,
}

/// The keypair for Schnorr signature.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct SchnorrKeyPair<G: CurveGroup> {
    /// The verifying key.
    pub(crate) verifying_key: SchnorrVerifyingKey<G>,
    /// The secret key.
    pub(crate) signing_key: SchnorrSigningKey<G>,
}

impl<G: CurveGroup> SchnorrKeyPair<G> {
    /// Sample the key pair.
    pub fn sample<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let signing_key = G::ScalarType::random(prng);
        let verifying_key = G::get_base().mul(&signing_key);

        Self {
            verifying_key: SchnorrVerifyingKey(verifying_key),
            signing_key: SchnorrSigningKey(signing_key),
        }
    }

    /// Get the verifying key.
    pub fn get_verifying_key(&self) -> SchnorrVerifyingKey<G> {
        self.verifying_key.clone()
    }

    /// Get the signing key.
    pub fn get_signing_key(&self) -> SchnorrSigningKey<G> {
        self.signing_key.clone()
    }
}

impl<G: CurveGroup> SchnorrSigningKey<G> {
    /// Sign the message with the signing key.
    pub fn sign<H, R>(
        &self,
        prng: &mut R,
        aux: G::BaseType,
        msg: &[G::BaseType],
    ) -> SchnorrSignature<G>
    where
        H: AnemoiJive<G::BaseType, 2, 12>,
        R: CryptoRng + RngCore,
    {
        let k = G::ScalarType::random(prng);
        let point_r = G::get_base().mul(&k);

        let mut input = vec![aux, point_r.get_x(), point_r.get_y()];
        input.extend_from_slice(msg);

        let e = H::eval_variable_length_hash(&input);

        // This will perform a modular reduction.
        let e_converted = G::ScalarType::from(&e.into());

        let s = k - &(self.0 * &e_converted);

        SchnorrSignature {
            schnorr_s: s,
            schnorr_e: e,
        }
    }

    /// Get the raw scalar element.
    pub fn get_raw(&self) -> G::ScalarType {
        self.0
    }

    /// Reconstruct from the raw scalar element.
    pub fn from_raw(raw: G::ScalarType) -> Self {
        Self(raw)
    }

    /// Compute the corresponding verifying key.
    pub fn to_verifying_key(&self) -> SchnorrVerifyingKey<G> {
        SchnorrVerifyingKey(G::get_base().mul(&self.0))
    }
}

impl<G: CurveGroup> SchnorrVerifyingKey<G> {
    /// Verify the signature with the verifying key.
    pub fn verify<H>(
        &self,
        signature: &SchnorrSignature<G>,
        aux: G::BaseType,
        msg: &[G::BaseType],
    ) -> Result<()>
    where
        H: AnemoiJive<G::BaseType, 2, 12>,
    {
        let e_converted = G::ScalarType::from(&signature.schnorr_e.into());

        let point_r_recovered = G::get_base().mul(&signature.schnorr_s) + &self.0.mul(&e_converted);

        let mut input = vec![aux, point_r_recovered.get_x(), point_r_recovered.get_y()];
        input.extend_from_slice(msg);

        let e: G::BaseType = H::eval_variable_length_hash(&input);

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
        bls12_381::BLSScalar, jubjub::JubjubPoint, rand_helper::test_rng, traits::Scalar,
    };

    use crate::anemoi_jive::AnemoiJive381;

    use super::SchnorrKeyPair;

    #[test]
    fn test_schnorr_signature() {
        let mut rng = test_rng();

        let key_pair = SchnorrKeyPair::<JubjubPoint>::sample(&mut rng);

        let verifying_key = key_pair.get_verifying_key();
        let signing_key = key_pair.get_signing_key();

        let msg = vec![
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
        ];

        let aux = BLSScalar::random(&mut rng);

        let sign = signing_key.sign::<AnemoiJive381, _>(&mut rng, aux, &msg);

        assert!(verifying_key
            .verify::<AnemoiJive381>(&sign, aux, &msg)
            .is_ok());
        assert!(verifying_key
            .verify::<AnemoiJive381>(&sign, aux, &msg[..4])
            .is_err());
    }
}
