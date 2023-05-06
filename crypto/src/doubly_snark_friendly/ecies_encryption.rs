use crate::anemoi_jive::AnemoiJive;
use noah_algebra::prelude::*;
use rand_core::{CryptoRng, RngCore};

/// The encryption key is often also called public key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESEncryptionKey<G: CurveGroup>(pub G);

/// The decryption key is also often called secret key.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESDecryptionKey<G: CurveGroup>(pub G::ScalarType);

/// The ciphertext.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESCiphertext<G: CurveGroup> {
    /// The Diffie-Hellman key exchange group element divided by the cofactor.
    pub dh_point_div_by_cofactor: G,
    /// the ciphertexts.
    pub ciphertext: Vec<G::BaseType>,
}

/// The plaintext.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESPlaintext<G: CurveGroup>(pub Vec<G::BaseType>);

/// The keypair for the ECIES encryption.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct ECIESKeyPair<G: CurveGroup> {
    /// The encryption key.
    pub(crate) encryption_key: ECIESEncryptionKey<G>,
    /// The decryption key.
    pub(crate) decryption_key: ECIESDecryptionKey<G>,
}

impl<G: CurveGroup> ECIESKeyPair<G> {
    /// Sample the key pair.
    pub fn sample<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        let decryption_key = G::ScalarType::random(prng);
        let encryption_key = G::get_base().mul(&decryption_key);

        Self {
            encryption_key: ECIESEncryptionKey(encryption_key),
            decryption_key: ECIESDecryptionKey(decryption_key),
        }
    }

    /// Get the encryption key.
    pub fn get_encryption_key(&self) -> ECIESEncryptionKey<G> {
        self.encryption_key.clone()
    }

    /// Get the decryption key.
    pub fn get_decryption_key(&self) -> ECIESDecryptionKey<G> {
        self.decryption_key.clone()
    }
}

impl<G: CurveGroup> ECIESDecryptionKey<G> {
    /// Decrypt the ciphertext with the decryption key.
    pub fn decrypt<H>(&self, ciphertext: &ECIESCiphertext<G>) -> ECIESPlaintext<G>
    where
        H: AnemoiJive<G::BaseType, 2, 12>,
    {
        let point = ciphertext
            .dh_point_div_by_cofactor
            .multiply_by_cofactor()
            .mul(&self.0);
        let mask = H::eval_stream_cipher(
            &[G::BaseType::zero(), point.get_x(), point.get_y()],
            ciphertext.ciphertext.len(),
        );

        let mut plaintext = Vec::<G::BaseType>::with_capacity(ciphertext.ciphertext.len());
        for (c, m) in ciphertext.ciphertext.iter().zip(mask.iter()) {
            plaintext.push(*c - m);
        }

        ECIESPlaintext(plaintext)
    }

    /// Get the raw scalar element.
    pub fn get_raw(&self) -> G::ScalarType {
        self.0
    }

    /// Reconstruct from the raw scalar element.
    pub fn from_raw(raw: G::ScalarType) -> Self {
        Self(raw)
    }

    /// Compute the corresponding encryption key.
    pub fn to_encryption_key(&self) -> ECIESEncryptionKey<G> {
        ECIESEncryptionKey(G::get_base().mul(&self.0))
    }
}

impl<G: CurveGroup> ECIESEncryptionKey<G> {
    /// Encrypt the plaintext with the encryption key.
    pub fn encrypt<H, R>(&self, prng: &mut R, plaintext: &ECIESPlaintext<G>) -> ECIESCiphertext<G>
    where
        H: AnemoiJive<G::BaseType, 2, 12>,
        R: CryptoRng + RngCore,
    {
        let k = G::ScalarType::random(prng);

        let point = self.0.mul(&k);
        let point_div_by_cofactor = G::get_point_div_by_cofactor().mul(&k);

        let mask = H::eval_stream_cipher(
            &[G::BaseType::zero(), point.get_x(), point.get_y()],
            plaintext.0.len(),
        );

        let mut ciphertext = Vec::<G::BaseType>::with_capacity(plaintext.0.len());
        for (p, m) in plaintext.0.iter().zip(mask.iter()) {
            ciphertext.push(*p + m);
        }

        ECIESCiphertext {
            dh_point_div_by_cofactor: point_div_by_cofactor,
            ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use noah_algebra::{
        bls12_381::BLSScalar, jubjub::JubjubPoint, rand_helper::test_rng, traits::Scalar,
    };

    use crate::anemoi_jive::AnemoiJive381;
    use crate::doubly_snark_friendly::ecies_encryption::{ECIESKeyPair, ECIESPlaintext};

    #[test]
    fn test_ecies_encryption() {
        let mut rng = test_rng();

        let key_pair = ECIESKeyPair::<JubjubPoint>::sample(&mut rng);

        let encryption_key = key_pair.get_encryption_key();
        let decryption_key = key_pair.get_decryption_key();

        let msg = vec![
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
            BLSScalar::random(&mut rng),
        ];

        let c = encryption_key.encrypt::<AnemoiJive381, _>(&mut rng, &ECIESPlaintext(msg.clone()));
        let p = decryption_key.decrypt::<AnemoiJive381>(&c);

        assert_eq!(msg, p.0);
    }
}
