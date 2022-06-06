use zei_algebra::ristretto::RistrettoPoint;
use zei_algebra::{
    hash::{Hash, Hasher},
    prelude::*,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The ElGamal encryption key/public key.
pub struct ElGamalEncKey<G>(pub G);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The ElGamal decryption key/secret key.
pub struct ElGamalDecKey<S>(pub(crate) S);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// An ElGamal ciphertext.
pub struct ElGamalCiphertext<G> {
    /// `e1` = `r * G`
    pub e1: G,
    /// `e2` = `m * G + r * pk`
    pub e2: G,
}

impl Hash for ElGamalEncKey<RistrettoPoint> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_compressed_bytes().as_slice().hash(state);
    }
}

impl ZeiFromToBytes for ElGamalCiphertext<RistrettoPoint> {
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(self.e1.to_compressed_bytes().as_slice());
        v.extend_from_slice(self.e2.to_compressed_bytes().as_slice());
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        let e1 = RistrettoPoint::from_compressed_bytes(&bytes[0..RistrettoPoint::COMPRESSED_LEN])
            .c(d!(ZeiError::DeserializationError))?;
        let e2 = RistrettoPoint::from_compressed_bytes(&bytes[RistrettoPoint::COMPRESSED_LEN..])
            .c(d!(ZeiError::DeserializationError))?;
        Ok(ElGamalCiphertext { e1, e2 })
    }
}

/// Return an ElGamal key pair as `(sk, pk = sk * G)`
pub fn elgamal_key_gen<R: CryptoRng + RngCore, G: Group>(
    prng: &mut R,
) -> (ElGamalDecKey<G::ScalarType>, ElGamalEncKey<G>) {
    let base = G::get_base();
    let secret_key = ElGamalDecKey(G::ScalarType::random(prng));
    let public_key = ElGamalEncKey(base.mul(&secret_key.0));
    (secret_key, public_key)
}

/// Return an ElGamal ciphertext pair as `(r * G, m * G + r * pk)`, where `G` is a base point on the curve
pub fn elgamal_encrypt<G: Group>(
    m: &G::ScalarType,
    r: &G::ScalarType,
    pub_key: &ElGamalEncKey<G>,
) -> ElGamalCiphertext<G> {
    let base = G::get_base();
    let e1 = base.mul(r);
    let e2 = base.mul(m).add(&(pub_key.0).mul(r));

    ElGamalCiphertext::<G> { e1, e2 }
}

/// Verify that the ElGamal ciphertext encrypts m by checking `ctext.e2 - ctext.e1 * sk = m * G`
pub fn elgamal_verify<G: Group>(
    m: &G::ScalarType,
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::ScalarType>,
) -> Result<()> {
    let base = G::get_base();
    if base.mul(m).add(&ctext.e1.mul(&sec_key.0)) == ctext.e2 {
        Ok(())
    } else {
        Err(eg!(ZeiError::ElGamalVerificationError))
    }
}

/// Perform a partial decryption for the ElGamal ciphertext that returns `m * G`
pub fn elgamal_partial_decrypt<G: Group>(
    ctext: &ElGamalCiphertext<G>,
    sec_key: &ElGamalDecKey<G::ScalarType>,
) -> G {
    ctext.e2.sub(&ctext.e1.mul(&sec_key.0))
}

#[cfg(test)]
mod elgamal_test {
    use rand_chacha::ChaChaRng;
    use zei_algebra::bls12_381::{BLSGt, BLSG1, BLSG2};
    use zei_algebra::jubjub::JubjubPoint;
    use zei_algebra::prelude::*;
    use zei_algebra::ristretto::RistrettoPoint;

    fn verification<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);

        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng);

        let m = G::ScalarType::from(100u32);
        let r = G::ScalarType::random(&mut prng);
        let ctext = super::elgamal_encrypt::<G>(&m, &r, &public_key);
        pnk!(super::elgamal_verify::<G>(&m, &ctext, &secret_key));

        let wrong_m = G::ScalarType::from(99u32);
        let err = super::elgamal_verify(&wrong_m, &ctext, &secret_key)
            .err()
            .unwrap();
        msg_eq!(ZeiError::ElGamalVerificationError, err);
    }

    fn decryption<G: Group>() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (secret_key, public_key) = super::elgamal_key_gen::<_, G>(&mut prng);

        let mu32 = 100u32;
        let m = G::ScalarType::from(mu32);
        let r = G::ScalarType::random(&mut prng);
        let ctext = super::elgamal_encrypt(&m, &r, &public_key);
        pnk!(super::elgamal_verify(&m, &ctext, &secret_key));

        let m = G::ScalarType::from(u64::MAX);
        let ctext = super::elgamal_encrypt(&m, &r, &public_key);
        pnk!(super::elgamal_verify(&m, &ctext, &secret_key));
    }

    #[test]
    fn verify() {
        verification::<RistrettoPoint>();
        verification::<BLSG1>();
        verification::<BLSG2>();
        verification::<BLSGt>();
        verification::<JubjubPoint>();
    }

    #[test]
    fn decrypt() {
        decryption::<RistrettoPoint>();
        decryption::<BLSG1>();
        decryption::<BLSG2>();
        decryption::<BLSGt>();
        decryption::<JubjubPoint>();
    }
}
