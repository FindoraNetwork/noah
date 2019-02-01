use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::CryptoRng;
use rand::Rng;
use blake2::{Blake2b, Digest};

pub fn symmetric_key_from_public_key<R>(prng: &mut R, pk: &RistrettoPoint, curve_base:&RistrettoPoint) -> ([u8;32], RistrettoPoint)
where R: CryptoRng + Rng {
    /*! I derive a symmetric key from an ElGamal public key over the Ristretto group. Return symmetric key, and encoded
     * randonmess to be used by secret key holder to derive the same symmetric key
    */
    let rand  = Scalar::random(prng);
    let encoded_rand = &rand * curve_base;
    let curve_key = &rand * pk;
    let mut hasher = Blake2b::new();
    hasher.input(curve_key.compress().as_bytes());
    let mut symmetric_key: [u8;32] = Default::default();
    let hash_result = hasher.result();
    let sym_64 = hash_result.as_slice();
    symmetric_key.copy_from_slice(&sym_64[0..32]);
    (symmetric_key, encoded_rand)
}

pub fn symmetric_key_from_secret_key<'a>(sk: &Scalar, rand: &RistrettoPoint) -> [u8;32]
{
    let curve_key = sk*rand;
    let mut hasher = Blake2b::new();
    hasher.input(curve_key.compress().as_bytes());
    let mut symmetric_key: [u8;32] = Default::default();
    let hash_result = hasher.result();
    let sym_64 = hash_result.as_slice();
    symmetric_key.copy_from_slice(&sym_64[0..32]);
    symmetric_key
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;


    #[test]
    fn test_key_derivation(){
        let mut prng: ChaChaRng;
        prng  = ChaChaRng::from_seed([0u8; 32]);
        let sk = Scalar::random(&mut prng);
        let base = RISTRETTO_BASEPOINT_POINT;
        let pk = &sk * &base;
        let (from_pk_key, encoded_rand) = symmetric_key_from_public_key(&mut prng, &pk, &base);
        let from_sk_key = symmetric_key_from_secret_key(&sk, &encoded_rand);
        assert_eq!(from_pk_key, from_sk_key);
    }
}


