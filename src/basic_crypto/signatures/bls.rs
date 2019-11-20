use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::errors::ZeiError;
use crate::utils::u64_to_bigendian_u8array;
use digest::Digest;
use rand::{CryptoRng, Rng};

type HashFnc = sha2::Sha512;

// BLS Signatures
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlsSecretKey<P: PairingTargetGroup>(pub(crate) P::ScalarField);
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlsPublicKey<P: PairingTargetGroup>(pub(crate) P::G1);
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlsSignature<P: PairingTargetGroup>(pub(crate) P::G2);

/// bls key generation function
pub fn bls_gen_keys<R: CryptoRng + Rng, P: PairingTargetGroup>(
  prng: &mut R)
  -> (BlsSecretKey<P>, BlsPublicKey<P>) {
  let sec_key = P::ScalarField::random_scalar(prng);
  let pub_key = P::G1::get_base().mul(&sec_key);
  (BlsSecretKey(sec_key), BlsPublicKey(pub_key))
}

/// bls signature function
pub fn bls_sign<P: PairingTargetGroup, B: AsRef<[u8]>>(signing_key: &BlsSecretKey<P>,
                                                       message: &B)
                                                       -> BlsSignature<P> {
  let hashed = bls_hash_message::<P>(message.as_ref());
  BlsSignature(hashed.mul(&signing_key.0))
}

/// bls verification function
pub fn bls_verify<P: PairingTargetGroup, B: AsRef<[u8]>>(ver_key: &BlsPublicKey<P>,
                                                         message: &B,
                                                         signature: &BlsSignature<P>)
                                                         -> Result<(), ZeiError> {
  let hashed = bls_hash_message::<P>(message.as_ref());
  let a = P::pairing(&P::G1::get_base(), &signature.0);
  let b = P::pairing(&ver_key.0, &hashed);

  if a == b {
    Ok(())
  } else {
    Err(ZeiError::SignatureError)
  }
}

/// aggregate signature (for a single common message)
pub fn bls_aggregate<P: PairingTargetGroup>(ver_keys: &[&BlsPublicKey<P>],
                                            signatures: &[&BlsSignature<P>])
                                            -> BlsSignature<P> {
  assert_eq!(ver_keys.len(), signatures.len());
  let scalars = bls_hash_pubkeys_to_scalars::<P>(ver_keys);
  let mut agg_signature = P::G2::get_identity();
  for (t, s) in scalars.iter().zip(signatures) {
    agg_signature = agg_signature.add(&s.0.mul(t));
  }
  BlsSignature(agg_signature)
}

/// Verification of an aggregated signature for a common message
pub fn bls_verify_aggregated<P: PairingTargetGroup, B: AsRef<[u8]>>(ver_keys: &[&BlsPublicKey<P>],
                                                                    message: &B,
                                                                    agg_signature: &BlsSignature<P>)
                                                                    -> Result<(), ZeiError> {
  let scalars = bls_hash_pubkeys_to_scalars::<P>(ver_keys);
  let mut agg_pub_key = P::G1::get_identity();
  for (t, key) in scalars.iter().zip(ver_keys) {
    agg_pub_key = agg_pub_key.add(&key.0.mul(t));
  }
  bls_verify::<P, B>(&BlsPublicKey(agg_pub_key), message, agg_signature)
}

/// Batch verification of many signatures
pub fn bls_batch_verify<P: PairingTargetGroup, B: AsRef<[u8]>>(ver_keys: &[BlsPublicKey<P>],
                                                               messages: &[B],
                                                               signatures: &[BlsSignature<P>])
                                                               -> Result<(), ZeiError> {
  assert!(ver_keys.len() == messages.len() && ver_keys.len() == signatures.len());
  let sig = bls_add_signatures(signatures);
  bls_batch_verify_added_signatures(ver_keys, messages, &sig)
}

/// signature aggregation for (possibly) different messages
pub fn bls_add_signatures<P: PairingTargetGroup>(signatures: &[BlsSignature<P>])
                                                 -> BlsSignature<P> {
  let mut sig = P::G2::get_identity();
  for s in signatures {
    sig = sig.add(&s.0);
  }
  BlsSignature(sig)
}

/// verification of an aggregated signatures for different messages
pub fn bls_batch_verify_added_signatures<P: PairingTargetGroup, B: AsRef<[u8]>>(
  ver_keys: &[BlsPublicKey<P>],
  messages: &[B],
  signature: &BlsSignature<P>)
  -> Result<(), ZeiError> {
  let a = P::pairing(&P::G1::get_base(), &signature.0);
  let mut b = P::get_identity();
  for (pk, m) in ver_keys.iter().zip(messages) {
    let hashed = bls_hash_message::<P>(m.as_ref());
    let p = P::pairing(&pk.0, &hashed);
    b = b.add(&p)
  }

  if a == b {
    Ok(())
  } else {
    Err(ZeiError::SignatureError)
  }
}

/// hash function to G2
pub fn bls_hash_message<P: PairingTargetGroup>(message: &[u8]) -> P::G2 {
  let mut hash = HashFnc::default();
  hash.input(message);
  P::G2::from_hash(hash)
}

/// hash function to N scalars on the pairing field
pub fn bls_hash_pubkeys_to_scalars<P: PairingTargetGroup>(ver_keys: &[&BlsPublicKey<P>])
                                                          -> Vec<P::ScalarField> {
  let mut hasher = HashFnc::default();
  let n = ver_keys.len();
  for key in ver_keys {
    hasher.input(key.0.to_compressed_bytes().as_slice());
  }
  let hash = hasher.result();

  let mut scalars = Vec::with_capacity(n);
  for i in 0..n {
    hasher = HashFnc::default();
    hasher.input(u64_to_bigendian_u8array(i as u64));
    hasher.input(&hash[..]);
    scalars.push(P::ScalarField::from_hash(hasher));
  }
  scalars
}

#[cfg(test)]
mod tests {
  use crate::algebra::bls12_381::BLSGt;
  use crate::errors::ZeiError;
  use rand::SeedableRng;

  #[test]
  fn bls_signatures() {
    let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
    let (sk, pk) = super::bls_gen_keys::<_, BLSGt>(&mut prng);

    let message = b"this is a message";

    let signature = super::bls_sign::<BLSGt, _>(&sk, message);

    assert_eq!(Ok(()), super::bls_verify(&pk, message, &signature));
    assert_eq!(Err(crate::errors::ZeiError::SignatureError),
               super::bls_verify(&pk, b"wrong message", &signature))
  }

  #[test]
  fn bls_aggregated_signatures() {
    let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
    let (sk1, pk1) = super::bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk2, pk2) = super::bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk3, pk3) = super::bls_gen_keys::<_, BLSGt>(&mut prng);

    let message = b"this is a message";

    let signature1 = super::bls_sign(&sk1, message);
    let signature2 = super::bls_sign(&sk2, message);
    let signature3 = super::bls_sign(&sk3, message);

    let keys = [&pk1, &pk2, &pk3];

    let agg_signature =
      super::bls_aggregate::<BLSGt>(&keys, &[&signature1, &signature2, &signature3]);

    assert_eq!(Ok(()),
               super::bls_verify_aggregated(&keys, message, &agg_signature));
  }

  #[test]
  fn bls_batching() {
    let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
    let (sk1, pk1) = super::bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk2, pk2) = super::bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk3, pk3) = super::bls_gen_keys::<_, BLSGt>(&mut prng);

    let message1 = b"this is a message";
    let message2 = b"this is another message";
    let message3 = b"this is an additional message";

    let signature1 = super::bls_sign::<BLSGt, _>(&sk1, message1);
    let signature2 = super::bls_sign::<BLSGt, _>(&sk2, message2);
    let signature3 = super::bls_sign::<BLSGt, _>(&sk3, message3);

    let keys = [pk1, pk2, pk3];
    let messages = [message1.as_ref(), message2.as_ref(), message3.as_ref()];
    let sigs = [signature1, signature2, signature3];

    assert_eq!(Ok(()), super::bls_batch_verify(&keys, &messages[..], &sigs));

    let new_message3 = b"this message has not been signed";

    let messages = [&message1[..], &message2[..], &new_message3[..]];

    assert_eq!(Err(ZeiError::SignatureError),
               super::bls_batch_verify(&keys, &messages, &sigs));
  }
}
