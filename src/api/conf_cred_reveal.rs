use crate::algebra::bls12_381::{BLSGt, BLSScalar, BLSG1, BLSG2};
use crate::api::anon_creds::{ACIssuerPublicKey, ACRevealSig};
use crate::errors::ZeiError;
use rand::{CryptoRng, Rng};

/// Aggregated proof of knowledge of revealed attributes for an anonymous credential reveal signature
/// that are encrypted under ElGamal
pub type AggPoKAttrs = crate::crypto::conf_cred_reveal::AggPoKAttrs<BLSG1, BLSG2, BLSScalar>;

/// Proof of knowledge of attributes that a) are elgamal encrypted, and b) verify an anonymous credential reveal proof.
pub type CACProof = crate::crypto::conf_cred_reveal::CACProof<BLSG1, BLSG2, BLSScalar>;

pub type ElGamalPublicKey = crate::basic_crypto::elgamal::ElGamalPublicKey<BLSG1>;
pub type ElGamalCiphertext = crate::basic_crypto::elgamal::ElGamalCiphertext<BLSG1>;

/// I produce a CACProof for a single instance of a confidential anonymous reveal. Proof asserts
/// that a list of attributes can be decrypted from a list of ciphertexts under recv_enc_pub_key,
/// and that these attributed verify an anonymous credential reveal proof.
/// * `prng` - randomness source
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `attrs` - attributes to prove knowledge of
/// * `ctexts_rand` - randomness used to encrypt attrs
/// * `bitmap` - indicates position of each attribute to prove
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `returns` - proof that the ciphertexts contains the attributes that have been signed by some issuer for the user.
/// # Example
/// ```
/// use zei::crypto::conf_cred_reveal::test_helpers::{setup_ac, ac_gen_proofs_and_ciphertexts};
/// use zei::api::conf_cred_reveal::{cac_prove, cac_verify};
/// use zei::algebra::bls12_381::BLSGt;
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng: ChaChaRng;
///
/// let mut prng: ChaChaRng;
/// prng = ChaChaRng::from_seed([0u8; 32]);
/// let reveal_bitmap = [true, false, true, false, true, false, true, false, true, false];
/// let (ac_issuer_pub_key, ac_issuer_sk, user_pk, user_sk, recv_enc_pub_key, _) =
///    setup_ac::<BLSGt>(&mut prng, reveal_bitmap.len());
/// let (revealed_attrs, mut ctexts, ctext_rands, mut proof) =
///    ac_gen_proofs_and_ciphertexts::<BLSGt>(&mut prng,
///                                       &ac_issuer_pub_key,
///                                       &ac_issuer_sk,
///                                       &user_pk,
///                                       &user_sk,
///                                       &recv_enc_pub_key,
///                                       &reveal_bitmap);
///
/// let mut cac_proof = cac_prove(&mut prng,
///                                        &ac_issuer_pub_key,
///                                        &recv_enc_pub_key,
///                                        &revealed_attrs.as_slice(),
///                                        &ctext_rands.as_slice(),
///                                        &reveal_bitmap,
///                                        &ctexts.as_slice(),
///                                        &proof).unwrap();
///
/// let vrfy = cac_verify(&ac_issuer_pub_key,
///                             &recv_enc_pub_key,
///                             &proof,
///                             ctexts.as_slice(),
///                             &cac_proof,
///                             &reveal_bitmap);
///
///  assert_eq!(Ok(()), vrfy);
/// ```
pub fn cac_prove<R: CryptoRng + Rng>(prng: &mut R,
                                     ac_issuer_pub_key: &ACIssuerPublicKey,
                                     recv_enc_pub_key: &ElGamalPublicKey,
                                     attrs: &[BLSScalar],
                                     ctexts_rand: &[BLSScalar],
                                     bitmap: &[bool],
                                     ctexts: &[ElGamalCiphertext],
                                     ac_reveal_sig: &ACRevealSig)
                                     -> Result<CACProof, ZeiError> {
  crate::crypto::conf_cred_reveal::cac_prove::<_, BLSGt>(prng,
                                                         ac_issuer_pub_key,
                                                         recv_enc_pub_key,
                                                         attrs,
                                                         ctexts_rand,
                                                         bitmap,
                                                         ctexts,
                                                         ac_reveal_sig)
}

/// I produce a CACProof for a set of instances of confidential anonymous reveal proofs.
/// # Example
/// ```
/// use zei::crypto::conf_cred_reveal::test_helpers::{setup_agg, gen_ac_reveal_sig};
/// use zei::api::conf_cred_reveal::{cac_multi_prove, cac_multi_verify};
/// use zei::algebra::bls12_381::BLSGt;
/// use rand::SeedableRng;
/// use rand_chacha::ChaChaRng;
/// let mut prng: ChaChaRng;
/// prng = ChaChaRng::from_seed([0u8; 32]);
/// let reveal_bitmap = [true, false];
/// let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
///      setup_agg::<BLSGt>(&mut prng, reveal_bitmap.len());
///
/// let mut prng: ChaChaRng;
///  prng = ChaChaRng::from_seed([0u8; 32]);
///
///  let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
///    setup_agg::<BLSGt>(&mut prng, reveal_bitmap.len());
///
///  let (ctexts1, ctexts_rands1, revealed_attrs1, proof1, recv_pub_key1) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let (ctexts2, ctexts_rands2, revealed_attrs2, proof2, recv_pub_key2) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let (ctexts3, ctexts_rands3, revealed_attrs3, proof3, recv_pub_key3) =
///    gen_ac_reveal_sig::<BLSGt>(&mut prng,
///                           &ac_issuer_pub_key,
///                           &ac_issuer_sec_key,
///                           &user_pub_key,
///                           &user_sec_key,
///                           &reveal_bitmap);
///
///  let mut cac_proof =
///    cac_multi_prove(&mut prng,
///                            &ac_issuer_pub_key,
///                            &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
///                            &[revealed_attrs1.as_slice(),
///                              revealed_attrs2.as_slice(),
///                              revealed_attrs3.as_slice()],
///                            &[ctexts_rands1.as_slice(),
///                              ctexts_rands2.as_slice(),
///                              ctexts_rands3.as_slice()],
///                            &reveal_bitmap,
///                            &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
///                            &[&proof1, &proof2, &proof3]).unwrap();
///
///  let vrfy = cac_multi_verify(&ac_issuer_pub_key,
///                                   &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
///                                   &[&proof1, &proof2, &proof3],
///                                   &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
///                                   &cac_proof,
///                                   &reveal_bitmap);
///
///  assert_eq!(Ok(()), vrfy);
/// ```
pub fn cac_multi_prove<R: CryptoRng + Rng>(prng: &mut R,
                                           ac_issuer_pub_key: &ACIssuerPublicKey,
                                           recv_enc_pub_keys: &[&ElGamalPublicKey],
                                           attrs_vecs: &[&[BLSScalar]],
                                           ctexts_rand_vecs: &[&[BLSScalar]],
                                           bitmap: &[bool],
                                           ctexts_vecs: &[&[ElGamalCiphertext]],
                                           ac_reveal_sigs: &[&ACRevealSig])
                                           -> Result<CACProof, ZeiError> {
  crate::crypto::conf_cred_reveal::cac_multi_prove::<_, BLSGt>(prng,
                                                               ac_issuer_pub_key,
                                                               recv_enc_pub_keys,
                                                               attrs_vecs,
                                                               ctexts_rand_vecs,
                                                               bitmap,
                                                               ctexts_vecs,
                                                               ac_reveal_sigs)
}

/// I verify a CACProof.
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_key` - encryption public key of the receiver
/// * `ac_reveal_sig` - proof that the issuer has signed some attributes
/// * `ctexts` - list of ciphertexts that encrypt the attributes
/// * `cac_proof` - proof that the ciphertexts contains the attributes that have been signed by some issuer for the user.
/// * `bitmap` - indicates which attributes should be revealed to the receiver.
/// * `returns` - nothing if the verification is successful an error otherwise.
/// # Example
/// ```
/// //See zei:crypto:conf_cred_reveal::cac_prove
/// ```
pub fn cac_verify(ac_issuer_pub_key: &ACIssuerPublicKey,
                  recv_enc_pub_key: &ElGamalPublicKey,
                  ac_reveal_sig: &ACRevealSig,
                  ctexts: &[ElGamalCiphertext],
                  cac_proof: &CACProof,
                  bitmap: &[bool])
                  -> Result<(), ZeiError> {
  crate::crypto::conf_cred_reveal::cac_verify::<BLSGt>(ac_issuer_pub_key,
                                                       recv_enc_pub_key,
                                                       ac_reveal_sig,
                                                       ctexts,
                                                       cac_proof,
                                                       bitmap)
}

/// I verify a CACProof for a set of Confidential Anonymous Credential instances.
/// * `ac_issuer_pub_key` - (signing) public key of the issuer
/// * `recv_enc_pub_keys` - list of encryption public keys for the receivers
/// * `ac_reveal_sigs` - collection of proofs that the issuer has signed some attributes
/// * `ctexts_vecs` - collection of lists containing ciphertexts that encrypt the attributes
/// * `cac_proof` - a single (short) proof corresponding to all the collections of ciphertexts / ac reveal signatures
/// * `bitmap` - indicates which attributes should be revealed to the receiver
/// * `returns` - nothing or an error if the verification fails
/// # Example
/// ```
/// //See zei::crypto::conf_cred_reveal::cac_multi_prove
/// ```
pub fn cac_multi_verify(ac_issuer_pub_key: &ACIssuerPublicKey,
                        recv_enc_pub_keys: &[&ElGamalPublicKey],
                        ac_reveal_sigs: &[&ACRevealSig],
                        ctexts_vecs: &[&[ElGamalCiphertext]],
                        cac_proof: &CACProof,
                        bitmap: &[bool])
                        -> Result<(), ZeiError> {
  crate::crypto::conf_cred_reveal::cac_multi_verify::<BLSGt>(ac_issuer_pub_key,
                                                             recv_enc_pub_keys,
                                                             ac_reveal_sigs,
                                                             ctexts_vecs,
                                                             cac_proof,
                                                             bitmap)
}
