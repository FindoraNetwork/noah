////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions for tests and runnable examples.                                              //
////////////////////////////////////////////////////////////////////////////////////////////////////

use super::{cac_multi_prove, cac_multi_verify, cac_prove, cac_verify};
use crate::algebra::groups::{Group, Scalar};
use crate::algebra::pairing::PairingTargetGroup;
use crate::basic_crypto::elgamal::{
  elgamal_derive_public_key, elgamal_encrypt, elgamal_generate_secret_key, ElGamalCiphertext,
  ElGamalPublicKey, ElGamalSecretKey,
};
use crate::crypto::anon_creds::{
  ac_keygen_issuer, ac_keygen_user, ac_reveal, ac_sign, ACIssuerPublicKey, ACIssuerSecretKey,
  ACRevealSig, ACUserPublicKey, ACUserSecretKey,
};
use crate::errors::ZeiError;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub fn setup_agg<P: PairingTargetGroup>(
  prng: &mut ChaChaRng,
  n_attr: usize)
  -> (ACIssuerPublicKey<P::G1, P::G2>,
      ACIssuerSecretKey<P::G1, P::ScalarField>,
      ACUserPublicKey<P::G1>,
      ACUserSecretKey<P::ScalarField>) {
  let ac_issuer_keypair = ac_keygen_issuer::<_, P>(prng, n_attr);
  let ac_issuer_pub_key = ac_issuer_keypair.0;
  let ac_issuer_sec_key = ac_issuer_keypair.1;
  let (user_pub_key, user_sec_key) = ac_keygen_user::<_, P>(prng, &ac_issuer_pub_key);

  (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key)
}

pub fn setup_ac<P: PairingTargetGroup>(
  prng: &mut ChaChaRng,
  n_attr: usize)
  -> (ACIssuerPublicKey<P::G1, P::G2>,
      ACIssuerSecretKey<P::G1, P::ScalarField>,
      ACUserPublicKey<P::G1>,
      ACUserSecretKey<P::ScalarField>,
      ElGamalPublicKey<P::G1>,
      ElGamalSecretKey<P::ScalarField>) {
  let ac_issuer_keypair = ac_keygen_issuer::<_, P>(prng, n_attr);

  let ac_issuer_pub_key = ac_issuer_keypair.0;
  let ac_issuer_sk = ac_issuer_keypair.1;

  let recv_secret_key = elgamal_generate_secret_key::<_, P::ScalarField>(prng);
  let recv_enc_pub_key = elgamal_derive_public_key(&P::G1::get_base(), &recv_secret_key);

  let (user_pk, user_sk) = ac_keygen_user::<_, P>(prng, &ac_issuer_pub_key);

  (ac_issuer_pub_key, ac_issuer_sk, user_pk, user_sk, recv_enc_pub_key, recv_secret_key)
}

pub fn gen_ac_reveal_sig<P: PairingTargetGroup>(
  prng: &mut ChaChaRng,
  ac_issuer_pub_key: &ACIssuerPublicKey<P::G1, P::G2>,
  ac_issuer_sec_key: &ACIssuerSecretKey<P::G1, P::ScalarField>,
  user_pub_key: &ACUserPublicKey<P::G1>,
  user_sec_key: &ACUserSecretKey<P::ScalarField>,
  reveal_bitmap: &[bool])
  -> (Vec<ElGamalCiphertext<P::G1>>,
      Vec<P::ScalarField>,
      Vec<P::ScalarField>,
      ACRevealSig<P::G1, P::G2, P::ScalarField>,
      ElGamalPublicKey<P::G1>) {
  let recv_sec_key = elgamal_generate_secret_key::<_, P::ScalarField>(prng);
  let recv_pub_key = elgamal_derive_public_key(&P::G1::get_base(), &recv_sec_key);

  let num_attr = reveal_bitmap.len();
  let mut attrs = vec![];
  for _ in 0..num_attr {
    attrs.push(P::ScalarField::random_scalar(prng));
  }
  let signature = ac_sign::<_, P>(prng, &ac_issuer_sec_key, &user_pub_key, attrs.as_slice());

  let proof = ac_reveal::<_, P>(prng,
                                &user_sec_key,
                                ac_issuer_pub_key,
                                &signature,
                                &attrs,
                                reveal_bitmap).unwrap();

  let mut ctexts_rands = vec![];
  let mut ctexts = vec![];
  let mut revealed_attrs = vec![];
  for (attr, reveal) in attrs.iter().zip(reveal_bitmap) {
    if *reveal {
      let rand = P::ScalarField::random_scalar(prng);
      let ctext = elgamal_encrypt(&P::G1::get_base(), attr, &rand, &recv_pub_key);

      ctexts_rands.push(rand);
      ctexts.push(ctext);
      revealed_attrs.push(attr.clone());
    }
  }

  (ctexts, ctexts_rands, revealed_attrs, proof, recv_pub_key)
}

pub fn confidential_reveal_agg<P: PairingTargetGroup>(reveal_bitmap: &[bool]) {
  let mut prng: ChaChaRng;
  prng = ChaChaRng::from_seed([0u8; 32]);

  let (ac_issuer_pub_key, ac_issuer_sec_key, user_pub_key, user_sec_key) =
    setup_agg::<P>(&mut prng, reveal_bitmap.len());

  let (ctexts1, ctexts_rands1, revealed_attrs1, proof1, recv_pub_key1) =
    gen_ac_reveal_sig::<P>(&mut prng,
                           &ac_issuer_pub_key,
                           &ac_issuer_sec_key,
                           &user_pub_key,
                           &user_sec_key,
                           reveal_bitmap);

  let (ctexts2, ctexts_rands2, revealed_attrs2, proof2, recv_pub_key2) =
    gen_ac_reveal_sig::<P>(&mut prng,
                           &ac_issuer_pub_key,
                           &ac_issuer_sec_key,
                           &user_pub_key,
                           &user_sec_key,
                           reveal_bitmap);

  let (ctexts3, ctexts_rands3, revealed_attrs3, proof3, recv_pub_key3) =
    gen_ac_reveal_sig::<P>(&mut prng,
                           &ac_issuer_pub_key,
                           &ac_issuer_sec_key,
                           &user_pub_key,
                           &user_sec_key,
                           reveal_bitmap);

  let mut cac_proof =
    cac_multi_prove::<_, P>(&mut prng,
                            &ac_issuer_pub_key,
                            &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                            &[revealed_attrs1.as_slice(),
                              revealed_attrs2.as_slice(),
                              revealed_attrs3.as_slice()],
                            &[ctexts_rands1.as_slice(),
                              ctexts_rands2.as_slice(),
                              ctexts_rands3.as_slice()],
                            reveal_bitmap,
                            &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                            &[&proof1, &proof2, &proof3]).unwrap();

  let vrfy = cac_multi_verify::<P>(&ac_issuer_pub_key,
                                   &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                                   &[&proof1, &proof2, &proof3],
                                   &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                                   &cac_proof,
                                   reveal_bitmap);

  assert_eq!(Ok(()), vrfy);

  //making one proof fail
  let old = cac_proof.0.attr_sum_com_yy2[2].clone();
  cac_proof.0.attr_sum_com_yy2[2] = P::G2::get_identity(); //making last proof fail due to bad credential

  let vrfy = cac_multi_verify::<P>(&ac_issuer_pub_key,
                                   &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                                   &[&proof1, &proof2, &proof3],
                                   &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                                   &cac_proof,
                                   reveal_bitmap);

  assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy);

  cac_proof.0.attr_sum_com_yy2[2] = old; //restoring credential
  cac_proof.0.agg_rands_coms_g[0] = P::G1::get_identity(); //making ciphertext fail

  let vrfy = cac_multi_verify::<P>(&ac_issuer_pub_key,
                                   &[&recv_pub_key1, &recv_pub_key2, &recv_pub_key3],
                                   &[&proof1, &proof2, &proof3],
                                   &[ctexts1.as_slice(), ctexts2.as_slice(), ctexts3.as_slice()],
                                   &cac_proof,
                                   reveal_bitmap);

  assert_eq!(Err(ZeiError::IdentityRevealVerifyError), vrfy);
}

pub fn ac_gen_proofs_and_ciphertexts<P: PairingTargetGroup>(
  prng: &mut ChaChaRng,
  ac_issuer_pk: &ACIssuerPublicKey<P::G1, P::G2>,
  ac_issuer_sk: &ACIssuerSecretKey<P::G1, P::ScalarField>,
  user_pk: &ACUserPublicKey<P::G1>,
  user_sk: &ACUserSecretKey<P::ScalarField>,
  recv_enc_pub_key: &ElGamalPublicKey<P::G1>,
  reveal_bitmap: &[bool])
  -> (Vec<P::ScalarField>,
      Vec<ElGamalCiphertext<P::G1>>,
      Vec<P::ScalarField>,
      ACRevealSig<P::G1, P::G2, P::ScalarField>) {
  let mut attrs = vec![];
  let num_attr = reveal_bitmap.len();

  for _ in 0..num_attr {
    attrs.push(P::ScalarField::random_scalar(prng));
  }

  let signature = ac_sign::<_, P>(prng, &ac_issuer_sk, &user_pk, attrs.as_slice());

  let proof = ac_reveal::<_, P>(prng,
                                &user_sk,
                                &ac_issuer_pk,
                                &signature,
                                &attrs,
                                reveal_bitmap).unwrap();

  let mut ctext_rands = vec![];
  let mut ctexts = vec![];
  let mut revealed_attrs: Vec<P::ScalarField> = vec![];
  for (attr, reveal) in attrs.iter().zip(reveal_bitmap) {
    if *reveal {
      let rand = P::ScalarField::random_scalar(prng);
      let ctext = elgamal_encrypt(&P::G1::get_base(), attr, &rand, &recv_enc_pub_key);

      ctext_rands.push(rand);
      ctexts.push(ctext);
      revealed_attrs.push(attr.clone());
    }
  }

  (revealed_attrs, ctexts.clone(), ctext_rands.clone(), proof)
}

pub fn confidential_ac_reveal<P: PairingTargetGroup>(reveal_bitmap: &[bool]) {
  let mut prng: ChaChaRng;
  prng = ChaChaRng::from_seed([0u8; 32]);

  let (ac_issuer_pub_key, ac_issuer_sk, user_pk, user_sk, recv_enc_pub_key, _) =
    setup_ac::<P>(&mut prng, reveal_bitmap.len());

  let (revealed_attrs, mut ctexts, ctext_rands, mut proof) =
    ac_gen_proofs_and_ciphertexts::<P>(&mut prng,
                                       &ac_issuer_pub_key,
                                       &ac_issuer_sk,
                                       &user_pk,
                                       &user_sk,
                                       &recv_enc_pub_key,
                                       &reveal_bitmap);

  let mut cac_proof = cac_prove::<_, P>(&mut prng,
                                        &ac_issuer_pub_key,
                                        &recv_enc_pub_key,
                                        &revealed_attrs.as_slice(),
                                        &ctext_rands.as_slice(),
                                        reveal_bitmap,
                                        &ctexts.as_slice(),
                                        &proof).unwrap();

  let vrfy = cac_verify::<P>(&ac_issuer_pub_key,
                             &recv_enc_pub_key,
                             &proof,
                             ctexts.as_slice(),
                             &cac_proof,
                             reveal_bitmap);

  assert_eq!(Ok(()), vrfy);

  let mut tampered_bitmap = vec![];
  tampered_bitmap.extend_from_slice(reveal_bitmap);

  let b = reveal_bitmap.get(0).unwrap();

  tampered_bitmap[0] = !(*b);
  if *b {
    ctexts.remove(0);
    cac_proof.0.agg_rands_coms_g.remove(0);
    cac_proof.0.agg_rands_coms_pk.remove(0);
    cac_proof.0.agg_attrs_coms_g.remove(0);
    cac_proof.0.attrs_resps[0].remove(0);
    cac_proof.0.rands_resps[0].remove(0);
    proof.pok.response_attrs.push(P::ScalarField::from_u32(0));
  } else {
    ctexts.push(elgamal_encrypt(&P::G1::get_base(),
                                &P::ScalarField::from_u32(0),
                                &P::ScalarField::from_u32(0),
                                &recv_enc_pub_key));
    cac_proof.0.agg_rands_coms_g.push(P::G1::get_identity());
    cac_proof.0.agg_rands_coms_pk.push(P::G1::get_identity());
    cac_proof.0.agg_attrs_coms_g.push(P::G1::get_identity());
    if cac_proof.0.attrs_resps.len() > 0 {
      cac_proof.0.attrs_resps[0].push(P::ScalarField::from_u32(0u32));
      cac_proof.0.rands_resps[0].push(P::ScalarField::from_u32(0u32));
    } else {
      cac_proof.0
               .attrs_resps
               .push(vec![P::ScalarField::from_u32(0u32)]);
      cac_proof.0
               .rands_resps
               .push(vec![P::ScalarField::from_u32(0u32)]);
    }
  }

  let vrfy = cac_verify::<P>(&ac_issuer_pub_key,
                             &recv_enc_pub_key,
                             &proof,
                             ctexts.as_slice(),
                             &cac_proof,
                             tampered_bitmap.as_slice());

  assert_eq!(Err(ZeiError::IdentityRevealVerifyError),
             vrfy,
             "proof should fail");
}
