// Bring the macros and other important things into scope.
#[cfg(test)]
use proptest::prelude::*;

use rand::SeedableRng;
use zei::algebra::bls12_381::BLSGt;
use zei::basic_crypto::signatures::bls::{
  bls_aggregate, bls_batch_verify, bls_gen_keys, bls_sign, bls_verify, bls_verify_aggregated,
};

proptest! {

    #[test]
    #[ignore]
    fn simple_signatures(message in "\\PC*") {

      let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
      let (sk, pk) = bls_gen_keys::<_, BLSGt>(&mut prng);
      let signature = bls_sign::<BLSGt, _>(&sk, &message);
      assert_eq!(Ok(()), bls_verify(&pk, &message, &signature));

    }

    #[test]
    #[ignore]
    fn aggregated_signatures(message in  "\\PC*"){

      let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
      let (sk1, pk1) = bls_gen_keys::<_, BLSGt>(&mut prng);
      let (sk2, pk2) = bls_gen_keys::<_, BLSGt>(&mut prng);
      let (sk3, pk3) = bls_gen_keys::<_, BLSGt>(&mut prng);

      let signature1 = bls_sign(&sk1, &message);
      let signature2 = bls_sign(&sk2, &message);
      let signature3 = bls_sign(&sk3, &message);

      let keys = [&pk1, &pk2, &pk3];

      let agg_signature =
        bls_aggregate::<BLSGt>(&keys, &[&signature1, &signature2, &signature3]);

      assert_eq!(Ok(()),
                 bls_verify_aggregated(&keys, &message, &agg_signature));
  }

  #[test]
  #[ignore]
  fn batching(message1 in  "\\PC*", message2 in  "\\PC*", message3 in  "\\PC*") {

    let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
    let (sk1, pk1) = bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk2, pk2) = bls_gen_keys::<_, BLSGt>(&mut prng);
    let (sk3, pk3) = bls_gen_keys::<_, BLSGt>(&mut prng);


    let signature1 = bls_sign::<BLSGt, _>(&sk1, &message1);
    let signature2 = bls_sign::<BLSGt, _>(&sk2, &message2);
    let signature3 = bls_sign::<BLSGt, _>(&sk3, &message3);

    let keys = [pk1, pk2, pk3];
    let messages = [&message1.as_bytes(), &message2.as_bytes(), &message3.as_bytes()];
    let sigs = [signature1, signature2, signature3];

    assert_eq!(Ok(()), bls_batch_verify(&keys, &messages[..], &sigs));

  }
}
