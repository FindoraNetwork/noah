// Bring the macros and other important things into scope.
#[cfg(test)]
use proptest::prelude::*;

use rand::SeedableRng;
use zei::algebra::bls12_381::BLSGt;
use zei::basic_crypto::signatures::bls::{
  bls_aggregate, bls_gen_keys, bls_sign, bls_verify_aggregated,
};

proptest! {

    #[test]
    fn test_bls(message1 in  "\\PC*", message2 in  "\\PC*", message3 in  "\\PC*"){

      let mut prng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);
      let (sk1, pk1) = bls_gen_keys::<_, BLSGt>(&mut prng);
      let (sk2, pk2) = bls_gen_keys::<_, BLSGt>(&mut prng);
      let (sk3, pk3) = bls_gen_keys::<_, BLSGt>(&mut prng);

      let signature1 = bls_sign(&sk1, &message1);
      let signature2 = bls_sign(&sk2, &message2);
      let signature3 = bls_sign(&sk3, &message3);

      let keys = [&pk1, &pk2, &pk3];

      let agg_signature =
        bls_aggregate::<BLSGt>(&keys, &[&signature1, &signature2, &signature3]);

      assert_eq!(Ok(()),
                 bls_verify_aggregated(&keys, &message1, &agg_signature));
      assert_eq!(Ok(()),
                 bls_verify_aggregated(&keys, &message2, &agg_signature));
      assert_eq!(Ok(()),
                 bls_verify_aggregated(&keys, &message3, &agg_signature));
  }
}
