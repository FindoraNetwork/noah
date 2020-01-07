// Bring the macros and other important things into scope.
#[cfg(test)]
use proptest::prelude::*;

use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use zei::api::gp_sig::{gpsig_join_cert, gpsig_setup, gpsig_sign, gpsig_verify};

proptest! {

    #[test]
    #[ignore]
    fn gp_sig(message in  "\\PC*"){

       let mut prng = ChaChaRng::from_seed([0u8;32]);
       let (gpk, msk) = gpsig_setup(&mut prng);
       let (join_cert, _) = gpsig_join_cert(&mut prng, &msk);
       let sig = gpsig_sign(&mut prng, &gpk, &join_cert, &message);
       assert!(gpsig_verify(&gpk, &sig, &message.as_bytes()).is_ok());

  }
}
