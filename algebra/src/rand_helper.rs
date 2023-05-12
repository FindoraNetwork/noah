use rand_chacha::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    ChaChaRng,
};

fn test_rng_helper() -> ChaChaRng {
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    ChaChaRng::from_seed(seed)
}

/// Should be used only for tests, not for any real world usage.
#[cfg(not(feature = "std"))]
pub fn test_rng() -> impl RngCore + CryptoRng {
    test_rng_helper()
}

/// Should be used only for tests, not for any real world usage.
#[cfg(feature = "std")]
pub fn test_rng() -> impl RngCore + CryptoRng {
    let is_deterministic =
        std::env::vars().any(|(key, val)| key == "DETERMINISTIC_TEST_RNG" && val == "1");
    if is_deterministic {
        test_rng_helper()
    } else {
        ChaChaRng::from_entropy()
    }
}

#[cfg(all(test, feature = "std"))]
mod test {
    use ark_std::UniformRand;

    #[test]
    fn test_deterministic_rng() {
        let mut rng = super::test_rng();
        let a = u128::rand(&mut rng);

        // Reset the rng by sampling a new one.
        let mut rng = super::test_rng();
        let b = u128::rand(&mut rng);
        assert_ne!(a, b); // should be unequal with high probability.

        // Let's make the rng deterministic.
        std::env::set_var("DETERMINISTIC_TEST_RNG", "1");
        let mut rng = super::test_rng();
        let a = u128::rand(&mut rng);

        // Reset the rng by sampling a new one.
        let mut rng = super::test_rng();
        let b = u128::rand(&mut rng);
        assert_eq!(a, b); // should be equal with high probability.
    }
}
