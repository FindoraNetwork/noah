use ark_std::test_rng;
use std::time::Instant;
use zei_algebra::{bls12_381::BLSScalar, prelude::*};
use zei_plonk::poly_commit::field_polynomial::{primitive_nth_root_of_unity, FpPolynomial};

fn main() {
    let mut prng = test_rng();
    let n = 65536;

    let root = primitive_nth_root_of_unity::<BLSScalar>(n).unwrap();

    let mut v = vec![BLSScalar::zero(); n];
    for i in 0..n {
        v[i] = BLSScalar::random(&mut prng);
    }

    let l = FpPolynomial::from_coefs(v);
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = FpPolynomial::ffti(&root, &l.coefs, n);
    }
    println!(
        "fft total time: {} s",
        start.elapsed().as_secs_f32() / 1000f32
    );
}
