use ark_std::time::Instant;
use noah_algebra::bn254::BN254G1;
use noah_algebra::{bn254::BN254Scalar, prelude::*};

fn main() {
    let mut prng = test_rng();

    let count = 65536;

    // Sample random points
    let mut points = Vec::new();
    for _ in 0..count {
        points.push(BN254G1::random(&mut prng));
    }

    // Sample random scalars
    let mut scalars = Vec::new();
    for _ in 0..count {
        scalars.push(BN254Scalar::random(&mut prng));
    }

    let points_ptr = points.iter().collect::<Vec<&BN254G1>>();
    let scalars_ptr = scalars.iter().collect::<Vec<&BN254Scalar>>();

    let start = Instant::now();
    for _ in 0..10 {
        let _ = BN254G1::multi_exp(&scalars_ptr, &points_ptr);
    }
    println!("average time: {} s", start.elapsed().as_secs_f32() / 10f32);
}
