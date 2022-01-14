use algebra::{
    bls12_381::{BLSScalar, BLSG1},
    groups::{Group, Scalar},
};
use ark_std::{rand::SeedableRng, time::Instant};
use rand_chacha::ChaChaRng;

fn main() {
    let mut prng = ChaChaRng::from_entropy();

    let count = 65536;

    // Sample random points
    let mut points = Vec::new();
    for _ in 0..count {
        points.push(BLSG1::get_random_base(&mut prng));
    }

    // Sample random scalars
    let mut scalars = Vec::new();
    for _ in 0..count {
        scalars.push(BLSScalar::random(&mut prng));
    }

    let points_ptr = points.iter().map(|r| r).collect::<Vec<&BLSG1>>();
    let scalars_ptr = scalars.iter().map(|r| r).collect::<Vec<&BLSScalar>>();

    let start = Instant::now();
    let _ = BLSG1::vartime_multi_exp(&scalars_ptr, &points_ptr);

    println!("total time: {} s", start.elapsed().as_secs_f32());
    println!("average time: {} us", start.elapsed().as_micros() / count);
}
