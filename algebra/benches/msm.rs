use ark_std::{rand::SeedableRng, time::Instant};
use rand_chacha::ChaChaRng;
use zei_algebra::{
    bls12_381::{BLSScalar, BLSG1},
    traits::{Group, Scalar},
};

fn main() {
    let mut prng = ChaChaRng::from_entropy();

    let count = 65536;

    // Sample random points
    let mut points = Vec::new();
    for _ in 0..count {
        points.push(BLSG1::random(&mut prng));
    }

    // Sample random scalars
    let mut scalars = Vec::new();
    for _ in 0..count {
        scalars.push(BLSScalar::random(&mut prng));
    }

    let points_ptr = points.iter().collect::<Vec<&BLSG1>>();
    let scalars_ptr = scalars.iter().collect::<Vec<&BLSScalar>>();

    let start = Instant::now();
    for _ in 0..10 {
        let _ = BLSG1::multi_exp(&scalars_ptr, &points_ptr);
    }
    println!("average time: {} s", start.elapsed().as_secs_f32() / 10f32);
}
