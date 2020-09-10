use super::MTHash;
use algebra::groups::{Scalar as _, ScalarArithmetic};
use algebra::ristretto::RistrettoScalar as Scalar;
use digest::Digest;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

pub struct MiMCHash {
  c: [Scalar; MIMC_ROUNDS],
}
pub(crate) const MIMC_ROUNDS: usize = 159;

impl MTHash for MiMCHash {
  type S = Scalar;
  fn new(level: usize) -> MiMCHash {
    MiMCHash { c: compute_mimc_constants(level) }
  }
  fn digest(&self, values: &[&Scalar]) -> Scalar {
    let mut sa = Scalar::from_u32(0u32);
    let mut sc = Scalar::from_u32(0u32);
    for value in values.iter() {
      let x = mimc_feistel(&(value.add(&sa)), &sc, &self.c[..]);
      sa = x.0;
      sc = x.1;
    }
    sa
  }

  fn digest_root(&self, size: usize, values: &[&Scalar]) -> Scalar {
    let x = Scalar::from_u64(size as u64);
    let mut vec = Vec::with_capacity(values.len() + 1);
    vec.push(&x);
    vec.extend_from_slice(values);
    self.digest(&vec[..])
  }
}

pub(crate) fn mimc_f(s: &Scalar, c: &Scalar) -> Scalar {
  let x = s.add(c);
  let x2 = x.mul(&x);
  x2.mul(&x2).mul(&x)
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn compute_mimc_constants(level: usize) -> [Scalar; MIMC_ROUNDS] {
  let mut c = [Scalar::from_u32(0u32); MIMC_ROUNDS];
  let mut hash = sha2::Sha256::new();
  hash.input(level.to_string());
  let mut seed = [0u8; 32];
  seed.copy_from_slice(&hash.result()[..]);
  let mut prng = ChaChaRng::from_seed(seed);
  for i in 1..MIMC_ROUNDS - 1 {
    c[i] = Scalar::random(&mut prng);
  }
  c
}

pub(crate) fn mimc_feistel(left: &Scalar, right: &Scalar, c: &[Scalar]) -> (Scalar, Scalar) {
  let mut xl = *left;
  let mut xr = *right;
  for ci in c {
    let aux = xl;
    xl = xr.add(&mimc_f(&xl, ci));
    xr = aux;
  }
  (xl, xr)
}

#[cfg(test)]
pub mod test {

  use crate::basics::hash::mimc::MiMCHash;
  use crate::basics::hash::MTHash;
  use algebra::groups::Scalar as _;
  use algebra::ristretto::RistrettoScalar as Scalar;

  fn check_mimc(level: usize, input: &[&Scalar], expected_output: &[u8]) {
    let hash = MiMCHash::new(level);

    let expected_output_scalar = Scalar::from_bytes(expected_output).unwrap();
    let res = hash.digest(input);
    assert_eq!(res, expected_output_scalar);
  }

  #[test]
  fn mimc() {
    check_mimc(0,
               &[],
               &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0]);

    check_mimc(0,
               &[&Scalar::from_u64(1)],
               &[215, 151, 33, 139, 13, 189, 216, 171, 212, 224, 32, 91, 177, 168, 253, 14, 111,
                 219, 48, 107, 2, 189, 149, 235, 107, 214, 49, 139, 124, 128, 204, 3]);

    check_mimc(1,
               &[],
               &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0]);

    check_mimc(1,
               &[&Scalar::from_u64(1), &Scalar::from_u64(5)],
               &[84, 187, 110, 168, 34, 210, 33, 51, 131, 110, 106, 108, 78, 131, 241, 207, 73,
                 110, 220, 110, 33, 219, 61, 27, 11, 203, 171, 90, 220, 83, 134, 15]);

    check_mimc(2,
               &[&Scalar::from_u64(3),
                 &Scalar::from_u64(3),
                 &Scalar::from_u64(10)],
               &[18, 170, 81, 36, 201, 195, 102, 94, 73, 192, 203, 249, 89, 93, 147, 61, 224,
                 180, 197, 169, 51, 164, 199, 88, 47, 0, 213, 69, 119, 80, 87, 5]);

    check_mimc(15,
               &[&Scalar::from_u64(4553),
                 &Scalar::from_u64(778878),
                 &Scalar::from_u64(11),
                 &Scalar::from_u64(45),
                 &Scalar::from_u64(454),
                 &Scalar::from_u64(0),
                 &Scalar::from_u64(33366),
                 &Scalar::from_u64(4587),
                 &Scalar::from_u64(11)],
               &[12, 61, 158, 17, 144, 198, 23, 28, 51, 100, 67, 120, 128, 52, 224, 169, 89, 1,
                 147, 81, 105, 150, 163, 11, 200, 65, 18, 185, 123, 144, 41, 14]);
  }
}
