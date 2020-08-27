pub mod errors;
pub mod serialization;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[macro_export]
macro_rules! serialize_deserialize {
  ($t:ident) => {
    impl serde::Serialize for $t {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
      {
        if serializer.is_human_readable() {
          serializer.serialize_str(&utils::b64enc(&self.zei_to_bytes()))
        } else {
          serializer.serialize_bytes(&self.zei_to_bytes())
        }
      }
    }

    impl<'de> serde::Deserialize<'de> for $t {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::Deserializer<'de>
      {
        let bytes = if deserializer.is_human_readable() {
          deserializer.deserialize_str(utils::serialization::zei_obj_serde::BytesVisitor)?
        } else {
          deserializer.deserialize_bytes(utils::serialization::zei_obj_serde::BytesVisitor)?
        };
        $t::zei_from_bytes(bytes.as_slice()).map_err(serde::de::Error::custom)
      }
    }
  };
}

///   I convert a u32 into a 4 bytes array (bigendian)
#[allow(dead_code)]
pub fn u32_to_bigendian_u8array(n: u32) -> [u8; 4] {
  let mut array = [0u8; 4];
  array[0] = ((n >> 24) & 0xFF) as u8;
  array[1] = ((n >> 16) & 0xFF) as u8;
  array[2] = ((n >> 8) & 0xFF) as u8;
  array[3] = (n & 0xFF) as u8;
  array
}

#[allow(dead_code)]
/// I convert a u32 into a 4 bytes array (littleendian)
pub fn u32_to_littleendian_u8array(n: u32) -> [u8; 4] {
  let mut array = [0u8; 4];
  array[3] = ((n >> 24) & 0xFF) as u8;
  array[2] = ((n >> 16) & 0xFF) as u8;
  array[1] = ((n >> 8) & 0xFF) as u8;
  array[0] = (n & 0xFF) as u8;
  array
}

/// I convert a u64 into a 8 bytes array (bigendian)
pub fn u64_to_bigendian_u8array(n: u64) -> [u8; 8] {
  let mut array = [0u8; 8];
  array[0] = ((n >> 56) & 0xFF) as u8;
  array[1] = ((n >> 48) & 0xFF) as u8;
  array[2] = ((n >> 40) & 0xFF) as u8;
  array[3] = ((n >> 32) & 0xFF) as u8;
  array[4] = ((n >> 24) & 0xFF) as u8;
  array[5] = ((n >> 16) & 0xFF) as u8;
  array[6] = ((n >> 8) & 0xFF) as u8;
  array[7] = (n & 0xFF) as u8;
  array
}

/// I convert a 16 byte array into a u128 (bigendian)
pub fn u8_bigendian_slice_to_u128(array: &[u8]) -> u128 {
  u128::from(array[0]) << 120
  | u128::from(array[1]) << 112
  | u128::from(array[2]) << 104
  | u128::from(array[3]) << 96
  | u128::from(array[4]) << 88
  | u128::from(array[5]) << 80
  | u128::from(array[6]) << 72
  | u128::from(array[7]) << 64
  | u128::from(array[8]) << 56
  | u128::from(array[9]) << 48
  | u128::from(array[10]) << 40
  | u128::from(array[11]) << 32
  | u128::from(array[12]) << 24
  | u128::from(array[13]) << 16
  | u128::from(array[14]) << 8
  | u128::from(array[15])
}

/// I convert a 8 byte array big-endian into a u64 (bigendian)
pub fn u8_bigendian_slice_to_u64(array: &[u8]) -> u64 {
  u64::from(array[0]) << 56
  | u64::from(array[1]) << 48
  | u64::from(array[2]) << 40
  | u64::from(array[3]) << 32
  | u64::from(array[4]) << 24
  | u64::from(array[5]) << 16
  | u64::from(array[6]) << 8
  | u64::from(array[7])
}

/// I convert a 8 byte array little-endian into a u64 (bigendian)
pub fn u8_littleendian_slice_to_u64(array: &[u8]) -> u64 {
  u64::from(array[7]) << 56
  | u64::from(array[6]) << 48
  | u64::from(array[5]) << 40
  | u64::from(array[4]) << 32
  | u64::from(array[3]) << 24
  | u64::from(array[2]) << 16
  | u64::from(array[1]) << 8
  | u64::from(array[0])
}

/// I convert a 4 byte array into a u32 (bigendian)
pub fn u8_bigendian_slice_to_u32(array: &[u8]) -> u32 {
  u32::from(array[0]) << 24
  | u32::from(array[1]) << 16
  | u32::from(array[2]) << 8
  | u32::from(array[3])
}

#[allow(dead_code)]
/// I convert a 4 byte array into a u32 (littleendian)
pub fn u8_littleendian_slice_to_u32(array: &[u8]) -> u32 {
  u32::from(array[3]) << 24
  | u32::from(array[2]) << 16
  | u32::from(array[1]) << 8
  | u32::from(array[0])
}

/// I compute the minimum power of two that is greater or equal to the input
pub fn min_greater_equal_power_of_two(n: u32) -> u32 {
  2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

pub fn u64_to_u32_pair(x: u64) -> (u32, u32) {
  ((x & 0xFFFF_FFFF) as u32, (x >> 32) as u32)
}

pub fn b64enc<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
  base64::encode_config(input, base64::URL_SAFE)
}
pub fn b64dec<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, base64::DecodeError> {
  base64::decode_config(input, base64::URL_SAFE)
}

pub const SEED_SIZE: usize = 32;
pub fn compute_seed_from_hash<D>(hash: D, seed: &mut [u8; SEED_SIZE])
  where D: Digest<OutputSize = U64> + Default
{
  let result = hash.result();
  seed.copy_from_slice(&result[0..SEED_SIZE]);
}

pub fn compute_prng_from_hash<D>(hash: D) -> ChaCha20Rng
  where D: Digest<OutputSize = U64> + Default
{
  let mut seed: [u8; SEED_SIZE] = [0; SEED_SIZE];
  compute_seed_from_hash(hash, &mut seed);
  rand_chacha::ChaChaRng::from_seed(seed)
}

#[cfg(test)]
mod test {

  #[test]
  fn u32_to_bignedian_u8array() {
    let n: u32 = 0xFA01C673;
    let n_array = super::u32_to_bigendian_u8array(n);
    assert_eq!(0xFA, n_array[0]);
    assert_eq!(0x01, n_array[1]);
    assert_eq!(0xC6, n_array[2]);
    assert_eq!(0x73, n_array[3]);
  }

  #[test]
  fn test_u8_bigendian_slice_to_u32() {
    let array = [0xFA as u8, 0x01 as u8, 0xC6 as u8, 0x73 as u8];
    let n = super::u8_bigendian_slice_to_u32(&array);
    assert_eq!(0xFA01C673, n);
  }

  #[test]
  fn u64_to_bignedian_u8array() {
    let n: u64 = 0xFA01C67322E498A2;
    let n_array = super::u64_to_bigendian_u8array(n);
    assert_eq!(0xFA, n_array[0]);
    assert_eq!(0x01, n_array[1]);
    assert_eq!(0xC6, n_array[2]);
    assert_eq!(0x73, n_array[3]);
    assert_eq!(0x22, n_array[4]);
    assert_eq!(0xE4, n_array[5]);
    assert_eq!(0x98, n_array[6]);
    assert_eq!(0xA2, n_array[7]);
  }

  #[test]
  fn u8_bigendian_slice_to_u64() {
    let array = [0xFA as u8, 0x01 as u8, 0xC6 as u8, 0x73 as u8, 0x22, 0xE4, 0x98, 0xA2];
    let n = super::u8_bigendian_slice_to_u64(&array);
    assert_eq!(0xFA01C67322E498A2, n);
  }

  #[test]
  fn min_greater_equal_power_of_two() {
    assert_eq!(16, super::min_greater_equal_power_of_two(16));
    assert_eq!(16, super::min_greater_equal_power_of_two(15));
    assert_eq!(16, super::min_greater_equal_power_of_two(9));
    assert_eq!(8, super::min_greater_equal_power_of_two(8));
    assert_eq!(8, super::min_greater_equal_power_of_two(6));
    assert_eq!(8, super::min_greater_equal_power_of_two(5));
    assert_eq!(4, super::min_greater_equal_power_of_two(4));
    assert_eq!(4, super::min_greater_equal_power_of_two(3));
    assert_eq!(2, super::min_greater_equal_power_of_two(2));
    assert_eq!(1, super::min_greater_equal_power_of_two(1));
    assert_eq!(0, super::min_greater_equal_power_of_two(0));
  }

  #[test]
  fn u64_to_u32_pair() {
    assert_eq!((32, 0), super::u64_to_u32_pair(32u64));
    assert_eq!((0xFFFFFFFF, 0xFFFFFFFF),
               super::u64_to_u32_pair(0xFFFFFFFFFFFFFFFFu64));
    assert_eq!((0, 0xFFFFFFFF),
               super::u64_to_u32_pair(0xFFFFFFFF00000000u64));
  }
}
