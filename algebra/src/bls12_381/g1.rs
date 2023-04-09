use crate::bls12_381::{BLSFq, BLSScalar};
use crate::errors::AlgebraError;
use crate::prelude::{derive_prng_from_hash, *};
use ark_bls12_381::{Fq, G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group as ArkGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::fmt::{Debug, Display, Formatter};
use digest::{consts::U64, Digest};
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use {
    ark_ff::{BigInteger, BigInteger384, FpConfig, MontBackend, PrimeField},
    js_sys::{
        Array, Function, Object, Reflect, Uint8Array,
        WebAssembly::{instantiate_buffer, Instance, Memory},
    },
    std::io::Cursor,
    wasm_bindgen::JsCast,
    wasm_bindgen_futures::JsFuture,
};

#[cfg(target_arch = "wasm32")]
const WASM: &[u8] = include_bytes!("./fastmsm.wasm");
#[cfg(target_arch = "wasm32")]
static mut WASM_INSTANCE: Option<Instance> = None;

#[cfg(target_arch = "wasm32")]
/// Init fast msm
pub async fn init_fast_msm_wasm() -> core::result::Result<(), JsValue> {
    unsafe {
        let a: JsValue = JsFuture::from(instantiate_buffer(WASM, &Object::new())).await?;
        WASM_INSTANCE = Some(Reflect::get(&a, &"instance".into())?.dyn_into()?);
    }

    Ok(())
}

/// The wrapped struct for ark_bls12_381::G1Projective
#[wasm_bindgen]
#[derive(Copy, Default, Clone, PartialEq, Eq)]
pub struct BLSG1(pub(crate) G1Projective);

impl Debug for BLSG1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <G1Affine as Display>::fmt(&self.0.into_affine(), f)
    }
}

impl Group for BLSG1 {
    type ScalarType = BLSScalar;
    const COMPRESSED_LEN: usize = 48;

    #[inline]
    fn double(&self) -> Self {
        Self(self.0.double())
    }

    #[inline]
    fn get_identity() -> Self {
        Self(G1Projective::zero())
    }

    #[inline]
    fn get_base() -> Self {
        Self(G1Projective::generator())
    }

    #[inline]
    fn random<R: CryptoRng + RngCore>(prng: &mut R) -> Self {
        Self(G1Projective::rand(prng))
    }

    #[inline]
    fn to_compressed_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::Yes).unwrap();

        buf
    }

    #[inline]
    fn to_unchecked_bytes(&self) -> Vec<u8> {
        let affine = G1Affine::from(self.0);
        let mut buf = Vec::new();
        affine.serialize_with_mode(&mut buf, Compress::No).unwrap();

        buf
    }

    #[inline]
    fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn from_unchecked_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = ark_std::io::BufReader::new(bytes);

        let affine = G1Affine::deserialize_with_mode(&mut reader, Compress::No, Validate::No);

        if affine.is_ok() {
            Ok(Self(G1Projective::from(affine.unwrap()))) // safe unwrap
        } else {
            Err(eg!(AlgebraError::DeserializationError))
        }
    }

    #[inline]
    fn unchecked_size() -> usize {
        G1Affine::default().serialized_size(Compress::No)
    }

    #[inline]
    fn from_hash<D>(hash: D) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut prng = derive_prng_from_hash::<D>(hash);
        Self(G1Projective::rand(&mut prng))
    }

    #[inline]
    #[cfg(not(target_arch = "wasm32"))]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        use ark_ec::VariableBaseMSM;

        let scalars_raw: Vec<_> = scalars.iter().map(|r| r.0).collect();
        let points_raw = G1Projective::normalize_batch(
            &points.iter().map(|r| r.0).collect::<Vec<G1Projective>>(),
        );

        Self(G1Projective::msm(&points_raw, scalars_raw.as_ref()).unwrap())
    }

    #[inline]
    #[cfg(target_arch = "wasm32")]
    fn multi_exp(scalars: &[&Self::ScalarType], points: &[&Self]) -> Self {
        let r: Vec<u8>;

        // unsafe here is alright because WASM is single threaded
        unsafe {
            let c = WASM_INSTANCE
                .clone()
                .expect("FastMSM WASM not initialized")
                .exports();

            let scalars_and_points_iter = scalars.iter().zip(points).filter(|(s, _)| s.is_zero());

            let scalars_vec: Vec<_> = scalars_and_points_iter.clone().map(|(r, _)| r.0).collect();
            let points_vec = G1Projective::normalize_batch(
                &scalars_and_points_iter
                    .map(|(_, r)| r.0)
                    .collect::<Vec<G1Projective>>(),
            );

            let size = scalars_vec.len();
            let window_bits = 13;

            macro_rules! load_wasm_func {
                ($a:expr, $b:ty) => {{
                    Reflect::get(c.as_ref(), &$a.into())
                        .unwrap()
                        .dyn_into::<$b>()
                        .expect("$a export wasn't a function")
                }};
            }

            let msm_initialize = load_wasm_func!("msmInitialize", Function);
            let msm_scalars_offset = load_wasm_func!("msmScalarsOffset", Function);
            let msm_points_offset = load_wasm_func!("msmPointsOffset", Function);
            let msm_run = load_wasm_func!("msmRun", Function);

            let size_u32 = size as u32;
            let args = Array::new_with_length(4);
            args.set(0, size_u32.into());
            args.set(1, window_bits.into());
            args.set(2, 1024.into());
            args.set(3, 128.into());
            msm_initialize.apply(&JsValue::undefined(), &args).unwrap();

            let mem: Memory = load_wasm_func!("memory", Memory);
            let buffer = &mem.buffer();

            let scalar_offset: JsValue = msm_scalars_offset.call0(&JsValue::undefined()).unwrap();
            let scalar_mem: Uint8Array = Uint8Array::new_with_byte_offset_and_length(
                &buffer,
                scalar_offset.as_f64().unwrap() as u32,
                size_u32 * 32,
            );

            let mut ptr = 0;
            for scalar in scalars_vec.into_iter() {
                for s in scalar.into_bigint().to_bytes_le() {
                    Uint8Array::set_index(&scalar_mem, ptr, s);
                    ptr += 1;
                }
            }

            let point_offset: JsValue = msm_points_offset.call0(&JsValue::undefined()).unwrap();
            let point_mem: Uint8Array = Uint8Array::new_with_byte_offset_and_length(
                &buffer,
                point_offset.as_f64().unwrap() as u32,
                size_u32 * 96,
            );

            ptr = 0;
            for point in points_vec.into_iter() {
                let affine = G1Affine::from(point);
                for s in affine.x.into_bigint().to_bytes_le() {
                    Uint8Array::set_index(&point_mem, ptr, s);
                    ptr += 1;
                }
                for s in affine.y.into_bigint().to_bytes_le() {
                    Uint8Array::set_index(&point_mem, ptr, s);
                    ptr += 1;
                }
            }

            let result_offset: JsValue = msm_run.call0(&JsValue::undefined()).unwrap();
            let result_mem: Uint8Array = Uint8Array::new_with_byte_offset_and_length(
                &buffer,
                result_offset.as_f64().unwrap() as u32,
                96,
            );

            r = result_mem.to_vec();
        }

        let a1 = r[0..48].to_vec();
        let a2 = r[48..96].to_vec();
        Self::from_xy(BLSFq(fq_from_bytes(a1)), BLSFq(fq_from_bytes(a2)))
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
fn fq_from_bytes(bytes: Vec<u8>) -> Fq {
    let buffer = Cursor::new(bytes.clone());
    let b = BigInteger384::deserialize_uncompressed(buffer).unwrap();
    MontBackend::from_bigint(b).unwrap()
}

impl<'a> Add<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        Self(self.0.add(&rhs.0))
    }
}

impl<'a> Sub<&'a BLSG1> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self(self.0.sub(&rhs.0))
    }
}

impl<'a> Mul<&'a BLSScalar> for BLSG1 {
    type Output = BLSG1;

    #[inline]
    fn mul(self, rhs: &BLSScalar) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl<'a> AddAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn add_assign(&mut self, rhs: &'a BLSG1) {
        self.0.add_assign(&rhs.0)
    }
}

impl<'a> SubAssign<&'a BLSG1> for BLSG1 {
    #[inline]
    fn sub_assign(&mut self, rhs: &'a BLSG1) {
        self.0.sub_assign(&rhs.0)
    }
}

impl<'a> MulAssign<&'a BLSScalar> for BLSG1 {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a BLSScalar) {
        self.0.mul_assign(rhs.0.clone())
    }
}

impl Neg for BLSG1 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl BLSG1 {
    /// Get the x-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_x(&self) -> BLSFq {
        BLSFq(self.0.x)
    }
    /// Get the y-coordinate of the Jubjub affine point.
    #[inline]
    pub fn get_y(&self) -> BLSFq {
        BLSFq(self.0.y)
    }
    /// Construct from the x-coordinate and y-coordinate
    pub fn from_xy(x: BLSFq, y: BLSFq) -> Self {
        if x.is_zero() && y.is_zero() {
            Self(G1Projective::zero())
        } else {
            Self(G1Projective::new(x.0, y.0, Fq::one()))
        }
    }
}
