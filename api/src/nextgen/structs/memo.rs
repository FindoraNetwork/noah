use noah_algebra::baby_jubjub::BabyJubjubPoint;
use noah_algebra::bn254::{BN254Scalar, BN254_SCALAR_LEN};
use noah_algebra::prelude::*;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Compute the expected number of BLS scalar elements in the memo ciphertext.
///
/// Note that the memo ciphertext consists of other information, such as:
/// - The Diffie-Hellman key exchange group element, r * G
/// - A fast-detection element
///
/// So it would consist of more elements than what we show here.
///
pub fn get_auditor_memo_length(num_inputs: usize, num_outputs: usize) -> usize {
    // Every transaction has at most one audited asset, which means that there
    // is also at most one auditor.
    //
    // The auditor will be presented all the input and output information.
    //
    // The memo first includes the sender address (3 BLS scalar elements).
    //
    // Note that, similar to anon_xfr, we prefer to consolidate assets into
    // a few addresses, and therefore, we also restrict all the inputs to
    // have the same owner (same public key).
    //
    // For each input, the memo includes:
    // - the coin commitment, which enables back-tracing.
    // - the amount
    // - the asset type (all not assets have to be the audited one)
    //
    // For each output, the memo includes:
    // - the amount
    // - the asset type
    // - the receiving address (it takes 3 BLS scalar elements)
    // - the randomizer
    //
    // Finally, there is one element for zk-ID

    3 + num_inputs * (1 + 1 + 1) + num_outputs * (1 + 1 + 3 + 1) + 1
}

/// A struct for the auditor's memo.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct NabarAuditorMemo {
    /// The Diffie-Hellman key exchange group element.
    ///
    /// Note: we explicitly stress that this point is often uncompressed and unchecked,
    /// and the application should take the responsibility to make application-specific checks.
    pub dh_point_unchecked: BabyJubjubPoint,
    /// The fast-detection element.
    pub fast_detection: BN254Scalar,
    /// The body of the memo.
    pub body: Vec<BN254Scalar>,
}

impl Serialize for NabarAuditorMemo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::<u8>::new();

        // We overwrite the serialization algorithm to avoid the need of recovering the point.
        bytes.extend_from_slice(&self.dh_point_unchecked.to_unchecked_bytes());
        bytes.extend_from_slice(&self.fast_detection.noah_to_bytes());

        for elem in self.body.iter() {
            bytes.extend_from_slice(&elem.noah_to_bytes());
        }

        if serializer.is_human_readable() {
            serializer.serialize_str(&b64enc(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for NabarAuditorMemo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(noah_obj_serde::BytesVisitor)?
        } else {
            deserializer.deserialize_bytes(noah_obj_serde::BytesVisitor)?
        };

        let dh_point_unchecked =
            BabyJubjubPoint::from_unchecked_bytes(&bytes[0..64]).map_err(SerdeError::custom)?;

        let fast_detection =
            BN254Scalar::noah_from_bytes(&bytes[64..96]).map_err(SerdeError::custom)?;

        let remaining_bytes = bytes.len() - 96;
        if remaining_bytes % BN254_SCALAR_LEN != 0 {
            return Err(SerdeError::custom(
                "The auditor memo does not have the correct length.",
            ));
        }

        let mut body = Vec::with_capacity(remaining_bytes / BN254_SCALAR_LEN);
        for elem_bytes in bytes[96..].chunks_exact(96) {
            let res = BN254Scalar::noah_from_bytes(elem_bytes).map_err(SerdeError::custom)?;

            body.push(res);
        }

        Ok(Self {
            dh_point_unchecked,
            fast_detection,
            body,
        })
    }
}
