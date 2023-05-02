use crate::xfr::structs::AssetType;
use noah_algebra::{
    bls12_381::{BLSScalar, BLS12_381_SCALAR_LEN},
    jubjub::{JubjubPoint, JubjubScalar},
    prelude::*,
};
use noah_crypto::basic::anemoi_jive::{AnemoiJive, AnemoiJive381};
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod memo;
pub use memo::*;

/// On-chain disclosure for a new asset that has the auditability.
///
/// Note: this asset is not limited to Nextgen assets. To enforce the auditability,
/// the enforcement must propagate all the ways to transparent, Maxwell, and Zerocash assets.
/// - Maxwell assets and Zerocash assets are completely suspended for auditable assets.
///   Transactions that include auditable assets in ops that involve Maxwell or Zerocash will fail.
/// - This is done by having the consensus to remember a list of all auditable assets.
///
/// The disclosure performs three things:
/// - declare that an asset code represents an auditable asset
///     (which would be verified for consistency on the platform side).
/// - provide the randomness and the signature verifying key for the auditor.
/// - provide a number of signed encryption key.
///
/// A transaction fee shall be charged for on-chain disclosure.
///
/// This is planned to be submitted from the EVM side.
///
pub struct NabarAuditableAssetIssuance {
    /// The asset type code after remapping.
    /// We expect all auditable assets be issued on the EVM side.
    pub remapped_asset_type: AssetType,
    /// The signature verifying key, which is a point on the Jubjub curve.
    ///
    /// However, note that the Jubjub curve has cofactor 8.
    /// Checking if the point is in the correct subgroup is cumbersome.
    ///
    /// Therefore, we choose a separate way of implementation.
    /// The issuance request should use sign_vk divided by 8.
    /// This allows the other party to get the actual point by simply
    /// multiplying by 8 (i.e., doubling three times).
    pub sign_vk_div_by_cofactor: JubjubPoint,
    /// A list of encryption keys to be authorized.
    pub enc_ek: Vec<NabarAuditEncryptionKey>,
    /// A list of signatures for such authorization.
    pub enc_sign: Vec<NabarMasterSignature>,
}

impl NabarAuditableAssetIssuance {
    /// Compute the actual, reconstructed signature verifying key.
    pub fn get_sign_vk(&self) -> NabarMasterPublicKey {
        NabarMasterPublicKey(self.sign_vk_div_by_cofactor.double().double().double())
    }
}
