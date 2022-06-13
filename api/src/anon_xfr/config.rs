use crate::xfr::structs::{AssetType, ASSET_TYPE_LENGTH};

const ASSET_TYPE_FRA: AssetType = AssetType([0; ASSET_TYPE_LENGTH]);
pub const FEE_TYPE: AssetType = ASSET_TYPE_FRA;
