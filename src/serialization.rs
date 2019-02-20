use bulletproofs::{RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use schnorr::SecretKey;

// preferred approach for handling of fields of types that don't provide correct default serde serialize/deserialize

pub trait ZeiFromToBytes {
    fn zei_to_bytes(&self) -> Vec<u8>;
    fn zei_from_bytes(bytes: &[u8]) -> Self;
}

impl ZeiFromToBytes for SecretKey{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> SecretKey{
        SecretKey::from_bytes(bytes).unwrap()
    }
}

impl ZeiFromToBytes for Scalar{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> Scalar{
        let mut bits = [0u8; 32];
        bits.copy_from_slice(bytes);
        Scalar::from_bits(bits)
    }
}

impl ZeiFromToBytes for CompressedRistretto{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> CompressedRistretto{
        CompressedRistretto::from_slice(bytes)
    }
}

impl ZeiFromToBytes for RangeProof{
    fn zei_to_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend_from_slice(&self.to_bytes()[..]);
        v
    }
    fn zei_from_bytes(bytes: &[u8]) -> RangeProof{
        RangeProof::from_bytes(bytes).unwrap()
    }
}

pub mod keypair {
    use schnorr::Keypair;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(kp: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = kp.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
    where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let keypair = Keypair::from_bytes(bytes).map_err(de::Error::custom)?;
        Ok(keypair)
    }
}

pub mod public_key {
    use schnorr::PublicKey;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = pk.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
        where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let public_key = PublicKey::from_bytes(bytes).map_err(de::Error::custom)?;
        Ok(public_key)
    }
}

pub mod secret_key {
    use schnorr::SecretKey;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(sk: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = sk.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
        where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let secret_key = SecretKey::from_bytes(bytes).map_err(de::Error::custom)?;
        Ok(secret_key)
    }
}

pub mod scalar {
    use curve25519_dalek::scalar::Scalar;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(sc: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = sc.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Scalar::from_bits(array))
    }
}

pub mod compressed_ristretto {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(cr: &CompressedRistretto, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer,
    {
        let bytes = cr.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<CompressedRistretto, D::Error>
    where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let ristretto = CompressedRistretto::from_slice(bytes);
        Ok(ristretto)
    }
}

pub mod range_proof{
    use bulletproofs::RangeProof;
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    pub fn serialize<S>(cr: &RangeProof, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer,
    {
        let bytes = cr.to_bytes();
        let encoded = hex::encode(&bytes[..]);
        serializer.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<RangeProof, D::Error>
        where D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let vector = hex::decode(s).map_err(de::Error::custom)?;
        let bytes = vector.as_slice();
        let range_proof = RangeProof::from_bytes(bytes).
            map_err(de::Error::custom)?;
        Ok(range_proof)
    }
}

pub mod option_bytes {
    use serde::{self, de, Deserialize, Serializer, Deserializer};
    use crate::serialization::ZeiFromToBytes;

    pub fn serialize<S,T>(object: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer, T: ZeiFromToBytes,
    {
        if object.is_none() {
            serializer.serialize_none()
        }
        else {
            let bytes = object.as_ref().unwrap().zei_to_bytes();
            let encoded = hex::encode(&bytes[..]);
            serializer.serialize_str(&encoded)
        }
    }
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
        where D: Deserializer<'de>, T: ZeiFromToBytes,
    {

        let s: Option<String> = Option::deserialize(deserializer)?;

        if s.is_some() {
            let vector = hex::decode(s.unwrap()).map_err(de::Error::custom)?;
            let object = T::zei_from_bytes(&vector.as_slice());
            Ok(Some(object))
        }
        else {
            Ok(None)
        }
    }
}


#[cfg(test)]
mod test {
    //use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    //use curve25519_dalek::ristretto::CompressedRistretto;
    //use curve25519_dalek::ristretto::RistrettoPoint;
    use crate::account::Account;


    /*
    #[test]
    pub fn serialization_compressed_ristretto(){
        let mut csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let point = RistrettoPoint::random(&mut csprng1).compress();
        let serialized = serde_json::to_string(&point).unwrap();
        let deserialized: CompressedRistretto = serde_json::from_str(&serialized).unwrap();
        assert_eq!(point,deserialized);
    }
    */
    #[test]
    pub fn test_account_to_json() {
        let mut csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let mut csprng2 = ChaChaRng::from_seed([0u8; 32]);
        let mut acc_old = Account::new(&mut csprng1);
        let asset_id = "default currency";
        acc_old.add_asset(&mut csprng1, asset_id, false, 50);
        acc_old.add_asset(&mut csprng1, "another currency", true, 50);

        let mut acc = Account::new(&mut csprng2);
        acc.add_asset(&mut csprng2, asset_id, false, 50);
        acc.add_asset(&mut csprng2, "another currency", true, 50);

        let json = serde_json::to_string(&acc_old).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().tx_counter, acc.balances.get("default currency").unwrap().tx_counter);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance, acc.balances.get("default currency").unwrap().balance);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance_commitment, acc.balances.get("default currency").unwrap().balance_commitment);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().balance_blinding, acc.balances.get("default currency").unwrap().balance_blinding);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_commitment, acc.balances.get("default currency").unwrap().asset_commitment);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_blinding, acc.balances.get("default currency").unwrap().asset_blinding);
        assert_eq!(acc_deserialized.balances.get("default currency").unwrap().asset_info.id, acc.balances.get("default currency").unwrap().asset_info.id);

        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().tx_counter, acc.balances.get("another currency").unwrap().tx_counter);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance, acc.balances.get("another currency").unwrap().balance);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance_commitment, acc.balances.get("another currency").unwrap().balance_commitment);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().balance_blinding, acc.balances.get("another currency").unwrap().balance_blinding);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_commitment, acc.balances.get("another currency").unwrap().asset_commitment);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_blinding, acc.balances.get("another currency").unwrap().asset_blinding);
        assert_eq!(acc_deserialized.balances.get("another currency").unwrap().asset_info.id, acc.balances.get("another currency").unwrap().asset_info.id);
    }
    #[test]
    pub fn test_empty_account() {
        let acc = Account::new(&mut ChaChaRng::from_seed([0u8; 32]));
        let json = serde_json::to_string(&acc).unwrap();

        let acc_deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());
    }
}
