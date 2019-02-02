use bulletproofs::{RangeProof};
use crate::errors::Error as ZeiError;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use schnorr::{Keypair,PublicKey};
use std::convert::TryFrom;


//serialization of external structures KeyPair, PublicKey, CompressedRistretto, Scalar,
// SecretBox, RangeProofs
#[derive(Serialize, Deserialize, Debug)]
pub struct KeypairString {
    val: String
}

impl TryFrom<KeypairString> for Keypair {
    type Error = ZeiError;
    fn try_from(value: KeypairString) -> Result<Keypair, ZeiError> {
        let vector = hex::decode(&value.val)?;
        let bytes = vector.as_slice();
        let keypair = Keypair::from_bytes(bytes)?;
        Ok(keypair)
    }
}

impl From<&Keypair>  for KeypairString {
    fn from(a: &Keypair) -> KeypairString {
        let bytes = a.to_bytes();
        KeypairString{val: hex::encode(&bytes[..])}
    }
}



#[derive(Serialize, Deserialize, Debug)]
pub struct CompressedRistrettoString {
    val: String
}

impl From<&CompressedRistretto> for CompressedRistrettoString {
    fn from(point: &CompressedRistretto) -> CompressedRistrettoString{
        CompressedRistrettoString{val:hex::encode(point.to_bytes())}
    }
}

impl TryFrom<CompressedRistrettoString> for CompressedRistretto {
    type Error = ZeiError;
    fn try_from(hex_str: CompressedRistrettoString) -> Result<CompressedRistretto, ZeiError>{
        let vector = hex::decode(hex_str.val)?;
        let bytes = vector.as_slice();
        Ok(CompressedRistretto::from_slice(bytes))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ScalarString {
    val: String
}

impl From<Scalar> for ScalarString {
    fn from(scalar: Scalar) -> ScalarString {
        ScalarString {
            val: hex::encode(scalar.to_bytes())
        }
    }
}

impl TryFrom<ScalarString> for Scalar {
    type Error = ZeiError;
    fn try_from(scalar: ScalarString) -> Result<Scalar, ZeiError> {
        let vector = hex::decode(&scalar.val)?;
        let bytes = vector.as_slice();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(Scalar::from_bits(array))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKeyString {
    val: String
}

impl TryFrom<PublicKeyString> for PublicKey {
    type Error = ZeiError;
    fn try_from(a: PublicKeyString) -> Result<PublicKey, ZeiError> {
        let vector = hex::decode(&a.val)?;
        let bytes = vector.as_slice();
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(PublicKey::from_bytes(&array)?)
    }
}

impl From<PublicKey> for PublicKeyString {
    fn from(a: PublicKey) -> PublicKeyString {
        PublicKeyString{val: hex::encode(a.to_bytes())}
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RangeProofString{
    val: Vec<u8>
}

impl TryFrom<RangeProofString> for RangeProof {
    type Error = ZeiError;
    fn try_from(a: RangeProofString) -> Result<RangeProof, ZeiError>{
        Ok(RangeProof::from_bytes(&a.val)?)
    }
}

impl From<&RangeProof> for RangeProofString {
    fn from(a: &RangeProof) -> RangeProofString{
        RangeProofString{val: a.to_bytes()}
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use crate::account::AccountString;
    use crate::account::Account;

    #[test]
    pub fn serialization_compressed_ristretto(){
        let mut csprng1 = ChaChaRng::from_seed([0u8; 32]);
        let point = RistrettoPoint::random(&mut csprng1).compress();
        let id = CompressedRistrettoString::from(&point);
        let serialized = serde_json::to_string(&id).unwrap();
        let deserialized = serde_json::from_str::<CompressedRistrettoString>(&serialized).unwrap();
        let final_deserialized = CompressedRistretto::try_from(deserialized).unwrap();
        assert_eq!(point,final_deserialized);
    }
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

        let acc_str = AccountString::from(&acc_old);

        let json = serde_json::to_string(&acc_str).unwrap();

        let acc_deserialized = Account::try_from(serde_json::from_str::<AccountString>(&json).unwrap()).unwrap();

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
        let acc_str = AccountString::from(&acc);

        let json = serde_json::to_string(&acc_str).unwrap();

        let acc_deserialized = Account::try_from(serde_json::from_str::<AccountString>(&json).unwrap()).unwrap();

        assert_eq!(acc_deserialized.tx_counter, acc.tx_counter);
        assert_eq!(acc_deserialized.keys.public, acc.keys.public);
        assert_eq!(acc_deserialized.keys.secret.to_bytes(), acc.keys.secret.to_bytes());
        assert_eq!(acc_deserialized.balances.len(), acc.balances.len());
    }
}
