use crate::xfr::{
    sig::{XfrPublicKey, XfrSecretKey, XfrSignature},
    structs::{AssetType, ASSET_TYPE_LENGTH},
};
use serde::Serializer;
use zei_algebra::prelude::*;

impl ZeiFromToBytes for AssetType {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ASSET_TYPE_LENGTH {
            Err(eg!(ZeiError::DeserializationError))
        } else {
            let mut array = [0u8; ASSET_TYPE_LENGTH];
            array.copy_from_slice(bytes);
            Ok(AssetType(array))
        }
    }
}

impl ZeiFromToBytes for XfrPublicKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        XfrPublicKey::from_bytes(bytes)
    }
}
serialize_deserialize!(XfrPublicKey);

impl ZeiFromToBytes for XfrSecretKey {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        XfrSecretKey::from_bytes(bytes)
    }
}

serialize_deserialize!(XfrSecretKey);

impl ZeiFromToBytes for XfrSignature {
    fn zei_to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn zei_from_bytes(bytes: &[u8]) -> Result<Self> {
        XfrSignature::from_bytes(bytes)
    }
}

serialize_deserialize!(XfrSignature);

#[cfg(test)]
mod test {
    use crate::anon_xfr::keys::{AXfrKeyPair, AXfrPubKey};
    use crate::ristretto::CompressedRistretto;
    use crate::serialization::ZeiFromToBytes;
    use crate::xfr::sig::XfrPublicKeyInner;
    use crate::xfr::{
        asset_tracer::RecordDataEncKey,
        sig::{XfrKeyPair, XfrPublicKey, XfrSecretKey, XfrSignature},
        structs::{BlindAssetRecord, OpenAssetRecord, XfrAmount, XfrAssetType},
    };
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    use rmp_serde::{Deserializer, Serializer};
    use ruc::*;
    use serde::{de::Deserialize, ser::Serialize};
    use std::convert::TryFrom;
    use zei_algebra::ristretto::RistrettoPoint;
    use zei_crypto::basic::{
        elgamal::elgamal_key_gen,
        hybrid_encryption::{XPublicKey, XSecretKey},
    };

    #[test]
    fn xfr_amount_u64_to_string_serde() {
        let amt = XfrAmount::NonConfidential(1844674407370955161);
        let actual_to_string_res = serde_json::to_string(&amt).unwrap();
        let expected_to_string_res = r##"{"NonConfidential":"1844674407370955161"}"##;
        assert_eq!(actual_to_string_res, expected_to_string_res);
    }

    #[test]
    fn xfr_amount_u64_from_string_serde() {
        let serialized_str = r##"{"NonConfidential":"1844674407370955161"}"##;
        let actual_amt: XfrAmount = serde_json::from_str::<XfrAmount>(&serialized_str).unwrap();

        let val = 1844674407370955161;
        let expected_amt = XfrAmount::NonConfidential(val);
        assert_eq!(expected_amt.get_amount(), actual_amt.get_amount());
    }

    #[test]
    fn oar_amount_u64_to_string_serde() {
        use curve25519_dalek::ristretto::CompressedRistretto as CR;
        let default_cr =
            CompressedRistretto(CR(<[u8; 32]>::try_from(vec![0_u8; 32].as_slice()).unwrap()));
        let blind_amount = XfrAmount::Confidential((default_cr, default_cr));
        let blind_type = XfrAssetType::Confidential(default_cr);
        let amt = 1844674407370955161;
        let oar = OpenAssetRecord {
            blind_asset_record: BlindAssetRecord {
                amount: blind_amount,
                asset_type: blind_type,
                public_key: XfrPublicKey(XfrPublicKeyInner::Ed25519(Default::default())),
            },
            amount: amt,
            amount_blinds: (Default::default(), Default::default()),
            asset_type: Default::default(),
            type_blind: Default::default(),
        };
        let actual_to_string_res = serde_json::to_string(&oar).unwrap();
        let expected_to_string_res = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
        assert_eq!(actual_to_string_res, expected_to_string_res);
    }

    #[test]
    fn oar_amount_u64_from_compatible_string_serde() {
        let serialized_str = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
        let oar: OpenAssetRecord =
            serde_json::from_str::<OpenAssetRecord>(&serialized_str).unwrap();
        let val = 1844674407370955161_u64;
        assert_eq!(val, *oar.get_amount());
    }

    #[test]
    fn oar_amount_u64_from_string_serde() {
        let serialized_str = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
        let oar: OpenAssetRecord =
            serde_json::from_str::<OpenAssetRecord>(&serialized_str).unwrap();
        let val = 1844674407370955161_u64;
        assert_eq!(val, *oar.get_amount());
    }

    #[test]
    fn anon_xfr_pub_key_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = AXfrKeyPair::generate(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .get_public_key()
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: AXfrPubKey = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair.get_public_key(), pk2);

        let mut keypair_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .serialize(&mut Serializer::new(&mut keypair_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&keypair_mp_vec[..]);
        let keypair_2: AXfrKeyPair = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair, keypair_2);
    }

    #[test]
    fn public_key_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .pub_key
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: XfrPublicKey = Deserialize::deserialize(&mut de).unwrap();

        assert_eq!(&keypair.pub_key, &pk2);
    }

    #[test]
    fn x25519_public_key_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let sk = XSecretKey::new(&mut prng);
        let pk = XPublicKey::from(&sk);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            pk.serialize(&mut Serializer::new(&mut pk_mp_vec)).is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: XPublicKey = Deserialize::deserialize(&mut de).unwrap();

        assert_eq!(&pk, &pk2);
    }

    #[test]
    fn signature_message_pack_serialization() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);
        let message = [10u8; 55];

        let signature = keypair.sign(&message).unwrap();

        let mut vec = vec![];
        assert_eq!(
            true,
            signature.serialize(&mut Serializer::new(&mut vec)).is_ok()
        );

        let mut de = Deserializer::new(&vec[..]);
        let signature2 = XfrSignature::deserialize(&mut de).unwrap();

        assert_eq!(signature, signature2);
    }

    #[derive(Serialize, Deserialize)]
    struct StructWithPubKey {
        key: XfrPublicKey,
    }

    #[derive(Serialize, Deserialize)]
    struct StructWithSecKey {
        key: XfrSecretKey,
    }

    #[test]
    fn serialize_and_deserialize_as_json() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let keypair = XfrKeyPair::generate(&mut prng);
        let test_struct = StructWithPubKey {
            key: keypair.pub_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize XfrPublicKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithPubKey>(&as_json) {
            assert_eq!(test_struct.key, restored.key);
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrPublicKey from JSON")));
        }

        let test_struct = StructWithSecKey {
            key: keypair.sec_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize XfrSecretKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithSecKey>(&as_json) {
            assert_eq!(test_struct.key.zei_to_bytes(), restored.key.zei_to_bytes());
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrSecretKey from JSON")));
        }
    }

    #[test]
    fn serialize_and_deserialize_elgamal() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let (_sk, xfr_pub_key) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng);
        let serialized = if let Ok(res) = serde_json::to_string(&xfr_pub_key) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize Elgamal public key")))
        };
        if let Ok(restored) = serde_json::from_str::<RecordDataEncKey>(&serialized) {
            assert_eq!(xfr_pub_key, restored);
        } else {
            pnk!(Err(eg!("Failed to deserialize XfrPublicKey from JSON")));
        }
    }
}
