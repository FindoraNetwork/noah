use crate::{
    keys::{KeyPair, PublicKey, SecretKey, Signature},
    xfr::structs::{AssetType, ASSET_TYPE_LENGTH},
};
use noah_algebra::prelude::*;
use serde::Serializer;

impl NoahFromToBytes for AssetType {
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ASSET_TYPE_LENGTH {
            Err(eg!(NoahError::DeserializationError))
        } else {
            let mut array = [0u8; ASSET_TYPE_LENGTH];
            array.copy_from_slice(bytes);
            Ok(AssetType(array))
        }
    }
}

serialize_deserialize!(SecretKey);

serialize_deserialize!(PublicKey);

serialize_deserialize!(KeyPair);

serialize_deserialize!(Signature);

#[cfg(test)]
mod test {
    use crate::keys::{KeyPair, PublicKey, PublicKeyInner, SecretKey, Signature};
    use crate::ristretto::CompressedRistretto;
    use crate::serialization::NoahFromToBytes;
    use crate::xfr::{
        asset_tracer::RecordDataEncKey,
        structs::{BlindAssetRecord, OpenAssetRecord, XfrAmount, XfrAssetType},
    };
    use noah_algebra::{prelude::*, ristretto::RistrettoPoint};
    use noah_crypto::basic::{
        elgamal::elgamal_key_gen,
        hybrid_encryption::{XPublicKey, XSecretKey},
    };
    use rmp_serde::{Deserializer, Serializer};
    use serde::{de::Deserialize, ser::Serialize};
    use std::convert::TryFrom;

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
                public_key: PublicKey(PublicKeyInner::Ed25519(Default::default())),
            },
            amount: amt,
            amount_blinds: (Default::default(), Default::default()),
            asset_type: Default::default(),
            type_blind: Default::default(),
        };
        let actual_to_string_res = serde_json::to_string(&oar).unwrap();
        let expected_to_string_res = r##"{"blind_asset_record":{"amount":{"Confidential":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},"asset_type":{"Confidential":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"amount":"1844674407370955161","amount_blinds":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"asset_type":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"type_blind":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"##;
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
        let mut prng = test_rng();
        let keypair = KeyPair::generate_secp256k1(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .get_pk()
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: PublicKey = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair.get_pk(), pk2);

        let mut keypair_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .serialize(&mut Serializer::new(&mut keypair_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&keypair_mp_vec[..]);
        let keypair_2: KeyPair = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(keypair, keypair_2);
    }

    #[test]
    fn public_key_message_pack_serialization() {
        let mut prng = test_rng();
        let keypair = KeyPair::generate_secp256k1(&mut prng);

        let mut pk_mp_vec = vec![];
        assert_eq!(
            true,
            keypair
                .pub_key
                .serialize(&mut Serializer::new(&mut pk_mp_vec))
                .is_ok()
        );
        let mut de = Deserializer::new(&pk_mp_vec[..]);
        let pk2: PublicKey = Deserialize::deserialize(&mut de).unwrap();

        assert_eq!(&keypair.pub_key, &pk2);
    }

    #[test]
    fn x25519_public_key_message_pack_serialization() {
        let mut prng = test_rng();
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
        let mut prng = test_rng();
        let keypair = KeyPair::generate_secp256k1(&mut prng);
        let message = [10u8; 55];

        let signature = keypair.sign(&message).unwrap();

        let mut vec = vec![];
        assert_eq!(
            true,
            signature.serialize(&mut Serializer::new(&mut vec)).is_ok()
        );

        let mut de = Deserializer::new(&vec[..]);
        let signature2 = Signature::deserialize(&mut de).unwrap();

        assert_eq!(signature, signature2);
    }

    #[derive(Serialize, Deserialize)]
    struct StructWithPubKey {
        key: PublicKey,
    }

    #[derive(Serialize, Deserialize)]
    struct StructWithSecKey {
        key: SecretKey,
    }

    #[test]
    fn serialize_and_deserialize_as_json() {
        let mut prng = test_rng();
        let keypair = KeyPair::generate_secp256k1(&mut prng);
        let test_struct = StructWithPubKey {
            key: keypair.pub_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize PublicKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithPubKey>(&as_json) {
            assert_eq!(test_struct.key, restored.key);
        } else {
            pnk!(Err(eg!("Failed to deserialize PublicKey from JSON")));
        }

        let test_struct = StructWithSecKey {
            key: keypair.sec_key,
        };
        let as_json = if let Ok(res) = serde_json::to_string(&test_struct) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize SecretKey to JSON")))
        };
        if let Ok(restored) = serde_json::from_str::<StructWithSecKey>(&as_json) {
            assert_eq!(
                test_struct.key.noah_to_bytes(),
                restored.key.noah_to_bytes()
            );
        } else {
            pnk!(Err(eg!("Failed to deserialize SecretKey from JSON")));
        }
    }

    #[test]
    fn serialize_and_deserialize_elgamal() {
        let mut prng = test_rng();
        let (_sk, xfr_pub_key) = elgamal_key_gen::<_, RistrettoPoint>(&mut prng);
        let serialized = if let Ok(res) = serde_json::to_string(&xfr_pub_key) {
            res
        } else {
            pnk!(Err(eg!("Failed to serialize Elgamal public key")))
        };
        if let Ok(restored) = serde_json::from_str::<RecordDataEncKey>(&serialized) {
            assert_eq!(xfr_pub_key, restored);
        } else {
            pnk!(Err(eg!("Failed to deserialize PublicKey from JSON")));
        }
    }
}
