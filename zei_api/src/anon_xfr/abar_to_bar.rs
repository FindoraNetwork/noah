use std::ptr::null;
use crate::anon_xfr::{bar_to_from_abar::TWO_POW_32, keys::{AXfrKeyPair, AXfrSignature}, nullifier, proofs::{prove_eq_committed_vals, verify_eq_committed_vals, AXfrPlonkPf}, structs::{AnonBlindAssetRecord, OpenAnonBlindAssetRecord}};
use crate::setup::{NodeParams, UserParams};
use crate::xfr::{
    asset_record::{
        build_open_asset_record,
        AssetRecordType::NonConfidentialAmount_NonConfidentialAssetType,
    },
    sig::XfrPublicKey,
    structs::{
        AssetRecordTemplate, BlindAssetRecord, OpenAssetRecord, XfrAmount, XfrAssetType,
    },
};
use algebra::{
    bls12_381::BLSScalar,
    groups::{GroupArithmetic, Scalar, ScalarArithmetic, Zero},
    jubjub::{JubjubPoint, JubjubScalar},
    ristretto::{RistrettoPoint, RistrettoScalar},
};
use crypto::{
    basics::commitments::pedersen::PedersenGens,
    pc_eq_groups::{prove_pair_to_vector_pc, Proof as PCEqProof},
};
use merlin::Transcript;
use rand_chacha::rand_core::{CryptoRng, RngCore};
use ruc::*;
use utils::errors::ZeiError;

/*
       Conversion Proof
*/
/// ConvertAbarBarProof is a struct to hold various aspects of a ZKP to prove equality, spendability
/// and conversion of an ABAR to a BAR on the chain.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct ConvertAbarBarProof {
    commitment_amount_asset_type: JubjubPoint,
    commitment_eq_proof: PCEqProof<RistrettoPoint, JubjubPoint>,
    pc_rescue_commitments_eq_proof: AXfrPlonkPf,
}

/// abar_to_bar functions generates the new BAR and the proof given the Open ABAR and the receiver
/// public key.
#[allow(dead_code)]
pub(crate) fn abar_to_bar<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    oabar: &OpenAnonBlindAssetRecord,
    bar_pubkey: &XfrPublicKey,
) -> Result<(OpenAssetRecord, ConvertAbarBarProof)> {
    let asset_type_scalar: JubjubScalar = oabar.asset_type.as_scalar();
    let blind = JubjubScalar::random(prng);
    let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);
    let pc_gens_ristretto =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());

    let art = AssetRecordTemplate::with_no_asset_tracing(
        oabar.amount,
        oabar.asset_type,
        NonConfidentialAmount_NonConfidentialAssetType,
        *bar_pubkey,
    );
    let (obar, _, _) =
        build_open_asset_record(prng, &pc_gens_ristretto.clone().into(), &art, vec![]);

    // 1. commitments
    let commitment_amount_asset_type = pc_gens_jubjub
        .commit(
            &[JubjubScalar::from_u64(obar.amount), asset_type_scalar],
            &blind,
        )
        .c(d!())?;

    let ristretto_amount_blind = obar.amount_blinds.0.add(
        &obar
            .amount_blinds
            .1
            .mul(&RistrettoScalar::from_u64(TWO_POW_32)),
    );

    // 2. compute proof of equality of commitments
    let mut transcript = Transcript::new(b"Commitment Equality Proof");
    let commitment_eq_proof = prove_pair_to_vector_pc(
        prng,
        &mut transcript,
        (&obar.amount.to_le_bytes(), &asset_type_scalar.to_bytes()),
        (&ristretto_amount_blind, &obar.type_blind),
        &blind,
        &pc_gens_ristretto,
        &pc_gens_jubjub,
    )
    .c(d!())?;

    let pc_rescue_commitments_eq_proof = prove_eq_committed_vals(
        prng,
        params,
        BLSScalar::from_u64(obar.amount),
        BLSScalar::from(&asset_type_scalar),
        BLSScalar::from(&blind),
        oabar.blind,
        &pc_gens_jubjub,
    )
    .c(d!())?;

    Ok((
        obar,
        ConvertAbarBarProof {
            commitment_amount_asset_type,
            commitment_eq_proof,
            pc_rescue_commitments_eq_proof,
        },
    ))
}

/// Verifies the proof with the input and output
#[allow(dead_code)]
pub fn verify_abar_to_bar(
    params: &NodeParams,
    abar: &AnonBlindAssetRecord,
    bar: &BlindAssetRecord,
    proof: &ConvertAbarBarProof,
) -> Result<()> {
    let pc_gens_rist =
        PedersenGens::<RistrettoPoint>::from(bulletproofs::PedersenGens::default());
    let pc_gens_jubjub = PedersenGens::<JubjubPoint>::new(2);

    // 1. get commitments
    // 1.1 reconstruct total amount commitment from bar object
    let (com_low, com_high) = match bar.amount {
        XfrAmount::Confidential((low, high)) => (
            low.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
            high.decompress()
                .ok_or(ZeiError::DecompressElementError)
                .c(d!())?,
        ),
        XfrAmount::NonConfidential(amount) => {
            // fake commitment
            let (l, h) = utils::u64_to_u32_pair(amount);
            (
                pc_gens_rist
                    .commit(&[RistrettoScalar::from_u32(l)], &RistrettoScalar::zero())
                    .c(d!())?,
                pc_gens_rist
                    .commit(&[RistrettoScalar::from_u32(h)], &RistrettoScalar::zero())
                    .c(d!())?,
            )
        }
    };

    // 1.2 get asset type commitment
    let com_amount = com_low.add(&com_high.mul(&RistrettoScalar::from_u64(TWO_POW_32)));
    let com_asset_type = match bar.asset_type {
        XfrAssetType::Confidential(a) => a
            .decompress()
            .ok_or(ZeiError::DecompressElementError)
            .c(d!())?,
        XfrAssetType::NonConfidential(a) => {
            // fake commitment
            pc_gens_rist
                .commit(&[a.as_scalar()], &RistrettoScalar::zero())
                .c(d!())?
        }
    };

    // 1.3 get vector commitment of amount and asset type over jubjub pedersen generators
    let com_amount_asset_type = &proof.commitment_amount_asset_type;

    // 2. verify equality of commited values
    let mut transcript = Transcript::new(b"Commitment Equality Proof");
    crypto::pc_eq_groups::verify_pair_to_vector_pc(
        &mut transcript,
        (&com_amount, &com_asset_type),
        com_amount_asset_type,
        &pc_gens_rist,
        &pc_gens_jubjub,
        &proof.commitment_eq_proof,
    )
    .c(d!())?;

    // 3. verify PLONK proof
    verify_eq_committed_vals(
        params,
        abar.amount_type_commitment,
        com_amount_asset_type,
        &proof.pc_rescue_commitments_eq_proof,
    )
    .c(d!())
}

/*
       Conversion Body
*/
/// AbarToBarBody has the input, the output and the proof related to the conversion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbarToBarBody {
    /// ABAR being spent
    pub input: AnonBlindAssetRecord,
    /// nullifier for signing key
    pub nullifier: BLSScalar,
    /// The new BAR to be created
    pub output: BlindAssetRecord,
    /// The ZKP for the conversion
    pub proof: ConvertAbarBarProof,
}

/// This function generates the AbarToBarBody from the Open ABAR, the receiver address and the signing
/// key pair.
#[allow(dead_code)]
pub fn gen_abar_to_bar_body<R: CryptoRng + RngCore>(
    prng: &mut R,
    input_keypair: AXfrKeyPair,
    params: &UserParams,
    uid: u64,
    record: &OpenAnonBlindAssetRecord,
    address: XfrPublicKey,
) -> Result<AbarToBarBody> {
    // build input witness infos
    let (obar, proof) = abar_to_bar(prng, params, record, &address).c(d!())?;

    let nullifier = nullifier(
        &input_keypair,
        record.amount,
        &record.asset_type,
        uid,
    );

    Ok(AbarToBarBody {
        input: AnonBlindAssetRecord::from_oabar(&record),
        nullifier,
        output: obar.blind_asset_record.clone(),
        proof,
    })
}

// Verifies the body
#[allow(dead_code)]
pub fn verify_abar_to_bar_body(params: &NodeParams, body: &AbarToBarBody) -> Result<()> {
    verify_abar_to_bar(params, &body.input, &body.output, &body.proof)
}

/*
       Conversion Note
*/
/// AbarToBarNote holds the data and the signature for ABAR to BAR conversion.
#[derive(Debug, Serialize, Deserialize, Eq, Clone, PartialEq)]
pub struct AbarToBarNote {
    /// All the data related to the conversion
    pub body: AbarToBarBody,
    /// The AXfr Signature for ABAR spending approval
    pub signature: AXfrSignature,
}

/// Generates a conversion note with the input, output, proof and signature.
#[allow(dead_code)]
pub fn gen_abar_to_bar_note<R: CryptoRng + RngCore>(
    prng: &mut R,
    params: &UserParams,
    uid: u64,
    record: &OpenAnonBlindAssetRecord,
    randomizer: JubjubScalar,
    address: XfrPublicKey,
    input_keypair: AXfrKeyPair,
) -> Result<AbarToBarNote> {
    // generate body
    let body = gen_abar_to_bar_body(prng, input_keypair, params, uid, record, address).c(d!())?;

    // serialize and sign
    let msg = bincode::serialize(&body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;
    let signature = input_keypair.randomize(&randomizer).sign(&msg);

    // return note
    let note = AbarToBarNote { body, signature };
    Ok(note)
}

// Verifies the note
#[allow(dead_code)]
pub fn verify_abar_to_bar_note(params: &NodeParams, note: &AbarToBarNote) -> Result<()> {
    let msg = bincode::serialize(&note.body)
        .map_err(|_| ZeiError::SerializationError)
        .c(d!())?;

    note.body
        .input
        .public_key
        .verify(msg.as_slice(), &note.signature)?;

    verify_abar_to_bar_body(params, &note.body)
}

#[cfg(test)]
mod test {
    use crate::anon_xfr::{
        abar_to_bar::{gen_abar_to_bar_note, verify_abar_to_bar_note},
        keys::AXfrKeyPair,
        structs::OpenAnonBlindAssetRecordBuilder,
    };
    use crate::setup::{NodeParams, UserParams};
    use crate::xfr::{
        sig::XfrKeyPair,
        structs::{AssetType, XfrAmount, XfrAssetType::NonConfidential},
    };
    use algebra::groups::Scalar;
    use algebra::jubjub::JubjubScalar;
    use crypto::basics::hybrid_encryption::{XPublicKey, XSecretKey};
    use rand_chacha::{rand_core::SeedableRng, ChaChaRng};

    #[test]
    fn test_abar_to_bar() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let params = UserParams::eq_committed_vals_params();
        let keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        let address = XfrKeyPair::generate(&mut prng).pub_key;

        let oabar = OpenAnonBlindAssetRecordBuilder::new()
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .pub_key(keypair.pub_key())
            .finalize(&mut prng, &enc_key)
            .unwrap()
            .build()
            .unwrap();

        let mut note = gen_abar_to_bar_note(
            &mut prng,
            &params,
            0u64,
            &oabar,
            oabar.key_rand_factor,
            address,
            keypair,
        )
        .unwrap();

        assert_eq!(note.body.output.amount, XfrAmount::NonConfidential(1234u64));
        assert_eq!(
            note.body.output.asset_type,
            NonConfidential(AssetType([0u8; 32]))
        );
        assert_eq!(note.body.output.public_key, address);

        let node_params = NodeParams::from(params);
        let ok = verify_abar_to_bar_note(&node_params, &note);
        assert!(ok.is_ok());

        // verification should fail for a tampered note
        note.body.output.amount = XfrAmount::NonConfidential(8888u64);
        let ok = verify_abar_to_bar_note(&node_params, &note);
        assert!(ok.is_err());
    }

    // verification should fail if wrong randomizer is supplied for signing
    #[test]
    fn test_abar_to_bar_wrong_randomizer() {
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let params = UserParams::eq_committed_vals_params();
        let keypair = AXfrKeyPair::generate(&mut prng);
        let dec_key = XSecretKey::new(&mut prng);
        let enc_key = XPublicKey::from(&dec_key);
        let address = XfrKeyPair::generate(&mut prng).pub_key;

        let oabar = OpenAnonBlindAssetRecordBuilder::new()
            .amount(1234u64)
            .asset_type(AssetType::from_identical_byte(0u8))
            .pub_key(keypair.pub_key())
            .finalize(&mut prng, &enc_key)
            .unwrap()
            .build()
            .unwrap();

        let note = gen_abar_to_bar_note(
            &mut prng,
            &params,
            0u64,
            &oabar,
            JubjubScalar::from_u64(12341234u64),
            address,
            keypair,
        )
        .unwrap();

        assert_eq!(note.body.output.amount, XfrAmount::NonConfidential(1234u64));
        assert_eq!(
            note.body.output.asset_type,
            NonConfidential(AssetType([0u8; 32]))
        );
        assert_eq!(note.body.output.public_key, address);

        let node_params = NodeParams::from(params);
        let ok = verify_abar_to_bar_note(&node_params, &note);
        assert!(ok.is_err());
    }
}
