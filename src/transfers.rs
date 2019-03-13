use sha2::{Sha512, Digest};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use crate::encryption::ZeiCipher;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{RangeProof, PedersenGens};
use crate::keys::{XfrPublicKey, XfrSignature, XfrKeyPair, XfrSecretKey};
use crate::utils::{u8_bigendian_slice_to_u128, smallest_greater_power_of_two, u8_bigendian_slice_to_u64, u64_to_bigendian_u8array};
use rand::{CryptoRng, Rng};
use crate::setup::{PublicParams, BULLET_PROOF_RANGE};
use crate::proofs::chaum_pedersen::{ChaumPedersenProofX, chaum_pedersen_prove_multiple_eq, chaum_pedersen_verify_multiple_eq};
use crate::errors::Error as ZeiError;
use merlin::Transcript;
use core::borrow::Borrow;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::traits::Identity;
use itertools::Itertools;
use serde::ser::Serialize;


/// I represent a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrNote{
    pub(crate) body: XfrBody,
    pub(crate) multisig: XfrMultiSig,
}

/// I am the body of a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrBody{
    pub(crate) inputs: Vec<BlindAssetRecord>,
    pub(crate) outputs: Vec<BlindAssetRecord>,
    pub(crate) proofs: XfrProofs,
}

////Primitive for multisignatures /////
///A multisignature is defined as a signature on a message that must verify against a list of public keys instead of one
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrMultiSig{
    pub(crate) signatures: Vec<XfrSignature>,
}

fn verify_multisig(keylist: &[XfrPublicKey],
                         message: &[u8],
                         multi_signature: &XfrMultiSig) -> Result<(), ZeiError>
{
    for (pk, signature) in keylist.iter().zip(multi_signature.signatures.iter()){
        pk.verify(message, signature)?;
    }
    Ok(())
}

fn sign_multisig(keylist: &[XfrKeyPair], message: &[u8]) -> XfrMultiSig {
    let mut signatures = vec![];
    for keypair in keylist.iter(){
        let signature = keypair.sign(message);
        signatures.push(signature);
    }
    XfrMultiSig{signatures}
}


/// I represent an Asset Record as presented in the public ledger.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BlindAssetRecord{
    pub(crate) amount: Option<u64>, // None if confidential transfers
    pub(crate) asset_type: Option<[u8;16]>, // None if confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) public_key: XfrPublicKey, // ownership address
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) amount_commitment: Option<CompressedRistretto>, //None if not confidential transfer
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_commitment: Option<CompressedRistretto>, //Noe if not confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) blind_share:  CompressedEdwardsY, // Used by pukey holder to derive blinding factors
    pub(crate) lock_amount: Option<ZeiCipher>,  // If confidential transfer lock the amount to the pubkey in asset_record
    pub(crate) lock_type: Option<ZeiCipher>, // If confidential type lock the type to the public key in asset_record
}

/// I'm a BlindAssetRecors with revealed commitment openings.
pub struct OpenAssetRecord{
    pub(crate) asset_record: BlindAssetRecord, //TODO have a reference here, and lifetime parameter. We will avoid copying info unnecessarily.
    pub(crate) amount: u64,
    pub(crate) amount_blind: Scalar,
    pub(crate) asset_type: [u8;16],
    pub(crate) type_blind: Scalar,
}

/// I'am a plaintext asset record, used to indicate output information when creating a transfer note
pub struct AssetRecord{
    pub(crate) amount: u64,
    pub(crate) asset_type: [u8;16],
    pub(crate) public_key: XfrPublicKey, // ownership address
}

/// I contain the proofs of a transfer note
#[derive(Serialize, Deserialize, Debug)]
pub struct XfrProofs{
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) range_proof: Option<RangeProof>,
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) asset_proof: Option<ChaumPedersenProofX>
}

impl PartialEq for XfrProofs {
    fn eq(&self, other: &XfrProofs) -> bool {
        let mut rp = false;
        if self.range_proof.is_none() && other.range_proof.is_none(){
            rp = true;
        }
        else if self.range_proof.is_some() && other.range_proof.is_some(){
            rp = self.range_proof.as_ref().unwrap().to_bytes() ==
                other.range_proof.as_ref().unwrap().to_bytes()
        }

        rp && self.asset_proof == other.asset_proof
    }
}

impl Eq for XfrProofs {}


/// I Create a XfrNote from list of opened asset records inputs and asset record outputs
pub fn gen_xfr_note<R: CryptoRng + Rng>(
    prng: &mut R,
    inputs: &[OpenAssetRecord],
    outputs: &[AssetRecord],
    input_keys: &[XfrKeyPair],
) -> Result<XfrNote, ZeiError>
{
    let confidential_amount = inputs[0].asset_record.amount.is_none();
    let confidential_asset = inputs[0].asset_record.asset_type.is_none();
    let pc_gens = PedersenGens::default();

    let open_outputs: Vec<OpenAssetRecord> = outputs.iter().
        map(|x| build_open_asset_record(
            prng, &pc_gens,x, confidential_amount, confidential_asset)
        ).collect();

    // do amount handling
    if ! check_amounts(inputs, open_outputs.as_slice()){
        return Err(ZeiError::XfrCreationAmountError);
    }
    let xfr_range_proof = match confidential_amount {
        true => Some(range_proof(inputs, open_outputs.as_slice())?),
        false => None,
    };

    // do asset handling
    if ! check_assets(inputs, open_outputs.as_slice()){
        return Err(ZeiError::XfrCreationAssetError);
    }
    let xfr_asset_proof = match confidential_asset{
        true => Some(asset_proof(prng, &pc_gens, inputs, open_outputs.as_slice())?),
        false => None,
    };

    let mut xfr_inputs = vec![];
    for x in inputs {xfr_inputs.push(x.asset_record.clone())}

    let mut xfr_outputs = vec![];
    for x in open_outputs {xfr_outputs.push(x.asset_record.clone())}

    let xfr_proofs  = XfrProofs{ range_proof: xfr_range_proof, asset_proof: xfr_asset_proof};

    let body = XfrBody{
        inputs: xfr_inputs,
        outputs: xfr_outputs,
        proofs: xfr_proofs,
    };

    let multisig = compute_transfer_multisig(&body, input_keys)?;

    Ok(XfrNote{body, multisig})
}

/// I compute a range proof for confidential amount transfers.
/// The proof guarantees that output amounts and difference between total input
/// and total output are in the range [0,2^{64} - 1]
fn range_proof(
    inputs: &[OpenAssetRecord],
    outputs: &[OpenAssetRecord])
    -> Result<RangeProof, ZeiError>
{
    let num_output = outputs.len();
    let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;
    let mut params = PublicParams::new(upper_power2);

    //build values vector (out amounts + amount difference)
    let in_amounts:Vec<u64> = inputs.iter().map(|x| x.amount).collect();
    let out_amounts: Vec<u64> = outputs.iter().map(|x| x.amount).collect();
    let in_total = in_amounts.iter().sum::<u64>();
    let out_total = out_amounts.iter().sum::<u64>();
    let xfr_diff = if in_total >= out_total{
        in_total - out_total
    }
    else {
        return Err(ZeiError::TxProofError);
    };
    let mut values = vec![];
    values.extend_from_slice(out_amounts.as_slice());
    values.push(xfr_diff);
    for _ in values.len()..upper_power2 {
        values.push(0);
    }

    //build blinding vectors (out blindings + blindings difference)
    let in_blindings: Vec<Scalar> = inputs.iter().map(|x| x.amount_blind).collect();
    let out_blindings: Vec<Scalar> = outputs.iter().map(|x| x.amount_blind).collect();
    let xfr_blind_diff = in_blindings.iter().sum::<Scalar>()
        - out_blindings.iter().sum::<Scalar>();
    let mut blindings = vec![];
    blindings.extend_from_slice(out_blindings.as_slice());
    blindings.push(xfr_blind_diff);
    for _ in blindings.len()..upper_power2 {
        blindings.push(Scalar::default());
    }

    let (proof,_) = RangeProof::prove_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut params.transcript,
        values.as_slice(),
        blindings.as_slice(),
        BULLET_PROOF_RANGE)?;

    Ok(proof)
}

/// I compute asset equality proof for confidential asset transfers
fn asset_proof<R: CryptoRng + Rng>(
    prng: &mut R,
    pc_gens: &PedersenGens,
    inputs: &[OpenAssetRecord],
    open_outputs: &[OpenAssetRecord]
) -> Result<ChaumPedersenProofX, ZeiError>
{
    let asset = inputs[0].asset_type;
    let asset_scalar = Scalar::from(u8_bigendian_slice_to_u128(&asset[..]));

    let mut asset_coms = vec![];
    let mut asset_blinds = vec![];

    for x in inputs.iter(){
        asset_coms.push(x.asset_record.asset_type_commitment.unwrap());
        asset_blinds.push(x.type_blind);
    }
    for x in open_outputs.iter(){
        asset_coms.push(x.asset_record.asset_type_commitment.unwrap());
        asset_blinds.push(x.type_blind);
    }

    let proof = chaum_pedersen_prove_multiple_eq(
        prng,
        pc_gens,
        &asset_scalar,
        asset_coms.as_slice(),
        asset_blinds.as_slice())?;

    Ok(proof)
}

/// I check that total input amount is greater or equal than total output amount
/// I return false only if output is greater than input
fn check_amounts(inputs: &[OpenAssetRecord], outputs: &[OpenAssetRecord]) -> bool{
    let in_amounts: Vec<u64> = inputs.iter().map(|x| x.amount).collect();
    let out_amounts: Vec<u64> = outputs.iter().map(|x| x.amount).collect();

    if out_amounts.iter().sum::<u64>() > in_amounts.iter().sum::<u64>() {
        return false;
    }
    true
}

/// I check that asset types are all equal
/// I return false only if output is greater than input
fn check_assets(inputs: &[OpenAssetRecord], outputs: &[OpenAssetRecord]) -> bool{
    let mut list = vec![];
    for x in inputs.iter(){
        list.push(x.asset_type);
    }
    for x in outputs.iter(){
        list.push(x.asset_type);
    }
    list.iter().all_equal()
}

/// I compute a multisignature over the transfer's body
fn compute_transfer_multisig(body: &XfrBody, keys: &[XfrKeyPair]) -> Result<XfrMultiSig, ZeiError>{
    let mut vec = vec![];
    body.serialize(&mut rmp_serde::Serializer::new(&mut vec))?;
    Ok(sign_multisig(keys, vec.as_slice()))
}

/// I verify the transfer multisignature over the its body
fn verify_transfer_multisig(xfr_note: &XfrNote) -> Result<(), ZeiError>{
    let mut vec = vec![];
    xfr_note.body.serialize(&mut rmp_serde::Serializer::new(&mut vec))?;
    let mut public_keys = vec![];
    for x in xfr_note.body.inputs.iter() {public_keys.push(x.public_key)}
    verify_multisig(
        public_keys.as_slice(),
        vec.as_slice(),
        &xfr_note.multisig)
}

/// I verify a transfer note
pub fn verify_xfr_note(xfr_note: &XfrNote) -> Result<(), ZeiError>{
    // 1. verify signature
    verify_transfer_multisig(&xfr_note)?;

    //2. verify amounts
    let confidential_amount = xfr_note.body.inputs[0].amount_commitment.is_some();
    match confidential_amount {
        true => verify_confidential_amount(&xfr_note.body)?,
        false => verify_plain_amounts(&xfr_note.body)?,
    }

    //3. Verify assets
    //TODO future version will handle several assets in a transfer
    let confidential_asset = xfr_note.body.inputs[0].asset_type_commitment.is_some();
    match confidential_asset {
        true => verify_confidential_asset(&xfr_note.body),
        false => verify_plain_asset(&xfr_note.body),
    }
}

fn verify_confidential_amount(xfr_body: &XfrBody) -> Result<(), ZeiError> {
    let num_output = xfr_body.outputs.len();
    let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

    let params = PublicParams::new(upper_power2);
    let mut transcript = Transcript::new(b"Zei Range Proof");

    let input_com: Vec<RistrettoPoint> = xfr_body.inputs.iter().
        map(|x| x.amount_commitment.unwrap().decompress().unwrap()).collect();

    let output_com: Vec<RistrettoPoint> = xfr_body.outputs.iter().
        map(|x| x.amount_commitment.
            unwrap().decompress().unwrap()).collect();

    let diff_com = input_com.iter().sum::<RistrettoPoint>() -
        output_com.iter().sum::<RistrettoPoint>();

    let mut range_coms: Vec<CompressedRistretto> = output_com.iter().
        map(|x| x.compress()).collect();

    range_coms.push(diff_com.compress());

    for _ in (num_output + 1)..upper_power2 {
        range_coms.push(CompressedRistretto::identity());
    }

    xfr_body.proofs.range_proof.
        as_ref().unwrap().verify_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut transcript,
        range_coms.as_slice(),
        BULLET_PROOF_RANGE)?;

    Ok(())
}

fn verify_plain_amounts(xfr_body: &XfrBody) -> Result<(), ZeiError>{
    let in_amount: Vec<u64> = xfr_body.inputs.iter().
        map(|x| x.amount.unwrap()).collect();
    let out_amount: Vec<u64> = xfr_body.outputs.iter().
        map(|x| x.amount.unwrap()).collect();
    if in_amount.into_iter().sum::<u64>() < out_amount.into_iter().sum::<u64>() {
        return Err(ZeiError::XfrVerifyAmountError);
    }
    Ok(())
}

fn verify_confidential_asset(xfr_body: &XfrBody) -> Result<(), ZeiError>{
    let pc_gens = PedersenGens::default();
    let mut asset_commitments: Vec<CompressedRistretto> = xfr_body.inputs.iter().
        map(|x| x.asset_type_commitment.unwrap()).collect();

    let out_asset_commitments: Vec<CompressedRistretto> = xfr_body.outputs.iter().
        map(|x| x.asset_type_commitment.unwrap()).collect();

    asset_commitments.extend(out_asset_commitments.iter());

    let proof = xfr_body.proofs.asset_proof.borrow().as_ref().unwrap();

    match chaum_pedersen_verify_multiple_eq(&pc_gens,
                                            asset_commitments.as_slice(), proof,)?
        {
            true => Ok(()),
            false => Err(ZeiError::XfrVerifyConfidentialAssetError)
        }
}

fn verify_plain_asset(xfr_body: &XfrBody) -> Result<(), ZeiError>{
    let mut list = vec![];
    for x in xfr_body.inputs.iter() { list.push(x.asset_type.unwrap()); }
    for x in xfr_body.outputs.iter() { list.push(x.asset_type.unwrap()); }

    match list.iter().all_equal(){
        true => Ok(()),
        false => Err(ZeiError::XfrVerifyAssetError)
    }
}

/// build complete OpenAssetRecord from AssetRecord structure
fn build_open_asset_record<R: CryptoRng + Rng>(
    prng: &mut R,
    pc_gens: &PedersenGens,
    asset_record: &AssetRecord,
    confidential_amount: bool,
    confidential_asset: bool) -> OpenAssetRecord
{
    let mut lock_amount = None;
    let mut lock_type = None;
    let (derived_point, blind_share) =
        sample_point_and_blind_share(prng, &asset_record.public_key);

    // build amount fields
    let (bar_amount, bar_amount_commitment,amount_blind)
        = match confidential_amount{
            true => {
                lock_amount = Some(ZeiCipher::encrypt(
                    prng,
                    &asset_record.public_key,
                    &u64_to_bigendian_u8array(asset_record.amount)).unwrap());

                let amount_blind = compute_blind_factor(&derived_point, "amount");
                let amount_commitment =
                    pc_gens.commit(Scalar::from(asset_record.amount), amount_blind);
                (None, Some(amount_commitment.compress()), amount_blind)
            },
            false => (Some(asset_record.amount), None, Scalar::default())
    };

    // build asset type fields
    let (bar_type, bar_type_commitment, type_blind)
        = match confidential_asset{
        true => {
            lock_type = Some(ZeiCipher::encrypt(prng, &asset_record.public_key,
                                             &asset_record.asset_type).unwrap());

            let type_blind = compute_blind_factor(&derived_point, "asset_type");
            let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
            let type_commitment =
                pc_gens.commit(Scalar::from(type_as_u128), type_blind);
            (None, Some(type_commitment.compress()), type_blind)
        },
        false => (Some(asset_record.asset_type), None, Scalar::default())
    };

    let blind_asset_record = BlindAssetRecord {
        amount: bar_amount,
        asset_type: bar_type,
        public_key: asset_record.public_key.clone(),
        amount_commitment: bar_amount_commitment,
        asset_type_commitment: bar_type_commitment,
        blind_share,
        lock_amount,
        lock_type,
    };

    let open_asset_record = OpenAssetRecord{
        asset_record: blind_asset_record,
        amount: asset_record.amount,
        amount_blind: amount_blind,
        asset_type: asset_record.asset_type,
        type_blind: type_blind,
    };

    open_asset_record
}

fn sample_point_and_blind_share<R: CryptoRng + Rng>(prng: &mut R, public_key: &XfrPublicKey)
                                                    -> (CompressedEdwardsY, CompressedEdwardsY)
{
    let blind_key = Scalar::random(prng);
    let pk_point = public_key.get_curve_point().unwrap();
    let derived_point: EdwardsPoint = blind_key * pk_point;
    let blind_share = blind_key * ED25519_BASEPOINT_POINT;
    (derived_point.compress(), blind_share.compress())
}

fn derive_point_from_blind_share(blind_share: &CompressedEdwardsY, secret_key: &XfrSecretKey)
    -> Result<CompressedEdwardsY, ZeiError>{

    let blind_share_decompressed = blind_share.decompress()?;
    Ok(secret_key.as_scalar_multiply_by_curve_point(&blind_share_decompressed).compress())
}

fn compute_blind_factor(point: &CompressedEdwardsY, aux: &str) -> Scalar
{
    let mut hasher = Sha512::new();
    hasher.input(point.as_bytes());
    hasher.input(aux.as_bytes());
    Scalar::from_hash(hasher)
}


/// I use the address secret key to compute the blinding factors for commitments in a BlindAssetRecord
pub fn open_asset_record(
    input: &BlindAssetRecord,
    secret_key: &XfrSecretKey) -> Result<OpenAssetRecord, ZeiError>
{
    let confidential_amount = input.amount.is_none();
    let confidential_asset = input.asset_type.is_none();
    let amount;
    let mut asset_type= [0u8;16];
    let amount_blind;
    let type_blind;
    let shared_point = derive_point_from_blind_share(&input.blind_share, secret_key)?;
    if confidential_amount{
        let amount_bytes = input.lock_amount.as_ref().unwrap().decrypt(secret_key)?;
        amount = u8_bigendian_slice_to_u64(amount_bytes.as_slice());
        amount_blind = compute_blind_factor(&shared_point, "amount");
    }
    else{
        amount = input.amount.unwrap();
        amount_blind = Scalar::default();
    }

    if confidential_asset{
        asset_type.copy_from_slice(input.lock_type.as_ref().unwrap().decrypt(secret_key)?.as_slice());
        type_blind = compute_blind_factor(&shared_point, "asset_type");
    }
    else{
        asset_type = input.asset_type.unwrap();
        type_blind = Scalar::default();
    }

    Ok(OpenAssetRecord{
        asset_type,
        amount,
        asset_record: input.clone(),
        amount_blind,
        type_blind,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::keys::XfrKeyPair;
    use crate::errors::Error::{XfrVerifyAmountError, XfrVerifyAssetError, XfrCreationAmountError, XfrCreationAssetError, XfrVerifyConfidentialAssetError, XfrVerifyConfidentialAmountError};
    use serde::ser::{Serialize};
    use serde::de::{Deserialize};

    #[test]
    fn test_build_open_asset_record_not_confidential() {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let amount = 100u64;
        let asset_type = [0u8; 16];
        let keypair = XfrKeyPair::generate(&mut prng);
        let asset_record = AssetRecord {
            amount,
            asset_type,
            public_key: keypair.get_pk_ref().clone()
        };

        let open_ar = build_open_asset_record(
            &mut prng,
            &pc_gens,
            &asset_record,
            false, false);

        assert_eq!(amount, open_ar.amount);
        assert_eq!(asset_type, open_ar.asset_type);
        assert_eq!(Some(amount), open_ar.asset_record.amount);
        assert_eq!(None, open_ar.asset_record.amount_commitment);
        assert_eq!(Some(asset_type), open_ar.asset_record.asset_type);
        assert_eq!(None, open_ar.asset_record.asset_type_commitment);
        assert_eq!(None, open_ar.asset_record.lock_amount);
        assert_eq!(None, open_ar.asset_record.lock_type);
        assert_eq!(keypair.get_pk_ref(), &open_ar.asset_record.public_key);
    }

    fn create_xfr(
        prng: &mut ChaChaRng,
        input_amounts: &[u64], output_amounts: &[u64],
        asset_type: [u8;16],
        confidential_amount: bool, confidential_asset: bool)
        -> (XfrNote, Vec<XfrKeyPair>, Vec<OpenAssetRecord>, Vec<AssetRecord>, Vec<XfrKeyPair>){
        let pc_gens = PedersenGens::default();

        let mut inputs = vec![];
        let mut outputs = vec![];

        let mut outkeys = vec![];
        let mut inkeys = vec![];
        let mut in_asset_records = vec![];

        for x in input_amounts.iter() {
            let keypair = XfrKeyPair::generate(prng);
            let asset_record = AssetRecord {
                amount: *x,
                asset_type,
                public_key: keypair.get_pk_ref().clone()
            };

            inputs.push(build_open_asset_record(
                prng,
                &pc_gens,
                &asset_record,
                confidential_amount, confidential_asset)
            );

            in_asset_records.push(asset_record);
            inkeys.push(keypair);
        }

        for x in output_amounts.iter() {
            let keypair = XfrKeyPair::generate(prng);

            outputs.push(AssetRecord {
                amount: *x,
                asset_type,
                public_key: keypair.get_pk_ref().clone(),

            });
            outkeys.push(keypair)
        }

        let xfr_note = gen_xfr_note(
            prng,
            inputs.as_slice(),
            outputs.as_slice(),
            inkeys.as_slice()).unwrap();

        (xfr_note, inkeys, inputs, outputs, outkeys)
    }
    fn do_transfer_tests(confidential_amount: bool, confidential_asset: bool) {
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let asset_type = [0u8; 16];
        let pc_gens = PedersenGens::default();
        let input_amount = [10u64, 10u64, 10u64];
        let out_amount = [1u64, 2u64, 3u64, 4u64];

        let tuple  = create_xfr(
            &mut prng,
            &input_amount,
            &out_amount,
            asset_type,
            confidential_amount, confidential_asset);

        let xfr_note = tuple.0;
        let inkeys = tuple.1;
        let mut inputs = tuple.2;
        let mut outputs = tuple.3;

        // test 1: simple transfer
        assert_eq!(Ok(()), verify_xfr_note(&xfr_note), "Not confidential simple transaction should verify ok");

        //test 2: overflow transfer
        outputs[3] = AssetRecord {
            amount: 0xFFFFFFFFFF,
            asset_type,
            public_key: outputs[3].public_key
        };
        let xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice());
        assert_eq!(true, xfr_note.is_err(), "Xfr cannot be build if output total amount is greater than input amounts");
        assert_eq!(XfrCreationAmountError, xfr_note.err().unwrap(), "Xfr cannot be build if output total amount is greater than input amounts");
        //output 3 back to original
        outputs[3] = AssetRecord {
            amount: 4,
            asset_type,
            public_key: outputs[3].public_key
        };
        let mut xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice()).unwrap();
        let error;
        if confidential_amount {
            xfr_note.body.outputs[3].amount_commitment = Some(pc_gens.commit(Scalar::from(0xFFFFFFFFFF as u128),Scalar::random(&mut prng)).compress());
            error = XfrVerifyConfidentialAmountError;
        }
        else{
            xfr_note.body.outputs[3].amount = Some(0xFFFFFFFFFF);
            error = XfrVerifyAmountError;
        }
        xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
        assert_eq!(Err(error), verify_xfr_note(&xfr_note),
                   "Confidential transfer with invalid amounts should fail verification");


        //test 4: exact amount transfer
        outputs[3] = AssetRecord {
            amount: 24u64,
            asset_type,
            public_key: outputs[3].public_key
        };
        let xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice()).unwrap();
        assert_eq!(Ok(()), verify_xfr_note(&xfr_note),
                   "Not confidential tx with exact input and output should pass");


        //test 4: one output asset different from rest
        outputs[3] = AssetRecord {
            amount: 24u64,
            asset_type: [1u8; 16],
            public_key: outputs[3].public_key
        };
        let xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice());
        assert_eq!(true, xfr_note.is_err(), "Xfr cannot be build if output asset types are different");
        assert_eq!(XfrCreationAssetError, xfr_note.err().unwrap(), "Xfr cannot be build if output asset types are different");
        outputs[3] = AssetRecord {
            amount: 24u64,
            asset_type: [0u8; 16],
            public_key: outputs[3].public_key
        };
        let mut xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice()).unwrap();
        // modify xfr_note asset on an output
        let error;
        if confidential_asset{
            xfr_note.body.outputs[1].asset_type_commitment = Some(CompressedRistretto::default());
            error = XfrVerifyConfidentialAssetError;
        }
        else{
            xfr_note.body.outputs[1].asset_type = Some([1u8;16]);
            error = XfrVerifyAssetError;
        }
        xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
        assert_eq!(Err(error), verify_xfr_note(&xfr_note),
                   "Transfer with different asset types should fail verification");

        //test 4:  one input asset different from rest
        let ar = AssetRecord {
            amount: 10u64,
            asset_type: [1u8; 16],
            public_key: inputs[1].asset_record.public_key,
        };
        inputs[1] = build_open_asset_record(&mut prng, &pc_gens, &ar,
                                            confidential_amount, confidential_asset);
        let xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice());
        assert_eq!(true, xfr_note.is_err(), "Xfr cannot be build if output asset types are different");
        assert_eq!(XfrCreationAssetError, xfr_note.err().unwrap(), "Xfr cannot be build if output asset types are different");
        //inputs[1] back to normal
        let ar = AssetRecord {
            amount: 10u64,
            asset_type: [0u8; 16],
            public_key: inputs[1].asset_record.public_key,
        };
        inputs[1] = build_open_asset_record(&mut prng, &pc_gens, &ar,
                                            confidential_amount, confidential_asset);
        let mut xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice()).unwrap();
        // modify xfr_note asset on an input
        let error;
        if confidential_asset{
            xfr_note.body.inputs[1].asset_type_commitment = Some(CompressedRistretto::default());
            error = XfrVerifyConfidentialAssetError;
        }
        else{
            xfr_note.body.inputs[1].asset_type = Some([1u8;16]);
            error = XfrVerifyAssetError;
        }
        xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
        assert_eq!(Err(error), verify_xfr_note(&xfr_note),
                   "Confidential transfer with different asset types should fail verification ok");
    }

    #[test]
    fn test_transfer_not_confidential() {
        /*! I test non confidential transfers*/
        do_transfer_tests(false, false);
    }

    #[test]
    fn test_transfer_confidential_amount_plain_asset() {
        /*! I test confidential amount transfers*/
        do_transfer_tests(true, false);
    }

    #[test]
    fn test_transfer_confidential_asset_plain_amount() {
        /*! I test confidential asset transfers*/
        do_transfer_tests(false, true);
    }

    #[test]
    fn test_transfer_confidential() {
        /*! I test confidential amount and confidential asset transfers*/
        do_transfer_tests(true, true);
    }

    fn do_test_transfer_multisig(confidential_amount: bool, confidential_asset: bool){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let input_amount = [10u64, 20u64];
        let out_amount = [1u64, 2u64, 1u64, 10u64, 3u64];

        let (xfr_note, _,_,_,_)  = create_xfr(
            &mut prng,
            &input_amount,
            &out_amount,
            [0u8;16],
            confidential_amount,
            confidential_asset);
        assert_eq!(Ok(()), verify_transfer_multisig(&xfr_note));
    }

    #[test]
    fn test_transfer_multisig(){
        do_test_transfer_multisig(false, false);
        do_test_transfer_multisig(false, true);
        do_test_transfer_multisig(true, false);
        do_test_transfer_multisig(true, true);
    }

    fn do_test_open_asset_record(confidential_amount: bool, confidential_asset: bool){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let input_amount = [10u64, 20u64];
        let out_amount = [30u64];

        let (xfr_note, _,_,_, outkeys)  = create_xfr(
            &mut prng,
            &input_amount,
            &out_amount,
            [1u8;16],
            confidential_amount,
            confidential_asset);

        let secret_key = outkeys.get(0).unwrap().get_sk_ref();
        let open_ar = open_asset_record(
            &xfr_note.body.outputs[0], secret_key).unwrap();

        assert_eq!(&open_ar.asset_record, &xfr_note.body.outputs[0]);
        assert_eq!(open_ar.amount, 30u64);
        assert_eq!(open_ar.asset_type, [1u8;16]);

        if confidential_amount{
            let derived_commitment = pc_gens.commit(Scalar::from(open_ar.amount), open_ar.amount_blind).compress();
            assert_eq!(derived_commitment, open_ar.asset_record.amount_commitment.unwrap());
        }

        if confidential_asset{
            let derived_commitment = pc_gens.commit(
                Scalar::from(u8_bigendian_slice_to_u128(&open_ar.asset_type[..])),
                open_ar.type_blind).compress();
            assert_eq!(derived_commitment, open_ar.asset_record.asset_type_commitment.unwrap());
        }
    }
    #[test]
    fn test_open_asset_record(){
        do_test_open_asset_record(false, false);
        do_test_open_asset_record(true, false);
        do_test_open_asset_record(false, true);
        do_test_open_asset_record(true, true);
    }

    fn do_test_serialization(confidential_amount: bool, confidential_asset: bool){
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);

        let input_amount = [10u64, 20u64];
        let out_amount = [1u64, 2u64, 1u64, 10u64, 3u64];

        let (xfr_note, _,_,_,_)  = create_xfr(
            &mut prng,
            &input_amount,
            &out_amount,
            [0u8;16],
            confidential_amount,
            confidential_asset);

        //serializing signatures
        use rmp_serde::{Deserializer, Serializer};
        let mut vec = vec![];
        assert_eq!(true, xfr_note.multisig.serialize(&mut Serializer::new(&mut vec)).is_ok());
        let mut de = Deserializer::new(&vec[..]);
        let multisig_de: XfrMultiSig = Deserialize::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.multisig, multisig_de);

        //serializing proofs
        let mut vec = vec![];
        assert_eq!(true, xfr_note.body.proofs.serialize(&mut Serializer::new(&mut vec)).is_ok());
        let mut de = Deserializer::new(&vec[..]);
        let proofs_de = XfrProofs::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.body.proofs, proofs_de);

        //serializing body
        let mut vec = vec![];
        assert_eq!(true, xfr_note.body.serialize(&mut Serializer::new(&mut vec)).is_ok());
        let mut de = Deserializer::new(&vec[..]);
        let body_de = XfrBody::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note.body, body_de);

        //serializing whole Xfr
        let mut vec = vec![];
        assert_eq!(true, xfr_note.serialize(&mut Serializer::new(&mut vec)).is_ok());
        let mut de = Deserializer::new(&vec[..]);
        let xfr_de = XfrNote::deserialize(&mut de).unwrap();
        assert_eq!(xfr_note, xfr_de);
    }

    #[test]
    fn test_serialization(){
        do_test_serialization(false, false);
        do_test_serialization(false, true);
        do_test_serialization(true, false);
        do_test_serialization(true, true);
    }
}
