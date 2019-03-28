use sha2::{Sha512, Digest};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use crate::basic_crypto::hybrid_encryption::{ZeiHybridCipher, hybrid_encrypt, hybrid_decrypt};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{RangeProof, PedersenGens};
use crate::basic_crypto::signatures::{XfrPublicKey, XfrKeyPair, XfrSecretKey, XfrMultiSig, sign_multisig, verify_multisig};
use crate::utils::{u8_bigendian_slice_to_u128, min_greater_equal_power_of_two, u8_bigendian_slice_to_u64, u64_to_bigendian_u8array, u64_to_u32_pair};
use rand::{CryptoRng, Rng};
use crate::setup::{PublicParams, BULLET_PROOF_RANGE, MAX_PARTY_NUMBER};
use crate::proofs::chaum_pedersen::{ChaumPedersenProofX, chaum_pedersen_prove_multiple_eq, chaum_pedersen_verify_multiple_eq};
use crate::errors::ZeiError;
use merlin::Transcript;
use core::borrow::Borrow;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::traits::Identity;
use itertools::Itertools;
use serde::ser::Serialize;
use crate::proofs::pedersen_elgamal::{PedersenElGamalEqProof, pedersen_elgamal_eq_prove, pedersen_elgamal_eq_verify};
use crate::basic_crypto::elgamal::{ElGamalPublicKey, ElGamalCiphertext, elgamal_encrypt};

const POW_2_32: u64 = 0xFFFFFFFFu64 + 1;
type AssetType = [u8;16];

/// I represent a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrNote{
    pub(crate) body: XfrBody,
    pub(crate) multisig: XfrMultiSig,
}

impl XfrNote {
    pub fn outputs_iter(&self) -> std::slice::Iter<BlindAssetRecord> {
        self.body.outputs.iter()
    }
}

/// I am the body of a transfer note
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct XfrBody{
    pub(crate) inputs: Vec<BlindAssetRecord>,
    pub(crate) outputs: Vec<BlindAssetRecord>,
    pub(crate) proofs: XfrProofs,
}

/// I represent an Asset Record as presented in the public ledger.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BlindAssetRecord{
    // amount is a 64 bit positive integer expressed in base 2^32 in confidential transaction
    // commitments and ciphertext
    pub(crate) issuer_public_key: Option<ElGamalPublicKey>, //None if issuer tracking is not required
    pub(crate) issuer_lock_amount: Option<(ElGamalCiphertext, ElGamalCiphertext)>, //None if issuer tracking not required or amount is not confidential
    pub(crate) issuer_lock_type: Option<ElGamalCiphertext>,
    pub(crate) amount_commitments: Option<(CompressedRistretto, CompressedRistretto)>, //None if not confidential transfer
    //pub(crate) issuer_lock_id: Option<(ElGamalCiphertext, ElGamalCiphertext)>, TODO

    pub(crate) amount: Option<u64>, // None if confidential transfers
    pub(crate) asset_type: Option<AssetType>, // None if confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) public_key: XfrPublicKey, // ownership address
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_commitment: Option<CompressedRistretto>, //Noe if not confidential asset
    //#[serde(with = "serialization::zei_obj_serde")]
    pub(crate) blind_share:  CompressedEdwardsY, // Used by pukey holder to derive blinding factors
    pub(crate) lock_amount: Option<ZeiHybridCipher>,  // If confidential transfer lock the amount to the pubkey in asset_record
    pub(crate) lock_type: Option<ZeiHybridCipher>, // If confidential type lock the type to the public key in asset_record
}

/// I'm a BlindAssetRecors with revealed commitment openings.
pub struct OpenAssetRecord{
    pub(crate) asset_record: BlindAssetRecord, //TODO have a reference here, and lifetime parameter. We will avoid copying info unnecessarily.
    pub(crate) amount: u64,
    pub(crate) amount_blinds: (Scalar, Scalar),
    pub(crate) asset_type: AssetType,
    pub(crate) type_blind: Scalar,
}

/// I'am a plaintext asset record, used to indicate output information when creating a transfer note
pub struct AssetRecord{
    pub(crate) amount: u64,
    pub(crate) asset_type: AssetType,
    pub(crate) public_key: XfrPublicKey, // ownership address
}

/// I contain the proofs of a transfer note
#[derive(Serialize, Deserialize, Debug)]
pub struct XfrProofs{
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) range_proof: Option<XfrRangeProof>,
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) asset_proof: Option<ChaumPedersenProofX>,
    pub(crate) asset_tracking_proof: Vec<Option<AssetTrackingProof>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct XfrRangeProof{
    range_proof: RangeProof,
    xfr_diff_commitment_low: CompressedRistretto, //lower 32 bits transfer amount difference commitment
    xfr_diff_commitment_high: CompressedRistretto, //lower 32 bits transfer amount difference commitment
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AssetTrackingProof{
    pub(crate) amount_proof: Option<(PedersenElGamalEqProof, PedersenElGamalEqProof)>, // None if confidential amount flag is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
    pub(crate) asset_type_proof: Option<PedersenElGamalEqProof>, //None if confidential asset_type is off. Otherwise, value proves that decryption of issuer_lock_amount yields the same as value committed in amount_commitment in BlindAssetRecord output
    //pub(crate) identity_proof: Option<?> //None if asset policy does not require identity tracking. Otherwise, value proves that ElGamal ciphertext encrypts the identity of the output address owner
}

impl PartialEq for XfrRangeProof {
    fn eq(&self, other: &XfrRangeProof) -> bool {
         self.range_proof.to_bytes() == other.range_proof.to_bytes() &&
             self.xfr_diff_commitment_low == other.xfr_diff_commitment_low &&
             self.xfr_diff_commitment_high == other.xfr_diff_commitment_high
    }
}

impl Eq for XfrRangeProof {}

impl PartialEq for XfrProofs {
    fn eq(&self, other: &XfrProofs) -> bool {
            self.range_proof == other.range_proof && self.asset_proof == other.asset_proof
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
    let issuer_pk = &inputs[0].asset_record.issuer_public_key;
    let pc_gens = PedersenGens::default();

    let open_outputs: Vec<OpenAssetRecord> = outputs.iter().
        map(|x| build_open_asset_record(
            prng, &pc_gens,x, confidential_amount, confidential_asset, issuer_pk)
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

    //do tracking proofs
    let xfr_tracking_proof =
        tracking_proofs(prng, open_outputs.as_slice())?;

    let mut xfr_inputs = vec![];
    for x in inputs {xfr_inputs.push(x.asset_record.clone())}

    let mut xfr_outputs = vec![];
    for x in open_outputs {xfr_outputs.push(x.asset_record.clone())}

    let xfr_proofs  = XfrProofs{
        range_proof: xfr_range_proof,
        asset_proof: xfr_asset_proof,
        asset_tracking_proof: xfr_tracking_proof};

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
    -> Result<XfrRangeProof, ZeiError>
{
    let num_output = outputs.len();
    let upper_power2 = min_greater_equal_power_of_two((2*num_output + 2) as u32) as usize;
    if upper_power2 > MAX_PARTY_NUMBER {
        return Err(ZeiError::RangeProofProveError);
    }

    let pow2_32 = Scalar::from(POW_2_32);
    let mut params = PublicParams::new();

    //build values vector (out amounts + amount difference)
    let in_amounts:Vec<u64> = inputs.iter().map(|x| x.amount).collect();
    let out_amounts: Vec<u64> = outputs.iter().map(|x| x.amount).collect();
    let in_total = in_amounts.iter().sum::<u64>();
    let out_total = out_amounts.iter().sum::<u64>();
    let xfr_diff = if in_total >= out_total{
        in_total - out_total
    }
    else {
        return Err(ZeiError::RangeProofProveError);
    };
    let mut values = Vec::with_capacity(out_amounts.len() + 1);
    for x in out_amounts{
        let (lower, higher) = u64_to_u32_pair(x);
        values.push(lower as u64);
        values.push(higher as u64);
    }
    let (diff_low, diff_high) = u64_to_u32_pair(xfr_diff);
    values.push(diff_low as u64);
    values.push(diff_high as u64);
    for _ in values.len()..upper_power2 {
        values.push(0u64);
    }

    //build blinding vectors (out blindings + blindings difference)
    let in_blind_low: Vec<Scalar> = inputs.iter().map(|x| x.amount_blinds.0).collect();
    let in_blind_high: Vec<Scalar> = inputs.iter().map(|x| x.amount_blinds.1).collect();
    let out_blind_low: Vec<Scalar> = outputs.iter().map(|x| x.amount_blinds.0).collect();
    let out_blind_high: Vec<Scalar> = outputs.iter().map(|x| x.amount_blinds.1).collect();

    let mut in_blind_sum = Scalar::zero();
    for (blind_low, blind_high) in
        in_blind_low.iter().zip(in_blind_high.iter()){
        in_blind_sum = in_blind_sum + (blind_low + blind_high * pow2_32); //2^32
    }
    let mut range_proof_blinds = Vec::with_capacity(upper_power2);
    let mut out_blind_sum = Scalar::zero();
    for (blind_low, blind_high) in
        out_blind_low.iter().zip(out_blind_high.iter()){
        range_proof_blinds.push(blind_low.clone());
        range_proof_blinds.push(blind_high.clone());
        out_blind_sum = out_blind_sum + (blind_low + blind_high * pow2_32); //2^32
    }

    let xfr_blind_diff = in_blind_sum - out_blind_sum;
    let xfr_blind_diff_high = xfr_blind_diff * pow2_32.invert();
    let xfr_blind_diff_low = xfr_blind_diff - xfr_blind_diff_high * pow2_32;
    range_proof_blinds.push(xfr_blind_diff_low);
    range_proof_blinds.push(xfr_blind_diff_high);
    for _ in range_proof_blinds.len()..upper_power2 {
        range_proof_blinds.push(Scalar::default());
    }

    let (range_proof,coms) = RangeProof::prove_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut params.transcript,
        values.as_slice(),
        range_proof_blinds.as_slice(),
        BULLET_PROOF_RANGE).map_err(|_| ZeiError::RangeProofProveError)?;

    let diff_com_low = coms[2*num_output];
    let diff_com_high = coms[2*num_output + 1];
    Ok(XfrRangeProof{
        range_proof,
        xfr_diff_commitment_low: diff_com_low,
        xfr_diff_commitment_high: diff_com_high,
    })
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

fn tracking_proofs<R:CryptoRng + Rng>(
    prng: &mut R,
    outputs:&[OpenAssetRecord]
)->Result<Vec<(Option<AssetTrackingProof>)>, ZeiError>{
    let mut v = vec![];
    for output in outputs {
        match output.asset_record.issuer_public_key.as_ref(){
            None => v.push(None),
            Some(public_key) => {
                let mut asset_type_proof = None;
                let mut amount_proof = None;
                //do asset
                if output.asset_record.asset_type_commitment.is_some() {
                    let asset_blind = &output.type_blind;
                    let asset_scalar = Scalar::from(u8_bigendian_slice_to_u128(&output.asset_type[..]));
                    let asset_com = &output.asset_record.asset_type_commitment.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    let asset_ctext = output.asset_record.issuer_lock_type.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    asset_type_proof = Some(pedersen_elgamal_eq_prove(
                        prng,
                        &asset_scalar,
                        asset_blind,
                        public_key,
                        asset_ctext,
                        asset_com));
                }
                if output.asset_record.amount_commitments.is_some() {
                    let (amount_low, amount_high) = u64_to_u32_pair(output.amount);
                    let ctexts = output.asset_record.issuer_lock_amount.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    let commitments = output.asset_record.amount_commitments.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    let proof_low = pedersen_elgamal_eq_prove(
                        prng,
                        &Scalar::from(amount_low),
                        &output.amount_blinds.0,
                        public_key,
                        &ctexts.0,
                        &commitments.0);
                    let proof_high = pedersen_elgamal_eq_prove(
                        prng,
                        &Scalar::from(amount_high),
                        &output.amount_blinds.1,
                        public_key,
                        &ctexts.1,
                        &commitments.1);
                    amount_proof = Some((proof_low, proof_high));
                }
                //TODO do identity
                v.push(Some(AssetTrackingProof { amount_proof, asset_type_proof }));
            }
        }
    }

    Ok(v)

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
    let confidential_amount = xfr_note.body.inputs[0].amount_commitments.is_some();
    match confidential_amount {
        true => verify_confidential_amount(&xfr_note.body)?,
        false => verify_plain_amounts(&xfr_note.body)?,
    }

    //3. Verify assets
    //TODO future version will handle several assets in a transfer
    let confidential_asset = xfr_note.body.inputs[0].asset_type_commitment.is_some();
    match confidential_asset {
        true => verify_confidential_asset(&xfr_note.body)?,
        false => verify_plain_asset(&xfr_note.body)?,
    }
    //4. Verify issuer asset tracing
    verify_issuer_tracking_proof(&xfr_note.body)

}

fn verify_confidential_amount(xfr_body: &XfrBody) -> Result<(), ZeiError> {
    let num_output = xfr_body.outputs.len();
    let upper_power2 = min_greater_equal_power_of_two((2*num_output + 2) as u32) as usize;
    if upper_power2 > MAX_PARTY_NUMBER {
        return Err(ZeiError::XfrVerifyConfidentialAmountError);
    }
    let pow2_32 = Scalar::from(POW_2_32);
    let params = PublicParams::new();
    let mut transcript = Transcript::new(b"Zei Range Proof");
    let range_proof = xfr_body.proofs.range_proof.as_ref().ok_or(ZeiError::InconsistentStructureError)?;

    // 1. verify proof commitment to transfer's input - output amounts match proof commitments
    let mut total_input_com = RistrettoPoint::identity();
    for bar in xfr_body.inputs.iter(){
        let coms = bar.amount_commitments.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
        let com_low = (coms.0).decompress().ok_or(ZeiError::DecompressElementError)?;
        let com_high = (coms.1).decompress().ok_or(ZeiError::DecompressElementError)?;
        total_input_com += com_low + com_high * pow2_32;
    }

    let mut total_output_com = RistrettoPoint::identity();
    let mut range_coms: Vec<CompressedRistretto> = Vec::with_capacity(2*num_output + 2);
    for bar in xfr_body.outputs.iter(){
        let coms = bar.amount_commitments.as_ref().ok_or(ZeiError::InconsistentStructureError)?;
        let com_low = (coms.0).decompress().ok_or(ZeiError::DecompressElementError)?;
        let com_high = (coms.1).decompress().ok_or(ZeiError::DecompressElementError)?;
        total_output_com += com_low + com_high * pow2_32;

        range_coms.push(coms.0);
        range_coms.push(coms.1);
        //output_com.push(com_low + com_high * Scalar::from(0xFFFFFFFF as u64 + 1));
    }
    let derived_xfr_diff_com = total_input_com - total_output_com;

    let proof_xfr_com_low = range_proof.xfr_diff_commitment_low.decompress().ok_or(ZeiError::DecompressElementError)?;
    let proof_xfr_com_high = range_proof.xfr_diff_commitment_high.decompress().ok_or(ZeiError::DecompressElementError)?;
    let proof_xfr_com_diff = proof_xfr_com_low + proof_xfr_com_high * pow2_32;

    if derived_xfr_diff_com.compress() != proof_xfr_com_diff.compress() {
        return Err(ZeiError::XfrVerifyConfidentialAmountError);
    }

    //2 verify range proof
    range_coms.push(range_proof.xfr_diff_commitment_low);
    range_coms.push(range_proof.xfr_diff_commitment_high);

    for _ in range_coms.len()..upper_power2 {
        range_coms.push(CompressedRistretto::identity());
    }

    xfr_body.proofs.range_proof.as_ref().unwrap().range_proof.verify_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut transcript,
        range_coms.as_slice(),
        BULLET_PROOF_RANGE).map_err(|_| ZeiError::XfrVerifyConfidentialAmountError)
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

fn verify_issuer_tracking_proof(xfr_body: &XfrBody) -> Result<(), ZeiError>{

    match xfr_body.inputs[0].issuer_public_key.as_ref() {
        None => Ok(()), //no asset tracing required
        Some(issuer_pk) => {
            let conf_asset = xfr_body.inputs[0].asset_type.is_none();
            let conf_amount = xfr_body.inputs[0].amount.is_none();

            for (proof, asset_record) in
                xfr_body.proofs.asset_tracking_proof.iter().zip(xfr_body.outputs.iter()) {
                if proof.is_none() {
                    return Err(ZeiError::XfrVerifyIssuerTrackingAssetTypeError);
                }
                if conf_asset {
                    let ctext = asset_record.issuer_lock_type.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let commitment = asset_record.asset_type_commitment.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let asset_proof = proof.as_ref().unwrap().asset_type_proof.
                        as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    pedersen_elgamal_eq_verify(issuer_pk, ctext, commitment, asset_proof).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAssetTypeError)?;
                }
                if conf_amount {
                    let ctext = asset_record.issuer_lock_amount.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let commitment = asset_record.amount_commitments.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let amount_proof = proof.as_ref().unwrap().amount_proof.
                        as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    pedersen_elgamal_eq_verify(issuer_pk, &ctext.0, &commitment.0, &amount_proof.0).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAmountError)?;
                    pedersen_elgamal_eq_verify(issuer_pk, &ctext.1, &commitment.1, &amount_proof.1).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAmountError)?;
                }
                //TODO identity tracing
            }
            Ok(())
        }
    }
}
/// build complete OpenAssetRecord from AssetRecord structure
fn build_open_asset_record<R: CryptoRng + Rng>(
    prng: &mut R,
    pc_gens: &PedersenGens,
    asset_record: &AssetRecord,
    confidential_amount: bool,
    confidential_asset: bool,
    issuer_public_key: &Option<ElGamalPublicKey> //none if no tracking is required
) -> OpenAssetRecord
{
    let mut lock_amount = None;
    let mut lock_type = None;
    let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
    let type_scalar = Scalar::from(type_as_u128);
    let (derived_point, blind_share) =
        sample_point_and_blind_share(prng, &asset_record.public_key);
    let type_blind = compute_blind_factor(&derived_point, "asset_type");
    let amount_blind_low = compute_blind_factor(&derived_point, "amount_low");
    let amount_blind_high = compute_blind_factor(&derived_point, "amount_high");
    let (amount_low, amount_high) = u64_to_u32_pair(asset_record.amount);

    // build amount fields
    let (bar_amount, bar_amount_commitments,amount_blinds)
        = match confidential_amount{
            true => {
                lock_amount = Some(hybrid_encrypt(
                    prng,
                    &asset_record.public_key,
                    &u64_to_bigendian_u8array(asset_record.amount)).unwrap());

                let amount_commitment_low =
                    pc_gens.commit(Scalar::from(amount_low), amount_blind_low);
                let amount_commitment_high =
                    pc_gens.commit(Scalar::from(amount_high), amount_blind_high);

                (None,
                Some( (amount_commitment_low.compress() , amount_commitment_high.compress())),
                (amount_blind_low, amount_blind_high))
            },
            false => (Some(asset_record.amount), None, (Scalar::default(), Scalar::default()))
    };

    // build asset type fields
    let (bar_type, bar_type_commitment, type_blind)
        = match confidential_asset{
        true => {
            lock_type = Some(hybrid_encrypt(prng, &asset_record.public_key,
                                            &asset_record.asset_type).unwrap());

            let type_commitment =
                pc_gens.commit(type_scalar, type_blind);
            (None, Some(type_commitment.compress()), type_blind)
        },
        false => (Some(asset_record.asset_type), None, Scalar::default())
    };


    //issuer asset tracking amount
    let issuer_lock_amount = match issuer_public_key {
        None => None,
        Some(pk) => match confidential_amount {
            true => Some((
                elgamal_encrypt(&pc_gens.B, &Scalar::from(amount_low), &amount_blind_low, pk).unwrap(),
                elgamal_encrypt(&pc_gens.B, &Scalar::from(amount_high), &amount_blind_high, pk).unwrap()
            )),
            false => None,
        }
    };
    //issuer asset tracking asset type
    let issuer_lock_type = match issuer_public_key {
        None => None,
        Some(pk) => match confidential_asset {
            true => Some(elgamal_encrypt(&pc_gens.B, &type_scalar, &type_blind, pk).unwrap()),
            false => None,
        }
    };

    let blind_asset_record = BlindAssetRecord {
        issuer_public_key: issuer_public_key.clone(), //None if issuer tracking is not required
        issuer_lock_type,
        issuer_lock_amount,
        amount: bar_amount,
        asset_type: bar_type,
        public_key: asset_record.public_key.clone(),
        amount_commitments: bar_amount_commitments,
        asset_type_commitment: bar_type_commitment,
        blind_share,
        lock_amount,
        lock_type,
    };

    let open_asset_record = OpenAssetRecord{
        asset_record: blind_asset_record,
        amount: asset_record.amount,
        amount_blinds,
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

    let blind_share_decompressed = blind_share.decompress().
        ok_or(ZeiError::DecompressElementError)?;
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
    let amount_blind_low;
    let amount_blind_high;
    let type_blind;
    let shared_point = derive_point_from_blind_share(&input.blind_share, secret_key)?;
    if confidential_amount{
        let amount_bytes = hybrid_decrypt(input.lock_amount.as_ref().unwrap(), secret_key)?;
        amount = u8_bigendian_slice_to_u64(amount_bytes.as_slice());
        amount_blind_low = compute_blind_factor(&shared_point, "amount_low");
        amount_blind_high = compute_blind_factor(&shared_point, "amount_high");
    }
    else{
        amount = input.amount.unwrap();
        amount_blind_low = Scalar::default();
        amount_blind_high = Scalar::default();
    }

    if confidential_asset{
        asset_type.copy_from_slice(hybrid_decrypt(input.lock_type.as_ref().unwrap(), secret_key)?.as_slice());
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
        amount_blinds: (amount_blind_low, amount_blind_high),
        type_blind,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::basic_crypto::signatures::XfrKeyPair;
    use crate::errors::ZeiError::{XfrVerifyAmountError, XfrVerifyAssetError, XfrCreationAmountError, XfrCreationAssetError, XfrVerifyConfidentialAssetError, XfrVerifyConfidentialAmountError, XfrVerifyIssuerTrackingAssetTypeError, XfrVerifyIssuerTrackingAmountError};
    use serde::ser::{Serialize};
    use serde::de::{Deserialize};
    use crate::basic_crypto::elgamal::{elgamal_generate_secret_key, elgamal_derive_public_key};


    fn do_test_build_open_asset_record(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool){
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

        let issuer_public_key = match asset_tracking{
            true => {
                let sk = elgamal_generate_secret_key(&mut prng);
                Some(elgamal_derive_public_key(&pc_gens.B, &sk))
            },
            false => None
        };

        let open_ar = build_open_asset_record(
            &mut prng,
            &pc_gens,
            &asset_record,
            confidential_amount, confidential_asset, &issuer_public_key);

        assert_eq!(amount, open_ar.amount);
        assert_eq!(asset_type, open_ar.asset_type);
        assert_eq!(keypair.get_pk_ref(), &open_ar.asset_record.public_key);

        let mut expected_bar_amount = None;
        let mut expected_bar_asset_type = None;
        let mut expected_bar_amount_commitment = None;
        let mut expected_bar_asset_type_commitment = None;
        let mut expected_bar_lock_amount_none = false;
        let mut expected_bar_lock_type_none = false;

        if confidential_amount {
            let (low, high) = u64_to_u32_pair(amount);
            let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0).compress();
            let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1).compress();
            expected_bar_amount_commitment = Some((commitment_low, commitment_high));
        }
        else{
            expected_bar_amount = Some(amount);
            expected_bar_lock_amount_none = true;
        }

        if confidential_asset {
            let type_as_u128 = u8_bigendian_slice_to_u128(&asset_record.asset_type[..]);
            let type_scalar = Scalar::from(type_as_u128);
            expected_bar_asset_type_commitment = Some(pc_gens.commit(type_scalar, open_ar.type_blind).compress());
        }
        else{
            expected_bar_asset_type = Some(asset_type);
            expected_bar_lock_type_none = true;
        }
        assert_eq!(expected_bar_amount, open_ar.asset_record.amount);
        assert_eq!(expected_bar_amount_commitment, open_ar.asset_record.amount_commitments);
        assert_eq!(expected_bar_lock_amount_none, open_ar.asset_record.lock_amount.is_none());
        assert_eq!(expected_bar_asset_type, open_ar.asset_record.asset_type);
        assert_eq!(expected_bar_asset_type_commitment, open_ar.asset_record.asset_type_commitment);
        assert_eq!(expected_bar_lock_type_none, open_ar.asset_record.lock_type.is_none());

        assert_eq!(asset_tracking, open_ar.asset_record.issuer_public_key.is_some());
        assert_eq!(asset_tracking && confidential_asset, open_ar.asset_record.issuer_lock_type.is_some());
        assert_eq!(asset_tracking && confidential_amount, open_ar.asset_record.issuer_lock_amount.is_some());
        //TODO check tracing identity
    }

    #[test]
    fn test_build_open_asset_record() {
        do_test_build_open_asset_record(false, false, false);
        do_test_build_open_asset_record(false, true, false);
        do_test_build_open_asset_record(true, false, false);
        do_test_build_open_asset_record(true, true, false);
        do_test_build_open_asset_record(false, false, true);
        do_test_build_open_asset_record(false, true, true);
        do_test_build_open_asset_record(true, false, true);
        do_test_build_open_asset_record(true, true, true);
    }

    fn create_xfr(
        prng: &mut ChaChaRng,
        input_amounts: &[u64], output_amounts: &[u64],
        asset_type: AssetType,
        confidential_amount: bool, confidential_asset: bool, asset_tracking: bool)
        -> (XfrNote, Vec<XfrKeyPair>, Vec<OpenAssetRecord>, Vec<AssetRecord>, Vec<XfrKeyPair>){

        let pc_gens = PedersenGens::default();
        let issuer_public_key = match asset_tracking{
            true => {
                let sk = elgamal_generate_secret_key(prng);
                Some(elgamal_derive_public_key(&pc_gens.B, &sk))
            },
            false => None
        };

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
                confidential_amount, confidential_asset, &issuer_public_key)
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

    fn do_transfer_tests(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool) {
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
            confidential_amount, confidential_asset, asset_tracking);

        let xfr_note = tuple.0;
        let inkeys = tuple.1;
        let mut inputs = tuple.2;
        let mut outputs = tuple.3;

        // test 1: simple transfer
        assert_eq!(Ok(()), verify_xfr_note(&xfr_note), "Simple transaction should verify ok");

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
            let (low, high) = u64_to_u32_pair(0xFFFFFFFFFF);
            let commitment_low = pc_gens.commit(Scalar::from(low),Scalar::random(&mut prng)).compress();
            let commitment_high = pc_gens.commit(Scalar::from(high),Scalar::random(&mut prng)).compress();
            xfr_note.body.outputs[3].amount_commitments = Some((commitment_low, commitment_high));
            error = XfrVerifyConfidentialAmountError;
        }
        else{
            xfr_note.body.outputs[3].amount = Some(0xFFFFFFFFFF);
            error = XfrVerifyAmountError;
        }
        xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
        assert_eq!(Err(error), verify_xfr_note(&xfr_note),
                   "Confidential transfer with invalid amounts should fail verification");


        //test 3: exact amount transfer
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
                                            confidential_amount, confidential_asset, &None);
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
                                            confidential_amount, confidential_asset, &None);
        let mut xfr_note = gen_xfr_note(&mut prng, inputs.as_slice(), outputs.as_slice(), inkeys.as_slice()).unwrap();
        let old_asset_com = xfr_note.body.inputs[1].asset_type_commitment.clone();
        let old_asset_type = xfr_note.body.inputs[1].asset_type.clone();
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

        //test 5 asset tracing
        xfr_note.body.inputs[1].asset_type_commitment = old_asset_com;
        xfr_note.body.inputs[1].asset_type = old_asset_type;
        xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
        assert_eq!(Ok(()), verify_xfr_note(&xfr_note),
                   "Transfer is ok at this point");

        for (proof, bar) in xfr_note.body.proofs.asset_tracking_proof.iter().zip(xfr_note.body.outputs.iter()) {
            assert_eq!(asset_tracking, proof.is_some());
            assert_eq!(asset_tracking && confidential_asset, proof.is_some() && proof.as_ref().unwrap().asset_type_proof.is_some());
            assert_eq!(asset_tracking && confidential_asset, bar.issuer_lock_type.is_some(), "Issuer lock type contain value only when asset tracing and confidential asset");
            assert_eq!(asset_tracking && confidential_amount, proof.is_some() && proof.as_ref().unwrap().amount_proof.is_some());
            assert_eq!(asset_tracking && confidential_amount, bar.issuer_lock_amount.is_some(), "Issuer lock amount contain value only when asset tracing and confidential asset");
            //TODO check identity proof
        }
        // test bad asset tracking
        if asset_tracking && confidential_asset {
            let old_enc = xfr_note.body.outputs[0].issuer_lock_type.as_ref().unwrap().clone();
            let new_enc = (old_enc.e2.decompress().unwrap() + pc_gens.B).compress(); //adding 1 to the exponent
            xfr_note.body.outputs[0].issuer_lock_type = Some(ElGamalCiphertext{e1:old_enc.e1, e2: new_enc});
            xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
            assert_eq!(Err(XfrVerifyIssuerTrackingAssetTypeError), verify_xfr_note(&xfr_note),
                       "Transfer verification should fail due to error in AssetTracing verification");

            //restore
            xfr_note.body.outputs[0].issuer_lock_type = Some(old_enc);
            xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
            assert_eq!(Ok(()), verify_xfr_note(&xfr_note),
                       "Transfer is ok");
        }
        // test bad amount tracking
        if asset_tracking && confidential_amount {
            let old_enc = xfr_note.body.outputs[0].issuer_lock_amount.as_ref().unwrap();
            let new_enc = (old_enc.0.e2.decompress().unwrap() + pc_gens.B).compress(); //adding 1 to the exponent
            xfr_note.body.outputs[0].issuer_lock_amount = Some((ElGamalCiphertext{e1:old_enc.0.e1, e2: new_enc} , ElGamalCiphertext{e1:old_enc.1.e1, e2: old_enc.1.e2}));
            xfr_note.multisig = compute_transfer_multisig(&xfr_note.body, inkeys.as_slice()).unwrap();
            assert_eq!(Err(XfrVerifyIssuerTrackingAmountError), verify_xfr_note(&xfr_note),
                       "Transfer verification should fail due to error in AssetTracing verification");
        }
    }

    #[test]
    fn test_transfer_not_confidential() {
        /*! I test non confidential transfers*/
        do_transfer_tests(false, false, false);
        do_transfer_tests(false, false, true);
    }

    #[test]
    fn test_transfer_confidential_amount_plain_asset() {
        /*! I test confidential amount transfers*/
        do_transfer_tests(true, false, false);
        do_transfer_tests(true, false, true);
    }

    #[test]
    fn test_transfer_confidential_asset_plain_amount() {
        /*! I test confidential asset transfers*/
        do_transfer_tests(false, true, false);
        do_transfer_tests(false, true, true);
    }

    #[test]
    fn test_transfer_confidential() {
        /*! I test confidential amount and confidential asset transfers*/
        do_transfer_tests(true, true, false);
        do_transfer_tests(true, true, true);
    }

    fn do_test_transfer_multisig(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool){
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
            confidential_asset, asset_tracking);
        assert_eq!(Ok(()), verify_transfer_multisig(&xfr_note));
    }

    #[test]
    fn test_transfer_multisig(){
        do_test_transfer_multisig(false, false, false);
        do_test_transfer_multisig(false, true, false);
        do_test_transfer_multisig(true, false, false);
        do_test_transfer_multisig(true, true, false);
        do_test_transfer_multisig(false, false, true);
        do_test_transfer_multisig(false, true, true);
        do_test_transfer_multisig(true, false, true);
        do_test_transfer_multisig(true, true, true);
    }

    fn do_test_open_asset_record(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool){
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
            confidential_asset,
            asset_tracking
        );

        let secret_key = outkeys.get(0).unwrap().get_sk_ref();
        let open_ar = open_asset_record(
            &xfr_note.body.outputs[0], secret_key).unwrap();

        assert_eq!(&open_ar.asset_record, &xfr_note.body.outputs[0]);
        assert_eq!(open_ar.amount, 30u64);
        assert_eq!(open_ar.asset_type, [1u8;16]);

        if confidential_amount{
            let (low, high) = u64_to_u32_pair(open_ar.amount);
            let commitment_low = pc_gens.commit(Scalar::from(low), open_ar.amount_blinds.0).compress();
            let commitment_high = pc_gens.commit(Scalar::from(high), open_ar.amount_blinds.1).compress();
            let derived_commitment = (commitment_low, commitment_high);
            assert_eq!(derived_commitment, open_ar.asset_record.amount_commitments.unwrap());
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
        do_test_open_asset_record(false, false, false);
        do_test_open_asset_record(true, false, false);
        do_test_open_asset_record(false, true, false);
        do_test_open_asset_record(true, true, false);
        do_test_open_asset_record(true, true, true);
    }

    fn do_test_serialization(confidential_amount: bool, confidential_asset: bool, asset_tracking: bool){
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
            confidential_asset,
            asset_tracking,
        );

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
        do_test_serialization(false, false, false);
        do_test_serialization(false, true, false);
        do_test_serialization(true, false, false);
        do_test_serialization(true, true, false);
        do_test_serialization(true, false, true);
        do_test_serialization(true, true, true);
    }
}
