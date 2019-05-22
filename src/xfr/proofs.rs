use bulletproofs::{RangeProof, PedersenGens};
use crate::algebra::bls12_381::{BLSG1, BLSG2, BLSScalar, BLSGt};
use crate::algebra::groups::{Scalar as ScalarTrait, Group};
use crate::basic_crypto::elgamal::{ElGamalCiphertext, ElGamalPublicKey, elgamal_encrypt};
use crate::credentials::AttrsRevealProof;
use crate::errors::ZeiError;
use crate::proofs::chaum_pedersen::{chaum_pedersen_verify_multiple_eq, ChaumPedersenProofX, chaum_pedersen_prove_multiple_eq};
use crate::proofs::identity::{PoKAttrs, pok_attrs_prove, pok_attrs_verify};
use crate::proofs::pedersen_elgamal::{pedersen_elgamal_eq_prove, pedersen_elgamal_eq_verify};
use crate::setup::{MAX_PARTY_NUMBER, BULLET_PROOF_RANGE, PublicParams};
use crate::xfr::structs::{OpenAssetRecord, AssetTrackingProof, XfrBody, IdRevealPolicy, XfrRangeProof, BlindAssetRecord};
use crate::utils::{u8_bigendian_slice_to_u128, u64_to_u32_pair, min_greater_equal_power_of_two};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand::{CryptoRng, Rng};

const POW_2_32: u64 = 0xFFFFFFFFu64 + 1;

// BLS12_381 implementation of confidential identity reveal protocol
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfIdReveal{
    ctexts: Vec<ElGamalCiphertext<BLSG1>>,
    attr_reveal_proof: AttrsRevealProof<BLSG1, BLSG2, BLSScalar>,
    pok_attrs: PoKAttrs<BLSG1, BLSG2, BLSScalar>,
}


pub(crate) fn tracking_proofs<R: CryptoRng + Rng>(
    prng: &mut R,
    outputs:&[OpenAssetRecord],
    identity_proofs: &[Option<ConfIdReveal>],
)->Result<Vec<(Option<AssetTrackingProof>)>, ZeiError>{
    let mut v = vec![];
    for (output, identity_proof) in outputs.iter().zip(identity_proofs.iter()) {
        match output.asset_record.issuer_public_key.as_ref(){
            None => v.push(None),
            Some(public_key) => {
                let mut asset_type_proof = None;
                let mut amount_proof = None;
                //do asset
                if output.asset_record.asset_type_commitment.is_some() {
                    let asset_blind = &output.type_blind;
                    let asset_scalar =
                        Scalar::from(u8_bigendian_slice_to_u128(&output.asset_type[..]));
                    let asset_com = output
                        .asset_record
                        .asset_type_commitment
                        .as_ref()
                        .ok_or(ZeiError::InconsistentStructureError)?;
                    let asset_ctext = output
                        .asset_record
                        .issuer_lock_type
                        .as_ref()
                        .ok_or(ZeiError::InconsistentStructureError)?;
                    asset_type_proof = Some(pedersen_elgamal_eq_prove(
                        prng,
                        &asset_scalar,
                        asset_blind,
                        &public_key.eg_ristretto_pub_key,
                        asset_ctext,
                        &asset_com.decompress().unwrap(),
                    ));
                }
                if output.asset_record.amount_commitments.is_some() {
                    let (amount_low, amount_high) = u64_to_u32_pair(output.amount);
                    let ctexts = output
                        .asset_record
                        .issuer_lock_amount
                        .as_ref()
                        .ok_or(ZeiError::InconsistentStructureError)?;
                    let commitments = output
                        .asset_record
                        .amount_commitments
                        .as_ref()
                        .ok_or(ZeiError::InconsistentStructureError)?;
                    let proof_low = pedersen_elgamal_eq_prove(
                        prng,
                        &Scalar::from(amount_low),
                        &output.amount_blinds.0,
                        &public_key.eg_ristretto_pub_key,
                        &ctexts.0,
                        &commitments.0.decompress().unwrap(),
                    );
                    let proof_high = pedersen_elgamal_eq_prove(
                        prng,
                        &Scalar::from(amount_high),
                        &output.amount_blinds.1,
                        &public_key.eg_ristretto_pub_key,
                        &ctexts.1,
                        &commitments.1.decompress().unwrap(),
                    );
                    amount_proof = Some((proof_low, proof_high));
                }
                v.push(Some(AssetTrackingProof {
                    amount_proof,
                    asset_type_proof,
                    identity_proof: identity_proof.clone() }));
            }
        }
    }

    Ok(v)
}

pub(crate) fn verify_issuer_tracking_proof(
    xfr_body: &XfrBody,
    attribute_reveal_policies: &[Option<IdRevealPolicy>]
) -> Result<(), ZeiError>
{

    match xfr_body.inputs[0].issuer_public_key.as_ref() {
        None => Ok(()), //no asset tracing required
        Some(issuer_pk) => {
            let conf_asset = xfr_body.inputs[0].asset_type.is_none();
            let conf_amount = xfr_body.inputs[0].amount.is_none();

            for ((proof, asset_record),attr_reveal_policy) in
                xfr_body.proofs.asset_tracking_proof.iter().zip(xfr_body.outputs.iter()).zip(attribute_reveal_policies) {
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
                    pedersen_elgamal_eq_verify(&issuer_pk.eg_ristretto_pub_key, ctext, &commitment.decompress().unwrap(), asset_proof).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAssetTypeError)?;
                }
                if conf_amount {
                    let ctext = asset_record.issuer_lock_amount.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let commitment = asset_record.amount_commitments.as_ref().
                        ok_or(ZeiError::InconsistentStructureError)?;
                    let amount_proof = proof.as_ref().unwrap().amount_proof.
                        as_ref().ok_or(ZeiError::InconsistentStructureError)?;
                    pedersen_elgamal_eq_verify(&issuer_pk.eg_ristretto_pub_key, &ctext.0, &commitment.0.decompress().unwrap(), &amount_proof.0).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAmountError)?;
                    pedersen_elgamal_eq_verify(&issuer_pk.eg_ristretto_pub_key, &ctext.1, &commitment.1.decompress().unwrap(), &amount_proof.1).
                        map_err(|_| ZeiError::XfrVerifyIssuerTrackingAmountError)?;
                }
                match attr_reveal_policy{
                    None => {},
                    Some(policy) => {
                        verify_attribute_reveal_policy(&issuer_pk.eg_blsg1_pub_key, proof, policy).map_err(|_| ZeiError::XfrVerifyIssuerTrackingIdentityError)?;
                    }
                }
            }
            Ok(())
        }
    }
}

/**** Confidential Identity Attributes Reveal *****/

fn verify_attribute_reveal_policy(
    asset_issuer_pk: &ElGamalPublicKey<BLSG1>,
    option_proof: &Option<AssetTrackingProof>,
    policy: &IdRevealPolicy) -> Result<(), ZeiError>
{
    match option_proof{
        None => return Err(ZeiError::InconsistentStructureError),
        Some(asset_tracking_proof) => {
            match asset_tracking_proof.identity_proof.as_ref(){
                None => return Err(ZeiError::XfrVerifyIssuerTrackingIdentityError),
                Some(identity_proof) => {
                    verify_conf_id_reveal(
                        &identity_proof,
                        asset_issuer_pk,
                        policy,
                    )
                }
            }
        }
    }
}

pub fn create_conf_id_reveal<R: Rng + CryptoRng>(
    prng: &mut R,
    attrs: &[BLSScalar],
    policy: &IdRevealPolicy,
    attr_reveal_proof: &AttrsRevealProof<BLSG1, BLSG2, BLSScalar>,
    asset_issuer_public_key: &ElGamalPublicKey<BLSG1>,
)
    -> Result<ConfIdReveal, ZeiError>
{
    let mut ctexts = vec![];
    let mut rands = vec![];
    let base = BLSG1::get_base();
    let mut revealed_attrs = vec![];
    for (attr,b) in attrs.iter().zip(policy.bitmap.iter()){
        if *b {
            let r = BLSScalar::random_scalar(prng);
            let ctext = elgamal_encrypt::<BLSG1>(
                &base, attr, &r, asset_issuer_public_key);
            rands.push(r);
            ctexts.push(ctext);
            revealed_attrs.push(attr.clone());
        }
    }

    let pok_attrs_proof = pok_attrs_prove::<_,BLSGt>(
        prng,
        revealed_attrs.as_slice(),
        &policy.cred_issuer_pub_key,
        asset_issuer_public_key,
        rands.as_slice(),
        policy.bitmap.as_slice(),
    )?;

    Ok(ConfIdReveal{
        ctexts,
        attr_reveal_proof:attr_reveal_proof.clone(),
        pok_attrs: pok_attrs_proof,
    })

}

pub fn verify_conf_id_reveal(
    conf_id_reveal: &ConfIdReveal,
    asset_issuer_public_key: &ElGamalPublicKey<BLSG1>,
    attr_reveal_policy: &IdRevealPolicy,
) -> Result<(), ZeiError>
{
    pok_attrs_verify::<BLSGt>(
        &conf_id_reveal.attr_reveal_proof,
        &conf_id_reveal.ctexts,
        &conf_id_reveal.pok_attrs,
        asset_issuer_public_key,
        &attr_reveal_policy.cred_issuer_pub_key,
        &attr_reveal_policy.bitmap,
    )
}

/**** Range Proofs *****/

/// I compute a range proof for confidential amount transfers.
/// The proof guarantees that output amounts and difference between total input
/// and total output are in the range [0,2^{64} - 1]
pub(crate) fn range_proof(
    inputs: &[OpenAssetRecord],
    outputs: &[OpenAssetRecord],
) -> Result<XfrRangeProof, ZeiError> {
    let num_output = outputs.len();
    let upper_power2 = min_greater_equal_power_of_two((2 * num_output + 2) as u32) as usize;
    if upper_power2 > MAX_PARTY_NUMBER {
        return Err(ZeiError::RangeProofProveError);
    }

    let pow2_32 = Scalar::from(POW_2_32);
    let mut params = PublicParams::new();

    //build values vector (out amounts + amount difference)
    let in_amounts: Vec<u64> = inputs.iter().map(|x| x.amount).collect();
    let out_amounts: Vec<u64> = outputs.iter().map(|x| x.amount).collect();
    let in_total = in_amounts.iter().sum::<u64>();
    let out_total = out_amounts.iter().sum::<u64>();
    let xfr_diff = if in_total >= out_total {
        in_total - out_total
    } else {
        return Err(ZeiError::RangeProofProveError);
    };
    let mut values = Vec::with_capacity(out_amounts.len() + 1);
    for x in out_amounts {
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
    for (blind_low, blind_high) in in_blind_low.iter().zip(in_blind_high.iter()) {
        in_blind_sum = in_blind_sum + (blind_low + blind_high * pow2_32); //2^32
    }
    let mut range_proof_blinds = Vec::with_capacity(upper_power2);
    let mut out_blind_sum = Scalar::zero();
    for (blind_low, blind_high) in out_blind_low.iter().zip(out_blind_high.iter()) {
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

    let (range_proof, coms) = RangeProof::prove_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut params.transcript,
        values.as_slice(),
        range_proof_blinds.as_slice(),
        BULLET_PROOF_RANGE,
    )
        .map_err(|_| ZeiError::RangeProofProveError)?;

    let diff_com_low = coms[2 * num_output];
    let diff_com_high = coms[2 * num_output + 1];
    Ok(XfrRangeProof {
        range_proof,
        xfr_diff_commitment_low: diff_com_low,
        xfr_diff_commitment_high: diff_com_high,
    })
}

pub(crate) fn verify_confidential_amount(
    inputs: &[BlindAssetRecord],
    outputs: &[BlindAssetRecord],
    range_proof: &XfrRangeProof
) -> Result<(), ZeiError>
{
    let num_output = outputs.len();
    let upper_power2 = min_greater_equal_power_of_two((2 * num_output + 2) as u32) as usize;
    if upper_power2 > MAX_PARTY_NUMBER {
        return Err(ZeiError::XfrVerifyConfidentialAmountError);
    }
    let pow2_32 = Scalar::from(POW_2_32);
    let params = PublicParams::new();
    let mut transcript = Transcript::new(b"Zei Range Proof");

    // 1. verify proof commitment to transfer's input - output amounts match proof commitments
    let mut total_input_com = RistrettoPoint::identity();
    for bar in inputs.iter() {
        let coms = bar
            .amount_commitments
            .as_ref()
            .ok_or(ZeiError::InconsistentStructureError)?;
        let com_low = (coms.0)
            .decompress()
            .ok_or(ZeiError::DecompressElementError)?;
        let com_high = (coms.1)
            .decompress()
            .ok_or(ZeiError::DecompressElementError)?;
        total_input_com += com_low + com_high * pow2_32;
    }

    let mut total_output_com = RistrettoPoint::identity();
    let mut range_coms: Vec<CompressedRistretto> = Vec::with_capacity(2 * num_output + 2);
    for bar in outputs.iter() {
        let coms = bar
            .amount_commitments
            .as_ref()
            .ok_or(ZeiError::InconsistentStructureError)?;
        let com_low = (coms.0)
            .decompress()
            .ok_or(ZeiError::DecompressElementError)?;
        let com_high = (coms.1)
            .decompress()
            .ok_or(ZeiError::DecompressElementError)?;
        total_output_com += com_low + com_high * pow2_32;

        range_coms.push(coms.0);
        range_coms.push(coms.1);
        //output_com.push(com_low + com_high * Scalar::from(0xFFFFFFFF as u64 + 1));
    }
    let derived_xfr_diff_com = total_input_com - total_output_com;

    let proof_xfr_com_low = range_proof
        .xfr_diff_commitment_low
        .decompress()
        .ok_or(ZeiError::DecompressElementError)?;
    let proof_xfr_com_high = range_proof
        .xfr_diff_commitment_high
        .decompress()
        .ok_or(ZeiError::DecompressElementError)?;
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

    range_proof.range_proof.verify_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut transcript,
        range_coms.as_slice(),
        BULLET_PROOF_RANGE).map_err(|_| ZeiError::XfrVerifyConfidentialAmountError)

}

/**** Asset Equality Proofs *****/

/// I compute asset equality proof for confidential asset transfers
pub(crate) fn asset_proof<R: CryptoRng + Rng>(
    prng: &mut R,
    pc_gens: &PedersenGens,
    inputs: &[OpenAssetRecord],
    open_outputs: &[OpenAssetRecord],
) -> Result<ChaumPedersenProofX, ZeiError> {
    let asset = inputs[0].asset_type;
    let asset_scalar = Scalar::from(u8_bigendian_slice_to_u128(&asset[..]));

    let mut asset_coms = vec![];
    let mut asset_blinds = vec![];

    for x in inputs.iter() {
        asset_coms.push(
            x.asset_record
                .asset_type_commitment
                .unwrap()
                .decompress()
                .unwrap(),
        );
        asset_blinds.push(x.type_blind);
    }
    for x in open_outputs.iter() {
        asset_coms.push(
            x.asset_record
                .asset_type_commitment
                .unwrap()
                .decompress()
                .unwrap(),
        );
        asset_blinds.push(x.type_blind);
    }

    let proof = chaum_pedersen_prove_multiple_eq(
        prng,
        pc_gens,
        &asset_scalar,
        asset_coms.as_slice(),
        asset_blinds.as_slice(),
    )?;

    Ok(proof)
}

pub(crate) fn verify_confidential_asset(
    inputs: &[BlindAssetRecord],
    outputs: &[BlindAssetRecord],
    asset_proof: &ChaumPedersenProofX
) -> Result<(), ZeiError>
{
    let pc_gens = PedersenGens::default();
    let mut asset_commitments: Vec<RistrettoPoint> = inputs
        .iter()
        .map(|x| x.asset_type_commitment.unwrap().decompress().unwrap())
        .collect();

    let out_asset_commitments: Vec<RistrettoPoint> = outputs
        .iter()
        .map(|x| x.asset_type_commitment.unwrap().decompress().unwrap())
        .collect();

    asset_commitments.extend(out_asset_commitments.iter());

    match chaum_pedersen_verify_multiple_eq(
        &pc_gens,
        asset_commitments.as_slice(),
        asset_proof)? {
        true => Ok(()),
        false => Err(ZeiError::XfrVerifyConfidentialAssetError),
    }
}
