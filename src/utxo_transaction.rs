use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use crate::asset::Asset;
use rand::CryptoRng;
use rand::Rng;
use crate::setup::PublicParams;
use bulletproofs::{PedersenGens, RangeProof};
use blake2::{Blake2b,Digest};
use crate::errors::Error as ZeiError;
use crate::proofs::chaum_perdersen::{chaum_pedersen_prove_multiple_eq, ChaumPedersenCommitmentEqProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use crate::setup::BULLET_PROOF_RANGE;
use crate::proofs::chaum_perdersen::chaum_pedersen_verify_multiple_eq;
use crate::encryption::ZeiRistrettoCipher;
use schnorr::Signature;
use std::collections::HashSet;
use schnorr::PublicKey;
use schnorr::SecretKey;
use core::borrow::Borrow;


pub struct TxAddressParams{
    amount: u64, //input or output amount
    amount_commitment: Option<CompressedRistretto>, //input or output balance
    amount_blinding: Option<Scalar>, //none for output
    asset_type: String,
    asset_type_commitment: Option<CompressedRistretto>, //None if non confidential asset or account is new, or Utxo model
    asset_type_blinding: Option<Scalar>, //None if non confidential asset or account is new or Utxo model
    public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

pub struct TxPublicAddressInfo{
    amount: Option<u64>, //None only if confidential
    amount_commitment: Option<CompressedRistretto>, //None if not confidential balance
    asset_type: Option<String>, //None only if confidential asset
    asset_type_commitment: Option<CompressedRistretto>,  //None if not confidential balance
    public_key: PublicKey, //source or destination
}

pub struct TxDestinationInfo{
    public_info: TxPublicAddressInfo,
    lock_box: ZeiRistrettoCipher,
}

pub struct TxProofs{
    range_proof: Option<RangeProof>,
    asset_proof: Option<(ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof)>,
}

pub struct TxBody{
    source_info: Vec<TxPublicAddressInfo>,
    destination_info: Vec<TxDestinationInfo>,
    proofs: TxProofs,
    confidential_amount:bool,
    confidential_asset: bool,
}

pub struct Tx{
    body: TxBody,
    signatures: Vec<Signature>,
}

impl Tx{
    pub fn new<R: CryptoRng + Rng>(
        prng: &mut R,
        input: &[TxAddressParams],
        output: &[TxAddressParams],
        confidential_amount: bool,
        confidential_asset: bool,
    ) -> Result<Tx, ZeiError> {

        let pc_gens = PedersenGens::default();

        //output values to be build
        let mut range_proof = None;
        let mut asset_proof = None;
        let mut source_info = Vec::new();
        let mut destination_info= Vec::new();

        //tmp values
        let mut src_amount_option = vec![];
        let mut dst_amount_option = vec![];
        let mut dst_asset_com: Vec<Option<CompressedRistretto>>;
        let mut dst_asset_blind: Vec<Option<Scalar>>;
        let mut out_amount_com_option: Vec<Option<CompressedRistretto>>;
        let out_amount_blind: Vec<Scalar>;

        //extract values from input struct
        let src_amount_com_option: Vec<Option<CompressedRistretto>> =
            input.iter().map(|x| x.amount_commitment).collect();
        let src_amount_blind_option: Vec<Option<Scalar>> =
            input.iter().map(|x| x.amount_blinding).collect();
        let src_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            input.iter().map(|x| x.asset_type_commitment).collect();
        let src_asset_type_blind_option: Vec<Option<Scalar>> =
            input.iter().map(|x| x.asset_type_blinding).collect();
        let src_pks: Vec<PublicKey> =
            input.iter().map(|x| x.public_key).collect();
        let in_amounts: Vec<u64> = input.iter().map(|x| x.amount ).collect();

        //extract values from output struct
        let dst_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            output.iter().map(|x| x.asset_type_commitment).collect();
        let dst_asset_type_blind_option: Vec<Option<Scalar>> =
            output.iter().map(|x| x.asset_type_blinding).collect();
        let destination_public_keys: Vec<PublicKey> =
            output.iter().map(|x| x.public_key ).collect();

        //do amount handling
        if confidential_amount {
            //let in_amounts: Vec<u64> = input.iter().map(|x| x.amount ).collect();
            let mut out_amounts: Vec<u64> = output.iter().map(|x| x.amount ).collect();

            let mut src_amount_blind: Vec<Scalar> = src_amount_blind_option.iter().map(|x| x.unwrap()).collect();

            let (proof, tx_com, tx_blind) =
                Tx::build_range_proof(
                    prng,
                    src_amount_blind.as_slice(),
                    in_amounts.as_slice(),
                    out_amounts.as_slice(),
                    destination_public_keys.as_slice()
                )?;
            range_proof = Some(proof);

            out_amount_com_option = tx_com.into_iter().map(|x| Some(x)).collect();
            out_amount_blind = tx_blind;

            for _ in 0..input.len(){
               src_amount_option.push(None);
            }
            for _ in 0..output.len(){
               dst_amount_option.push(None);
            }
        }
        else{
            src_amount_option = input.iter().map(|x| Some(x.amount)).collect();
            dst_amount_option = output.iter().map(|x| Some(x.amount)).collect();
            out_amount_com_option = (0..output.len()).map(|_| None).collect();
        }

        if confidential_asset{
            let src_asset_com: Vec<CompressedRistretto> = src_asset_type_com_option.iter().map(|x| x.unwrap()).collect();
            let src_asset_blind: Vec<Scalar> = src_asset_type_blind_option.iter().map(|x| x.unwrap()).collect();


            let (proof_asset, out_asset_com, out_asset_blind) = Tx::build_asset_proof(
                prng,
                &pc_gens,
                &input[0].asset_type,
                src_asset_com.as_slice(),
                src_asset_blind.as_slice(),
                dst_asset_type_com_option,
                dst_asset_type_blind_option,
                &destination_public_keys,
            )?;

            asset_proof = Some(proof_asset);
            dst_asset_com = vec![];
            dst_asset_blind = vec![];
            for (x,y) in out_asset_com.iter().zip(out_asset_blind.iter()) {
                dst_asset_com.push(Some(*x));
                dst_asset_blind.push(Some(*y))
            }
        }
        else{
            dst_asset_com = dst_asset_type_com_option;
            dst_asset_blind = dst_asset_type_blind_option;
        }

        //compute input struct
        for i in 0..input.len(){
            source_info.push(
                TxPublicAddressInfo{
                    amount: src_amount_option[i],
                    amount_commitment: src_amount_com_option[i],
                    asset_type: match confidential_asset{ true => None, false => Some(input[i].asset_type.clone())},
                    asset_type_commitment: src_asset_type_com_option[i],
                    public_key: src_pks[i],
                    }
            );
        }

        //compute output struct
        for i in 0..output.len(){
            destination_info.push(
                TxDestinationInfo{
                    public_info: TxPublicAddressInfo{
                        amount: dst_amount_option[i],
                        amount_commitment: out_amount_com_option[i],
                        asset_type: match confidential_asset {
                            true => None,
                            false => Some(output[i].asset_type.clone()),
                        },
                        asset_type_commitment: dst_asset_com[i],
                        public_key: destination_public_keys[i],
                    },
                    lock_box: ZeiRistrettoCipher::encrypt(
                        prng,
                        &destination_public_keys[i].get_curve_point()?.compress(),
                        &[0u8,0u8],
                    )?,
                }
            );
        }

        //compute signatures on transaction
        let mut signatures = vec![];
        let mut pk_set = HashSet::new();
        for i in 0..input.len(){
            let pk = src_pks[i].as_bytes();
            if pk_set.contains(pk) == false {
                pk_set.insert(pk);
                let sk = &input[i].secret_key;
                signatures.push(sk.as_ref().unwrap().sign::<blake2::Blake2b, R>(prng, &[0u8,0u8], &src_pks[i]));
            }
        }

        Ok(Tx::build_tx_struct(source_info, destination_info, range_proof, asset_proof, signatures))
    }

    fn build_asset_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        pc_gens: &PedersenGens,
        asset_type: &str,
        source_asset_commitments: &[CompressedRistretto],
        source_asset_blindings: &[Scalar],
        destination_asset_commitments: Vec<Option<CompressedRistretto>>,
        destination_asset_blindings: Vec<Option<Scalar>>,
        destination_public_keys: &Vec<PublicKey>,

    ) -> Result<((ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof),
                 Vec<CompressedRistretto>, Vec<Scalar>), ZeiError>
    {
        let num_output = destination_public_keys.len();
        let mut out_asset_com = vec![];
        let mut out_asset_blind = vec![];
        let asset = Asset {id: String::from(asset_type)};

        let mut all_asset_com = Vec::new();
        all_asset_com.extend_from_slice(source_asset_commitments);

        let mut all_asset_blind = Vec::new();
        all_asset_blind.extend_from_slice(source_asset_blindings);

        //create commitments and blindings if they don't exits (UTXO or new type for account)
        for i in 0..num_output{
            if destination_asset_commitments.len() >= i || destination_asset_commitments[i].is_none() {
                let (asset_comm, asset_blind) =
                    compute_asset_commitment(
                        prng, pc_gens, &destination_public_keys[i], &asset)?;
                out_asset_com.push(asset_comm.compress());
                out_asset_blind.push(asset_blind);
            }
            else{
                out_asset_com.push(destination_asset_commitments[i].unwrap());
                out_asset_blind.push(destination_asset_blindings[i].unwrap());

            }
        }

        all_asset_com.extend(out_asset_com.iter());
        all_asset_blind.extend(out_asset_blind.iter());

        let asset_as_scalar = asset.compute_scalar_hash();

        let proof_asset = chaum_pedersen_prove_multiple_eq(
            prng,
            pc_gens,
            &asset_as_scalar,
            all_asset_com.as_slice(),
            all_asset_blind.as_slice())?;

        Ok((proof_asset, out_asset_com, out_asset_blind))
    }

    fn build_range_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        source_blindings: &[Scalar],
        source_amounts: &[u64],
        destination_amounts: &[u64],
        destination_public_keys: &[PublicKey],
    )-> Result<(RangeProof, Vec<CompressedRistretto>, Vec<Scalar>),ZeiError>
    {

        let num_output = destination_amounts.len();

        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;
        let mut params = PublicParams::new(upper_power2);

        //build blindings for output commitments
        let mut blindings = Vec::new(); //for all outputs and sum(inputs) - sum(outputs)
        for i in 0..num_output {
            let blind = sample_blinding_factor(prng, &destination_public_keys[i])?;
            blindings.push(blind);
        }

        let blind_diff =
            source_blindings.iter().sum::<Scalar>() - blindings.iter().sum::<Scalar>();

        blindings.push(blind_diff);
        for _ in blindings.len()..upper_power2 {
            blindings.push(Scalar::from(0u8));
        }

        let source_amounts_addition = source_amounts.into_iter().sum::<u64>();
        let destination_amounts_addition = destination_amounts.into_iter().sum::<u64>();
        let tx_diff = if source_amounts_addition > destination_amounts_addition{
            source_amounts_addition - destination_amounts_addition
        }
        else{
            return Err(ZeiError::TxProofError);
        };

        let mut values = vec![];
        values.extend_from_slice(destination_amounts);
        values.push(tx_diff);
        for _ in values.len()..upper_power2 {
            values.push(0);
        }

        let (proof,commitments) = RangeProof::prove_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut params.transcript,
            values.as_slice(),
            blindings.as_slice(),
            BULLET_PROOF_RANGE)?;

        Ok((proof, commitments, blindings))
    }
    fn build_tx_struct(
        source_info: Vec<TxPublicAddressInfo>,
        destination_info: Vec<TxDestinationInfo>,
        range_proof: Option<RangeProof>,
        asset_proof: Option<(ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof)>,
        signatures: Vec<Signature>) -> Tx
    {
        let confidential_amount = range_proof.is_some();
        let confidential_asset = asset_proof.is_some();
        let proofs = TxProofs{
            range_proof,
            asset_proof,
        };
        let body = TxBody{
            source_info,
            destination_info,
            proofs,
            confidential_amount,
            confidential_asset,
        };
        Tx{
            body,
            signatures,
        }
    }

    pub fn verify(&self) -> bool{
        //1 signature TODO
        //2 amounts
        if self.body.confidential_amount {
            if !self.verify_confidential_ammount(){
                return false;
            }
        }
        else {
            let in_amount: Vec<u64> = self.body.source_info.iter().map(|x| x.amount.unwrap()).collect();
            let in_amount_sum = in_amount.iter().sum::<u64>();
            let out_amount: Vec<u64> = self.body.destination_info.iter().map(|x| x.public_info.amount.unwrap()).collect();
            let out_amount_sum = out_amount.iter().sum::<u64>();

            if out_amount_sum > in_amount_sum {
                return false;
            }
        }

        //3 asset
        if self.body.confidential_asset {
            return self.verify_confidential_asset();
        }
        //else
        let asset_id_option = self.body.source_info[0].asset_type.as_ref().unwrap();
        for x in self.body.source_info.iter(){
            let asset_id_option_i = x.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }

        for x in self.body.destination_info.iter(){
            let asset_id_option_i = x.public_info.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }
        true
    }

    fn verify_confidential_ammount(&self) -> bool {
        let num_output = self.body.destination_info.len();
        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

        let params = PublicParams::new(upper_power2);
        let mut transcript = Transcript::new(b"Zei Range Proof");

        let input_com: Vec<RistrettoPoint> = self.body.source_info.iter().
            map(|x| x.amount_commitment.unwrap().decompress().unwrap()).collect();

        let output_com: Vec<RistrettoPoint> = self.body.destination_info.iter().
            map(|x| x.public_info.amount_commitment.
                unwrap().decompress().unwrap()).collect();

        let diff_com = input_com.iter().sum::<RistrettoPoint>() -
            output_com.iter().sum::<RistrettoPoint>();

        let mut ranges_com: Vec<CompressedRistretto> = output_com.iter().
            map(|x| x.compress()).collect();

        ranges_com.push(diff_com.compress());

        for _ in (num_output + 1)..upper_power2 {
            ranges_com.push(CompressedRistretto::identity());
        }

        let verify_range_proof = self.body.proofs.range_proof.
            as_ref().unwrap().verify_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut transcript,
            ranges_com.as_slice(),
            BULLET_PROOF_RANGE,
        );

        verify_range_proof.is_ok()

    }

    fn verify_confidential_asset(&self) -> bool{
        let pc_gens = PedersenGens::default();
        let mut asset_commitments: Vec<CompressedRistretto> = self.body.source_info.iter().
            map(|x| x.asset_type_commitment.unwrap()).collect();

        let out_asset_commitments: Vec<CompressedRistretto> = self.body.destination_info.iter().
            map(|x| x.public_info.asset_type_commitment.unwrap()).collect();

        asset_commitments.extend(out_asset_commitments.iter());

        let proof = self.body.proofs.asset_proof.borrow().as_ref().unwrap();
        let r = chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            asset_commitments.as_slice(),
            proof,
        );

        r.unwrap()
    }

}
























/*
pub struct UtxoTx{
    input_balance_commitment: Vec<CompressedRistretto>,
    input_asset_commitment: Vec<CompressedRistretto>,// TODO replace and above this with UTXO address
    output_balance_commitment: Vec<CompressedRistretto>,
    output_asset_commitment: Vec<CompressedRistretto>,
    output_address: Vec<PublicKey>,
    range_proof: bulletproofs::RangeProof,
    proof_asset: (ChaumPedersenCommitmentEqProof, ChaumPedersenCommitmentEqProof),
}

impl UtxoTx{

    pub fn create<R: CryptoRng + Rng>(
        csprng: &mut R,
        input_balance: &[u64],
        input_balance_commitment: &[CompressedRistretto],
        input_balance_blinding: &[Scalar],
        input_asset_commitment: &[CompressedRistretto],
        input_asset_blinding: &[Scalar],
        asset_type: &Asset,
        output_address: &[PublicKey],
        output_amount: &[u64]) -> Result<UtxoTx, ZeiError>
    {
        /*! I create a transaction from n inputs to m ouputs.
 * Algorithm:
    For each output:
    - sample balance_blind_key
    - compute balance_blind_factor as SHA256 (balance_blind_key*OUT_PK_i)
    - compute amount_commitment (value = outputs_amounts[i], blind = blind_factor)
    - compute balance_blind_share = balance_blind_key * G
    - append balance_commitment and balance_blind_share to output
    - sample asset_blind_key
    - compute asset_blind_factor as SHA256 (asset_blind_key*OUT_PK_i)
    - compute asset_commitment (value = asset.id, blind = blind_factor)
    - append balance_commitment and balance_blind_share to output
    Append proof that all balances remain non-negative and that all asset types are equal
 */

        let num_input: usize = input_balance.len();
        let num_output: usize = output_amount.len();

        if num_input != input_balance_commitment.len() || num_input != input_balance_blinding.len()
            || num_input != input_asset_commitment.len() || num_input != input_asset_blinding.len()
            || num_output != output_address.len()
        {
            return Err(ZeiError::ParameterError);
        }
        //bullet proofs only allow power of 2 aggregation
        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

        let mut params = PublicParams::new(upper_power2);

        //range proofs and output commitments
        //commitements and blindings
        let mut blindings = Vec::new(); //for all outputs and sum(inputs) - sum(outputs)
        for i in 0..num_output {
            let blind = sample_blinding_factor(csprng, &output_address[i])?;
            blindings.push(blind);


            /*let output_commitment = params.pc_gens.commit(
                Scalar::from(output_amount[i]), blind);
            output_balance_commitment.push(output_commitment.compress());
            */
        }

        let blind_diff =
            input_balance_blinding.iter().sum::<Scalar>() - blindings.iter().sum::<Scalar>();
        blindings.push(blind_diff);

        for _ in blindings.len()..upper_power2 {
            blindings.push(Scalar::from(0u8));
        }

        let tx_diff = input_balance.into_iter().sum::<u64>() - output_amount.into_iter().sum::<u64>();

        let mut values = Vec::new();
        for i in output_amount.iter(){
            values.push(*i);
        }
        values.push(tx_diff);

        for _ in values.len()..upper_power2 {
            values.push(0);
        }

        let (proof,vec) = RangeProof::prove_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut params.transcript,
            //&[output_amount[0], output_amount[1], output_amount[2], output_amount[3], tx_diff],
            //&[blindings[0], blindings[1], blindings[2], blindings[3], blind_diff],
            values.as_slice(),
            blindings.as_slice(),
            BULLET_PROOF_RANGE)?;

        let mut output_balance_commitment = Vec::new();

        for i in 0..num_output{
            output_balance_commitment.push(vec[i]);
        }

        //asset commitment
        let mut asset_commitments = Vec::new();
        asset_commitments.extend_from_slice(input_asset_commitment);

        let mut asset_blindings = Vec::new();
        asset_blindings.extend_from_slice(input_asset_blinding);

        //add output
        let mut output_asset_commitment = vec![];
        let mut output_asset_blinding = vec![];
        for i in 0..num_output {
            let (asset_comm, asset_blind) =
                compute_asset_commitment(
                    csprng,&params.pc_gens,&output_address[i], &asset_type)?;

            output_asset_commitment.push(asset_comm.compress());
            output_asset_blinding.push(asset_blind);
        }

        asset_commitments.extend(output_asset_commitment.iter());
        asset_blindings.extend(output_asset_blinding.iter());

        let asset_as_scalar = asset_type.compute_scalar_hash();
        let proof_asset = chaum_pedersen_prove_multiple_eq(
            csprng, &params.pc_gens, &asset_as_scalar,
            asset_commitments.as_slice(), asset_blindings.as_slice())?;

        Ok(UtxoTx{
            input_balance_commitment: Vec::from(input_balance_commitment),
            input_asset_commitment: Vec::from(input_asset_commitment),
            output_balance_commitment: Vec::from(output_balance_commitment.as_slice()),
            output_asset_commitment: Vec::from(output_asset_commitment.as_slice()),
            output_address: Vec::from(output_address),
            range_proof: proof,
            proof_asset: proof_asset,
        })
    }

    pub fn verify(&self) -> Result<bool, ZeiError>{
        let num_output = self.output_address.len();
        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

        let params = PublicParams::new(upper_power2);
        let mut transcript = Transcript::new(b"Zei Range Proof");

        let mut input_com = vec![];
        for x in self.input_balance_commitment.iter(){
            input_com.push(x.decompress()?);
        }

        let mut output_com = vec![];
        for x in self.output_balance_commitment.iter(){
            output_com.push(x.decompress()?);
        }

        let mut range_proof_commitments: Vec<_> = output_com.iter().map(|x| x.compress()).collect();

        let diff_comm = input_com.iter().sum::<RistrettoPoint>() - output_com.iter().sum::<RistrettoPoint>();

        range_proof_commitments.push(diff_comm.compress());

        for _ in range_proof_commitments.len()..upper_power2{
            range_proof_commitments.push(RistrettoPoint::identity().compress());
        }

        let verify_range_proof = self.range_proof.verify_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut transcript,
            range_proof_commitments.as_slice(),
            BULLET_PROOF_RANGE,
        );

        if verify_range_proof.is_err(){
            return Ok(false);
        }

        let mut all_asset_commitment = self.input_asset_commitment.clone();
        all_asset_commitment.extend(self.output_asset_commitment.iter());
        let verify_asset_eq = chaum_pedersen_verify_multiple_eq(&params.pc_gens,
        all_asset_commitment.as_slice(), &self.proof_asset)?;

        Ok(verify_asset_eq)
    }

}

*/

#[inline]
fn smallest_greater_power_of_two(n: u32) -> u32{
    2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

fn compute_asset_commitment<R>(
    csprng: &mut R,
    pc_gens: &PedersenGens,
    address: &PublicKey,
    asset_type: &Asset) -> Result<(RistrettoPoint,Scalar), ZeiError>
    where R:CryptoRng + Rng,
{
    let blinding_factor = sample_blinding_factor(csprng, address)?;
    let asset_hash = asset_type.compute_scalar_hash();

    Ok((pc_gens.commit(asset_hash, blinding_factor), blinding_factor))
}

fn sample_blinding_factor<R>(csprng: &mut R, address: &PublicKey) -> Result<Scalar, ZeiError>
    where R: CryptoRng + Rng,
{
    let blinding_key = Scalar::random(csprng);
    let aux: RistrettoPoint = blinding_key * address.get_curve_point()?;
    let mut hasher = Blake2b::new();
    hasher.input(&aux.compress().to_bytes());
    Ok(Scalar::from_hash(hasher))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use schnorr::Keypair;

    fn build_address_params<R: CryptoRng + Rng>(prng: &mut R, amount: u64, asset: &str,
                                                input: bool, //input or output
                                                confidential_amount: bool,
                                                confidential_asset: bool) -> TxAddressParams {
        let pc_gens = PedersenGens::default();


        let mut amount_commitment = None;
        let mut amount_blinding = None;
        let mut asset_type_commitment = None;
        let mut asset_type_blinding = None;

        if confidential_amount && input{
            let blind = Scalar::random(prng);
            let com = pc_gens.commit(Scalar::from(amount), blind);

            amount_commitment = Some(com.compress());
            amount_blinding = Some(blind);
        }
        if confidential_asset {
            let a = Asset {
                id: String::from(asset),
            };
            let (com, blind) = a.compute_commitment(prng);
            asset_type_commitment = Some(com.compress());
            asset_type_blinding = Some(blind);
        }
        let key = Keypair::generate(prng);
        TxAddressParams {
            amount,
            amount_commitment,
            amount_blinding,
            asset_type: String::from(asset),
            asset_type_commitment,
            asset_type_blinding,
            public_key: key.public,
            secret_key: Some(key.secret),
        }
    }

    #[test]
    fn test_transaction_not_confidential() {
        let asset_id = "default_currency";
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let addr1 = build_address_params(&mut prng, 10u64,
                                         asset_id, true, false, false);

        let addr2 = build_address_params(&mut prng, 10u64,
                                         asset_id, true, false, false);

        let addr3 = build_address_params(&mut prng, 10u64,
                                         asset_id, true, false, false);

        let addr4 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,false, false);

        let addr5 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,false, false);

        let addr6 = build_address_params(&mut prng, 1u64,
                                         asset_id, false, false, false);

        let addr7 = build_address_params(&mut prng, 1u64,
                                         asset_id, false, false, false);

        let mut input = [addr1, addr2, addr3];
        let mut output = [addr4, addr5, addr6, addr7];
        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(true, tx.verify());

        //overflow transfer
        output[3].amount = 0xFFFFFFFFFF;

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(false, tx.verify());

        //exact transfer
        output[3].amount = 27;

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(true, tx.verify());

        //first different from rest
        input[0].asset_type = String::from("another asset");

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(false, tx.verify());

        //input does not match
        input[0].asset_type = String::from(asset_id);
        input[1].asset_type = String::from("another asset");


        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(false, tx.verify());

        //output does not match
        input[1].asset_type = String::from(asset_id);
        output[1].asset_type = String::from("another asset");


        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(false, tx.verify());
    }

    #[test]
    fn test_transaction_confidential_asset() {
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let addr1 = build_address_params(&mut prng, 10u64,
                                         asset_id, true,false, true);

        let addr2 = build_address_params(&mut prng, 10u64,
                                         asset_id, true,false, true);

        let addr3 = build_address_params(&mut prng, 10u64,
                                         asset_id, true,false, true);

        let addr4 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,false, true);

        let addr5 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,false, true);

        let addr6 = build_address_params(&mut prng, 1u64,
                                         asset_id, false, false, true);

        let addr7 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,false, true);


        let mut input = [addr1, addr2, addr3];
        let mut output = [addr4, addr5, addr6, addr7];
        println!("Building tx");
        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, true).unwrap();

        assert_eq!(true, tx.verify());

        input[1] = build_address_params(&mut prng, 10, "another asset", true, false, true);

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, true).unwrap();

        assert_eq!(false, tx.verify());


        //output does not match
        input[1] = build_address_params(&mut prng, 10, asset_id, true, false, true);
        output[2] = build_address_params(&mut prng, 1, "another asset", false, false, true);


        let tx = Tx::new(&mut prng, &input,
                         &output,
                         false, false).unwrap();

        assert_eq!(false, tx.verify());
    }

    #[test]
    fn test_confidential_amount() {
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let addr1 = build_address_params(&mut prng, 10u64,
                                         asset_id,true, true, false);

        let addr2 = build_address_params(&mut prng, 10u64,
                                         asset_id,true, true, false);

        let addr3 = build_address_params(&mut prng, 10u64,
                                         asset_id,true, true, false);

        let addr4 = build_address_params(&mut prng, 1u64,
                                         asset_id, false, true, false);

        let addr5 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,true, false);

        let addr6 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,true, false);

        let addr7 = build_address_params(&mut prng, 1u64,
                                         asset_id, false,true, false);


        let mut input = [addr1, addr2, addr3];
        let mut output = [addr4, addr5, addr6, addr7];

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         true, false).unwrap();

        assert_eq!(true, tx.verify());

        output[3] = build_address_params(&mut prng, 50, asset_id, false, true, false);

        let tx = Tx::new(&mut prng, &input,
                         &output,
                         true, false);

        assert_eq!(ZeiError::TxProofError, tx.err().unwrap());
    }
}
