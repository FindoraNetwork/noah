use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use crate::asset::Asset;
use rand::CryptoRng;
use rand::Rng;
use crate::setup::PublicParams;
use bulletproofs::RangeProof;
use bulletproofs::PedersenGens;
use blake2::{Blake2b,Digest};
use schnorr::PublicKey;
use crate::errors::Error as ZeiError;


pub fn create_n_m_utxo_transaction<R>(
    csprng: &mut R,
    input_balance: &[u32],
    input_balance_commitment: &[RistrettoPoint],
    input_balance_blinding: &[Scalar],
    input_asset_commitment: &[RistrettoPoint],
    input_asset_blinding: &[Scalar],
    asset_type: Asset,
    output_address: &[PublicKey],
    output_amount: &[u32]) -> Result<(), ZeiError>
    where R: CryptoRng + Rng,
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
    let num_inputs: usize = input_asset_commitment.len();
    let num_output: usize = output_address.len();
    let mut params = PublicParams::new();

    //range proofs and output commitments
    //commitements and blindings
    let mut blindings = Vec::new(); //for all outputs and sum(inputs) - sum(outputs)
    for i in 0..num_output {
        let blind = sample_blinding_factor(csprng, &output_address[i])?;
        blindings.push(blind);
    }
    let blind_diff =
        input_balance_blinding.iter().sum::<Scalar>() - blindings.iter().sum::<Scalar>();
    blindings.push(blind_diff);

    //create values vector (all outputs and sum(input) - sum(output)
    let tx_diff = (input_balance.into_iter().sum::<u32>() - output_amount.into_iter().sum::<u32>()) as u64;
    let mut values = Vec::new();
    for i in output_amount.iter(){
        values.push(*i as u64);
    }
    values.push(tx_diff);

    let range_proof_result = RangeProof::prove_multiple(
        &params.bp_gens,
        &params.pc_gens,
        &mut params.transcript,
        values.as_slice(),
        blindings.as_slice(),
        32);

    //asset commitment
    let mut asset_commitments = Vec::new();
    let mut asset_blindings = Vec::new();
    for i in 0..num_output {
        let (asset_comm, asset_blind) =
            compute_asset_commitment(
                csprng,&params.pc_gens,&output_address[i], &asset_type)?;
        asset_commitments.push(asset_comm);
        asset_blindings.push(asset_blind);
    }
    let mut asset_eq_proofs = Vec::new();
    for i in 1..num_inputs {
        let proof =
            Asset::prove_eq(
                &asset_blindings[0], &input_asset_blinding[i]);
        asset_eq_proofs.push(proof);
    }
    for i in 0..num_output {
        let proof = Asset::prove_eq(&asset_blindings[0], &asset_blindings[i]);
        asset_eq_proofs.push(proof);
    }
    Ok(())
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