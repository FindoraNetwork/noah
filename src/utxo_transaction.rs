use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use crate::asset::Asset;
use rand::CryptoRng;
use rand::Rng;
use crate::setup::PublicParams;
use bulletproofs::{PedersenGens, RangeProof};
use blake2::{Blake2b,Digest};
use schnorr::PublicKey;
use crate::errors::Error as ZeiError;
use crate::proofs::chaum_perdersen::{chaum_pedersen_prove_multiple_eq, ChaumPedersenCommitmentEqProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use crate::setup::BULLET_PROOF_RANGE;
use crate::proofs::chaum_perdersen::chaum_pedersen_verify_multiple_eq;


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

    #[test]
    fn test_utxo_m2n(){
        let asset_id = "default_currency";
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let asset = Asset{id: String::from(asset_id)};
        let asset_scalar = asset.compute_scalar_hash();


        let balance_addr1 = 1000u64;
        let blind_addr1 = Scalar::random(&mut csprng);
        let addr1_balance_com = pc_gens.commit(
            Scalar::from(balance_addr1), blind_addr1);
        let addr1_asset_blind = Scalar::random(&mut csprng);
        let addr1_asset_com  = pc_gens.commit(asset_scalar, addr1_asset_blind);

        let balance_addr2 = 2000u64;
        let blind_addr2 = Scalar::random(&mut csprng);
        let addr2_balance_com = pc_gens.commit(
            Scalar::from(balance_addr2), blind_addr2);
        let addr2_asset_blind = Scalar::random(&mut csprng);
        let addr2_asset_com  = pc_gens.commit(asset_scalar, addr2_asset_blind);

        let balance_addr3:u64 = 3000u64;
        let blind_addr3 = Scalar::random(&mut csprng);
        let addr3_balance_com = pc_gens.commit(
            Scalar::from(balance_addr3), blind_addr3);
        let addr3_asset_blind = Scalar::random(&mut csprng);
        let addr3_asset_com  = pc_gens.commit(asset_scalar, addr3_asset_blind);

        //let keys1 = Keypair::generate(&mut csprng);
        //let keys2 = Keypair::generate(&mut csprng);
        //let keys3 = Keypair::generate(&mut csprng);
        let keys4 = Keypair::generate(&mut csprng);
        let keys5 = Keypair::generate(&mut csprng);
        let keys6 = Keypair::generate(&mut csprng);
        let keys7 = Keypair::generate(&mut csprng);

        //let in_address = [keys1.public, keys2.public, keys3.public];
        let input_balance = [balance_addr1, balance_addr2, balance_addr3];
        let input_balance_commitment = [
            addr1_balance_com.compress(),
            addr2_balance_com.compress(),
            addr3_balance_com.compress()];
        let input_balance_blinding = [blind_addr1, blind_addr2, blind_addr3];
        let input_asset_commitment = [
            addr1_asset_com.compress(),
            addr2_asset_com.compress(),
            addr3_asset_com.compress()];
        let input_asset_blinding = [addr1_asset_blind, addr2_asset_blind, addr3_asset_blind];

        let output_address = [keys4.public, keys5.public, keys6.public, keys7.public];
        let output_amount = [1u64, 1u64, 1u64, 1u64];
            //balance_addr1 + balance_addr2 + balance_addr3 - 3];

        let tx = UtxoTx::create(
            &mut csprng,
            &input_balance,
            &input_balance_commitment,
            &input_balance_blinding,
            &input_asset_commitment,
            &input_asset_blinding,
            &asset,
            &output_address,
            &output_amount,
        ).unwrap();

        let verify = tx.verify();

        assert_eq!(true, verify.unwrap());
    }
}