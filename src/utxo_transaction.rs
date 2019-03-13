use blake2::{Blake2b,Digest};
use bulletproofs::{PedersenGens, RangeProof};
use core::borrow::Borrow;
use crate::errors::Error as ZeiError;
use crate::encryption::ZeiCipher;
use crate::proofs::chaum_pedersen::{chaum_pedersen_prove_multiple_eq,
                                     chaum_pedersen_verify_multiple_eq,
                                    ChaumPedersenProofX};
use crate::serialization;
use crate::setup::{BULLET_PROOF_RANGE,PublicParams};
use crate::utils::{u64_to_bigendian_u8array, u8_bigendian_slice_to_u64};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand::CryptoRng;
use rand::Rng;
use std::collections::HashSet;
use crate::utils::compute_str_scalar_hash;
use crate::keys::XfrPublicKey;
use crate::keys::XfrSecretKey;
use crate::serialization::ZeiFromToBytes;
use crate::keys::XfrSignature;
use curve25519_dalek::edwards::EdwardsPoint;

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxAddressParams{
    /// Address parameters used as input and output to create transactiona
    pub(crate) amount: u64, // Input or output amount
    #[serde(with = "serialization::option_bytes")]
    pub(crate) amount_commitment: Option<CompressedRistretto>, // Input or output balance
    #[serde(with = "serialization::option_bytes")]
    pub(crate) amount_blinding: Option<Scalar>, // None for output
    pub(crate) asset_type: String,
    #[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_commitment: Option<CompressedRistretto>, // None if non confidential asset or
                                                        // account is new, or Utxo model
    #[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_blinding: Option<Scalar>, // None if non confidential asset or
                                         // account is new or Utxo model
    #[serde(with = "serialization::zei_obj_serde")]
    pub(crate) public_key: XfrPublicKey,
    #[serde(with = "serialization::option_bytes")]
    pub(crate) secret_key: Option<XfrSecretKey>, //None for output account
}

impl PartialEq for TxAddressParams{
    fn eq(&self, other: &TxAddressParams) -> bool {
        let b = self.amount == other.amount &&
            self.amount_commitment == other.amount_commitment &&
            self.amount_blinding == other.amount_blinding &&
            self.asset_type == other.asset_type &&
            self.asset_type_commitment == other.asset_type_commitment &&
            self.asset_type_blinding == other.asset_type_blinding &&
            self.public_key == other.public_key;
        let mut sk_eq = false;
        if self.secret_key.is_none() && other.secret_key.is_none(){
            sk_eq = true;
        }
        else if self.secret_key.is_some() && other.secret_key.is_some(){
            sk_eq = self.secret_key.as_ref().unwrap().zei_to_bytes() ==
                other.secret_key.as_ref().unwrap().zei_to_bytes()
        }

        b && sk_eq
    }
}

impl Eq for TxAddressParams {}

#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct TxPublicFields {
    /// Address information for input and output that is safe to add to transaction
    pub(crate) amount: Option<u64>, // None only if confidential
    #[serde(with = "serialization::option_bytes")]
    pub(crate) amount_commitment: Option<CompressedRistretto>, // None if not confidential balance
    pub(crate) asset_type: Option<String>, // None only if confidential asset
    #[serde(with = "serialization::option_bytes")]
    pub(crate) asset_type_commitment: Option<CompressedRistretto>, // None if not confidential asset
    #[serde(with = "serialization::zei_obj_serde")]
    pub(crate) public_key: XfrPublicKey, // source or destination
}

#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct TxOutput {
    /// Output structure for output
    pub(crate) public: TxPublicFields,
    //#[serde(with = "serialization::option_bytes")]
    pub(crate) lock_box: Option<ZeiCipher>,
}

impl TxOutput {
    pub fn get_pk(&self) -> XfrPublicKey {
        self.public.public_key
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct TxProofs{
    /// Proof to be included in transactions
    #[serde(with = "serialization::option_bytes")]
    pub(crate) range_proof: Option<RangeProof>,
    #[serde(with = "serialization::option_bytes")]
    pub(crate) asset_proof: Option<ChaumPedersenProofX>,
}

impl PartialEq for TxProofs {
    fn eq(&self, other: &TxProofs) -> bool {
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

impl Eq for TxProofs {}

#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct TxBody{
    /// Transaction body structure
    pub(crate) input: Vec<TxPublicFields>,
    pub(crate) output: Vec<TxOutput>,
    pub(crate) proofs: TxProofs,
    pub(crate) confidential_amount:bool,
    pub(crate) confidential_asset: bool,
}

#[derive(Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Tx{
    /// Transaction structure
    pub body: TxBody,
    pub signatures: Vec<XfrSignature>,
}

impl Tx{
    pub fn new<R: CryptoRng + Rng>(
        prng: &mut R,
        input: &[TxAddressParams],
        output: &[TxAddressParams],
        confidential_amount: bool,
        confidential_asset: bool,
    ) -> Result<(Tx, Option<Vec<Scalar>>), ZeiError> {
        let pc_gens = PedersenGens::default();
        //output values to be build
        let mut tx_range_proof = None;
        let mut tx_asset_proof = None;
        let mut tx_input = Vec::new();
        let mut tx_output= Vec::new();
        let mut tx_in_amount = vec![];
        let mut tx_out_amount = vec![];
        let mut tx_out_amount_com: Vec<Option<CompressedRistretto>>;
        let mut tx_out_asset_com: Vec<Option<CompressedRistretto>>;
        // to be encrypted to receiver
        let mut memo_out_amount_blind = vec![];
        let mut memo_out_asset_blind: Vec<Option<Scalar>>;

        // extract values from input struct
        let src_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            input.iter().map(|x| x.asset_type_commitment).collect();
        let src_pks: Vec<XfrPublicKey> =
            input.iter().map(|x| x.public_key).collect();

        // extract values from output struct
        let dst_asset_type_com_option: Vec<Option<CompressedRistretto>> =
            output.iter().map(|x| x.asset_type_commitment).collect();
        let dst_asset_type_blind_option: Vec<Option<Scalar>> =
            output.iter().map(|x| x.asset_type_blinding).collect();
        let destination_public_keys: Vec<XfrPublicKey> =
            output.iter().map(|x| x.public_key ).collect();

        // do amount handling
        if confidential_amount {
            let (range_proof, out_coms, out_blinds)
                = Tx::do_confidential_amount_range_proof(prng, input, output)?;

            tx_out_amount_com = out_coms.into_iter().map(|x| Some(x)).collect();
            tx_range_proof = Some(range_proof);
            memo_out_amount_blind = out_blinds;

            // in confidential amount transaction, amounts are hidden, use None value
            for _ in 0..input.len(){
               tx_in_amount.push(None);
            }
            for _ in 0..output.len(){
               tx_out_amount.push(None);
            }
        }
        else{
            // add plaintext amount to source and destination
            // out commitmements are None
            tx_in_amount = input.iter().map(|x| Some(x.amount)).collect();
            tx_out_amount = output.iter().map(|x| Some(x.amount)).collect();
            tx_out_amount_com = (0..output.len()).map(|_| None).collect();
        }

        if confidential_asset{
            let src_asset_com: Vec<CompressedRistretto> = src_asset_type_com_option.iter().map(|x| x.unwrap()).collect();
            let src_asset_blind: Vec<Scalar> =
                input.iter().map(|x| x.asset_type_blinding.unwrap()).collect();


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

            tx_asset_proof = Some(proof_asset);
            tx_out_asset_com = vec![];
            memo_out_asset_blind = vec![];
            for (x,y) in out_asset_com.iter().zip(out_asset_blind.iter()) {
                tx_out_asset_com.push(Some(*x));
                memo_out_asset_blind.push(Some(*y))
            }
        }
        else{
            // if non-confidential asset, then output asset_com is same as before (None)
            tx_out_asset_com = dst_asset_type_com_option;
            memo_out_asset_blind = dst_asset_type_blind_option;
        }

        //compute input struct
        for i in 0..input.len(){
            tx_input.push(
                TxPublicFields {
                    amount: tx_in_amount[i],
                    amount_commitment: input[i].amount_commitment,
                    asset_type: match confidential_asset{ true => None, false => Some(input[i].asset_type.clone())},
                    asset_type_commitment: src_asset_type_com_option[i],
                    public_key: src_pks[i],
                    }
            );
        }

        //compute output struct
        for i in 0..output.len(){
            let lbox: Option<ZeiCipher>;
            if confidential_amount || confidential_asset{
                let mut memo = vec![];
                if confidential_amount {
                    memo.extend_from_slice(&u64_to_bigendian_u8array(output[i].amount));
                    memo.extend_from_slice(memo_out_amount_blind[i].as_bytes());
                }
                if confidential_asset {
                    memo.extend_from_slice(memo_out_asset_blind[i].unwrap().as_bytes());
                }
                let ciphertext = ZeiCipher::encrypt(
                    prng,
                    &destination_public_keys[i],
                    memo.as_slice(),
                )?;
                lbox = Some(ciphertext);
            }
            else {
                lbox = None;
            }

            tx_output.push(
                TxOutput {
                    public: TxPublicFields {
                        amount: tx_out_amount[i],
                        amount_commitment: tx_out_amount_com[i],
                        asset_type: match confidential_asset {
                            true => None,
                            false => Some(output[i].asset_type.clone()),
                        },
                        asset_type_commitment: tx_out_asset_com[i],
                        public_key: destination_public_keys[i],
                    },
                    lock_box: lbox,
                }
            );
        }



        let body = Tx::build_body(
            tx_input, tx_output,
            tx_range_proof, tx_asset_proof);

        let signatures = Tx::compute_signatures(&body, input);

        let out_amount_blindings = match confidential_amount{
            true => Some(memo_out_amount_blind),
            false => None,
        };

        Ok( ( Tx{body, signatures }, out_amount_blindings))
    }

    fn do_confidential_amount_range_proof<R: CryptoRng + Rng>(prng: &mut R,
        input: &[TxAddressParams],
        output: &[TxAddressParams]
    ) -> Result<(RangeProof, Vec<CompressedRistretto>, Vec<Scalar>), ZeiError>
    {

        let in_amount_blinds: Vec<Scalar> =
            input.iter().map(|x| x.amount_blinding.unwrap()).collect();
        let in_amounts: Vec<u64> = input.iter().map(|x| x.amount ).collect();
        let out_amounts: Vec<u64> = output.iter().map(|x| x.amount ).collect();
        let destination_public_keys: Vec<XfrPublicKey> =
            output.iter().map(|x| x.public_key ).collect();

        let (proof, tx_coms, tx_blinds) =
            Tx::build_range_proof(
                prng,
                in_amount_blinds.as_slice(),
                in_amounts.as_slice(),
                out_amounts.as_slice(),
                destination_public_keys.as_slice()
            )?;
        Ok((proof, tx_coms, tx_blinds))
    }

    fn build_range_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        source_blindings: &[Scalar],
        source_amounts: &[u64],
        destination_amounts: &[u64],
        destination_public_keys: &[XfrPublicKey],
    ) -> Result<(RangeProof, Vec<CompressedRistretto>, Vec<Scalar>),ZeiError>
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

    fn build_asset_proof<R: CryptoRng + Rng>(
        prng: &mut R,
        pc_gens: &PedersenGens,
        asset_type: &str,
        source_asset_commitments: &[CompressedRistretto],
        source_asset_blindings: &[Scalar],
        destination_asset_commitments: Vec<Option<CompressedRistretto>>,
        destination_asset_blindings: Vec<Option<Scalar>>,
        destination_public_keys: &Vec<XfrPublicKey>,

    ) -> Result<(ChaumPedersenProofX,
                 Vec<CompressedRistretto>, Vec<Scalar>), ZeiError>
    {
        let num_output = destination_public_keys.len();
        let mut out_asset_com = vec![];
        let mut out_asset_blind = vec![];
        let asset =String::from(asset_type);

        let mut all_asset_com = Vec::new();
        all_asset_com.extend_from_slice(source_asset_commitments);

        let mut all_asset_blind = Vec::new();
        all_asset_blind.extend_from_slice(source_asset_blindings);

        //create commitments and blindings if they don't exits (UTXO or new type for account)
        for i in 0..num_output{
            if destination_asset_commitments[i].is_none() {
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

        let asset_as_scalar = compute_str_scalar_hash(&asset);

        let proof_asset = chaum_pedersen_prove_multiple_eq(
            prng,
            pc_gens,
            &asset_as_scalar,
            all_asset_com.as_slice(),
            all_asset_blind.as_slice())?;

        Ok((proof_asset, out_asset_com, out_asset_blind))
    }


    fn compute_signatures(
        body: &TxBody, input: &[TxAddressParams]) -> Vec<XfrSignature>
    {
        let msg = serde_json::to_vec(body).unwrap();
        let mut signatures = vec![];
        let mut pk_set = HashSet::new();
        for i in 0..input.len(){
            let pk = &input[i].public_key;
            if pk_set.contains(pk.as_bytes()) == false {
                pk_set.insert(pk.as_bytes());
                let sign = input[i].secret_key.as_ref().unwrap().sign(msg.as_slice(),
                                                                                            pk);
                signatures.push(sign);
            }
        }
        signatures
    }

    fn build_body(
        source_info: Vec<TxPublicFields>,
        destination_info: Vec<TxOutput>,
        range_proof: Option<RangeProof>,
        asset_proof: Option<ChaumPedersenProofX>,
        ) -> TxBody
    {
        let confidential_amount = range_proof.is_some();
        let confidential_asset = asset_proof.is_some();
        let proofs = TxProofs{
            range_proof,
            asset_proof,
        };
        TxBody{
            input: source_info,
            output: destination_info,
            proofs,
            confidential_amount,
            confidential_asset,
        }
    }

     pub fn get_outputs(&self) -> Vec<TxOutput> {
        self.body.output.clone()
     }

    pub fn verify(&self) -> bool{
        //1 signature
        if ! self.verify_signatures(){
            return false;
        }
        //2 amounts
        if self.body.confidential_amount {
            if !self.verify_confidential_amount(){
                return false;
            }
        }
        else {
            let in_amount: Vec<u64> = self.body.input.iter().map(|x| x.amount.unwrap()).collect();
            let in_amount_sum = in_amount.iter().sum::<u64>();
            let out_amount: Vec<u64> = self.body.output.iter().map(|x| x.public.amount.unwrap()).collect();
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
        let asset_id_option = self.body.input[0].asset_type.as_ref().unwrap();
        for x in self.body.input.iter(){
            let asset_id_option_i = x.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }

        for x in self.body.output.iter(){
            let asset_id_option_i = x.public.asset_type.as_ref().unwrap();
            if asset_id_option_i != asset_id_option {
                return false;
            }
        }
        true
    }

    fn verify_signatures(&self) -> bool{
        let msg = serde_json::to_vec(&self.body).unwrap();
        let input = &self.body.input;
        let signatures = &self.signatures;
        let mut pk_set = HashSet::new();
        for i in 0..input.len(){
            let pk = &input[i].public_key;
            if pk_set.contains(pk.as_bytes()) == false {
                pk_set.insert(pk.as_bytes());

                if pk.verify(msg.as_slice(),&signatures[i]).is_err(){
                    return false;
                }
            }
        }
        //number of different keys == number of signatures in tx
        if pk_set.iter().len() != signatures.len() {
            return false;
        }

        true
    }

    fn verify_confidential_amount(&self) -> bool {
        let num_output = self.body.output.len();
        let upper_power2 = smallest_greater_power_of_two((num_output + 1) as u32) as usize;

        let params = PublicParams::new(upper_power2);
        let mut transcript = Transcript::new(b"Zei Range Proof");

        let input_com: Vec<RistrettoPoint> = self.body.input.iter().
            map(|x| x.amount_commitment.unwrap().decompress().unwrap()).collect();

        let output_com: Vec<RistrettoPoint> = self.body.output.iter().
            map(|x| x.public.amount_commitment.
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
        let mut asset_commitments: Vec<CompressedRistretto> = self.body.input.iter().
            map(|x| x.asset_type_commitment.unwrap()).collect();

        let out_asset_commitments: Vec<CompressedRistretto> = self.body.output.iter().
            map(|x| x.public.asset_type_commitment.unwrap()).collect();

        asset_commitments.extend(out_asset_commitments.iter());

        let proof = self.body.proofs.asset_proof.borrow().as_ref().unwrap();
        let r = chaum_pedersen_verify_multiple_eq(
            &pc_gens,
            asset_commitments.as_slice(),
            proof,
        );

        r.unwrap()
    }

    pub fn receiver_unlock_memo(
        lbox: &ZeiCipher,
        sk: &XfrSecretKey,
        confidential_amount: bool,
        confidential_asset: bool,
    ) -> Result<(Option<u64>, Option<Scalar>, Option<Scalar>), ZeiError>
    {
        let mut amount = None;
        let mut amount_blind = None;
        let mut asset_blind = None;

        let mut bytes = [0u8;32];

        let message = lbox.decrypt(sk)?;
        if confidential_amount {
            let (value, scalars) = message.split_at(8);
            amount = Some(u8_bigendian_slice_to_u64(value));
            bytes.copy_from_slice(&scalars[0..32]);    
         //@Ben: We have changed the protocol. The blind is shared through a key exchange blind_share not here in lbox.
            amount_blind = Some(Scalar::from_bits(bytes));
          
            if confidential_asset {
            //@Ben: Do we not encrypt the asset type in lbox because it can be brute forced given the blind? 
                bytes.copy_from_slice(&scalars[32..64]);
                asset_blind = Some(Scalar::from_bits(bytes));
            }
        }
        else if confidential_asset {
            bytes.copy_from_slice(message.as_slice());
            asset_blind = Some(Scalar::from_bits(bytes));
        }

        Ok((amount, amount_blind, asset_blind))
    }

}


#[inline]
fn smallest_greater_power_of_two(n: u32) -> u32{
    2.0f64.powi((n as f64).log2().ceil() as i32) as u32
}

fn compute_asset_commitment<R>(
    csprng: &mut R,
    pc_gens: &PedersenGens,
    address: &XfrPublicKey,
    asset_type: &str) -> Result<(RistrettoPoint,Scalar), ZeiError>
    where R:CryptoRng + Rng,
{
    let blinding_factor = sample_blinding_factor(csprng, address)?;
    let asset_hash = compute_str_scalar_hash(asset_type);

    Ok((pc_gens.commit(asset_hash, blinding_factor), blinding_factor))
}

fn sample_blinding_factor<R>(csprng: &mut R, address: &XfrPublicKey) -> Result<Scalar, ZeiError>
    where R: CryptoRng + Rng,
{
    let blinding_key = Scalar::random(csprng);
    let pk_curve_point = address.get_curve_point()?;
    let aux: EdwardsPoint = blinding_key * pk_curve_point;
    let mut hasher = Blake2b::new();
    hasher.input(&aux.compress().to_bytes());
    Ok(Scalar::from_hash(hasher))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::utils::compute_str_commitment;
    use crate::keys::XfrKeyPair;

    fn build_address_params<R: CryptoRng + Rng>(prng: &mut R, amount: u64, asset: &str,
                                                input: bool, //input or output
                                                confidential_amount: bool,
                                                confidential_asset: bool) -> (TxAddressParams, XfrSecretKey) {
        let pc_gens = PedersenGens::default();


        let mut amount_commitment = None;
        let mut amount_blinding = None;
        let mut asset_type_commitment = None;
        let mut asset_type_blinding = None;
        let mut sk = None;

        if confidential_amount && input {
            let blind = Scalar::random(prng);
            let com = pc_gens.commit(Scalar::from(amount), blind);

            amount_commitment = Some(com.compress());
            amount_blinding = Some(blind);
        }
        if confidential_asset {
            let (com, blind) = compute_str_commitment(prng, asset);
            asset_type_commitment = Some(com.compress());
            asset_type_blinding = Some(blind);
        }
        let key = XfrKeyPair::generate(prng);

        if input {
            sk = Some(key.get_sk());
        }
        (TxAddressParams {
            amount,
            amount_commitment,
            amount_blinding,
            asset_type: String::from(asset),
            asset_type_commitment,
            asset_type_blinding,
            public_key: key.get_pk_ref().clone(),
            secret_key: sk,
        }, key.get_sk())
    }

    #[test]
    fn test_transaction_not_confidential() {
        /*! I test simple transaction from 3 input to 4 output that do not provide any
        confidentiality*/
        let asset_id = "default_currency";
        let mut prng: ChaChaRng;
        prng = ChaChaRng::from_seed([0u8; 32]);
        let num_inputs = 3;
        let num_outputs = 4;
        let input_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<XfrSecretKey> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, input_amount[i], asset_id,
                                     true,false, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false,false, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();

        assert_eq!(true, tx.verify(), "Not confidential simple transaction should verify ok");

        for i in 0..num_outputs {
            assert_eq!(None, tx.body.output[i].lock_box);
        }

        //overflow transfer
        out_addrs[3].amount = 0xFFFFFFFFFF;
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Output amounts are greater than input, should fail in verify");

        //exact transfer
        out_addrs[3].amount = 24;
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(true, tx.verify(),
                   "Not confidential tx with exact input and output should pass");

        //first different from rest
        in_addrs[0].asset_type = String::from("another asset");
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on first input should \
                   fail verification ok");

        //input does not match
        in_addrs[0].asset_type = String::from(asset_id);
        in_addrs[1].asset_type = String::from("another asset");
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on non first input \
                   should fail verification ok");

        //output does not match
        in_addrs[1].asset_type = String::from(asset_id);
        out_addrs[1].asset_type = String::from("another asset");
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(),
                   "Not confidential transaction with different asset type on output \
                   should fail verification ok");
    }

    #[test]
    fn test_transaction_confidential_asset() {
        /*! I test transaction from 3 input to 4 output that hide the asset type
        but not the amount*/
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        let num_inputs = 3;
        let num_outputs = 4;
        let input_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<XfrSecretKey> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, input_amount[i], asset_id,
                                     true,false, true);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false,false, true);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, true).unwrap();

        assert_eq!(true, tx.verify(), "Conf. asset tx: Transaction is valid");

        //check receivers memos decryption
        for i in 0..4 {
            let (amount, amount_blind, asset_blind) =
                Tx::receiver_unlock_memo(
                    tx.body.output[i].lock_box.as_ref().unwrap(),
                    &out_sks[i], false, true).unwrap();

            assert_eq!(None, amount, "Conf. asset tx: Decryption should not contain amount");
            assert_eq!(None, amount_blind, " Conf. asset tx: Decryption should not contain amount blinding");
            let blind_com = pc_gens.commit(
                compute_str_scalar_hash(asset_id), asset_blind.unwrap());
            assert_eq!(blind_com.compress(),
                       tx.body.output[i].public.asset_type_commitment.unwrap(),
                       "Conf. asset tx: Decryption should contain valit asset blinding");
            //TODO what if output blinding was provided (account based)
        }

        //one input does not match
        let (new_in1,_) =
            build_address_params(&mut prng, 10, "another asset",
                                 true, false, true);
        in_addrs[1] = new_in1;
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, true).unwrap();
        assert_eq!(false, tx.verify(), "Confidential asset tx, one input asset does not match");

        //one output does not match
        let (new_in1, _) =
            build_address_params(&mut prng, 10, asset_id,
                                 true, false, true);
        in_addrs[1] = new_in1;
        let (new_out2, _) =
            build_address_params(&mut prng, 1, "another asset",
                                 false, false, true);
        out_addrs[2] = new_out2;
        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();
        assert_eq!(false, tx.verify(), "Confidential asset tx, one output asset does not match");
    }

    #[test]
    fn test_confidential_amount() {
        /*! I test transactions from 3 input to 4 output that hide the amount
        but not the asset type*/

        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();
        let num_inputs = 3;
        let num_outputs = 4;
        let in_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks: Vec<XfrSecretKey> = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, in_amount[i], asset_id,
                                     true, true, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false, true, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         true, false).unwrap();
        assert_eq!(true, tx.verify(),
                   "Conf. amount tx: Transaction should be valid");

        //check receivers memos decryption
        for i in 0..num_outputs {
            let (amount, amount_blind, asset_blind) =
                Tx::receiver_unlock_memo(tx.body.output[i].lock_box.as_ref().unwrap(),
                                         &out_sks[i],
                                         true, false).unwrap();

            assert_eq!(None, asset_blind,
                       "Conf. amount tx: memo decryption should not contain asset blinding,\
                       since it is not a confidential asset tx");
            assert_eq!(out_amount[i], amount.unwrap(),
                       "Conf. amount tx: memo decryption should contain original tx amount");
            let amount_com = pc_gens.commit(Scalar::from(out_amount[i]),
                                            amount_blind.unwrap());
            assert_eq!(amount_com.compress(),
                       tx.body.output[i].public.amount_commitment.unwrap(),
                       "Conf. amount tx: memo decryption should contain valid amount blinding");
        }

        let (new_out3, _) =
            build_address_params(&mut prng, 50, asset_id,
                                 false, true, false);
        out_addrs[3] = new_out3;

        let tx = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         true, false);

        assert_eq!(ZeiError::TxProofError, tx.err().unwrap(),
                   "Conf. amount tx: tx should have not be able to produce range proof");
    }

    #[test]
    fn test_tx_serialization_plain(){
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let num_inputs = 3;
        let num_outputs = 4;
        let in_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, in_amount[i], asset_id,
                                     true, false, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false, false, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                         &out_addrs,
                         false, false).unwrap();

        let json = serde_json::to_string(&tx).unwrap();
        
        let dtx = serde_json::from_str::<Tx>(&json).unwrap();

        assert_eq!(tx, dtx);
    }

    #[test]
    fn test_tx_serialization_conf_amount(){
        let asset_id = "default_currency";
        let mut prng = ChaChaRng::from_seed([0u8; 32]);
        let num_inputs = 3;
        let num_outputs = 4;
        let in_amount = [10u64, 10u64, 10u64];
        let mut in_addrs = vec![];
        let mut out_addrs  = vec![];
        let out_amount = [1u64, 2u64, 3u64, 4u64];
        let mut out_sks = vec![];

        for i in 0..num_inputs{
            let (addr,_) =
                build_address_params(&mut prng, in_amount[i], asset_id,
                                     true, true, false);
            in_addrs.push(addr);
        }

        for i in 0..num_outputs{
            let (addr, sk) =
                build_address_params(&mut prng, out_amount[i], asset_id,
                                     false, true, false);
            out_addrs.push(addr);
            out_sks.push(sk);
        }

        let (tx,_) = Tx::new(&mut prng, &in_addrs,
                             &out_addrs,
                             true, false).unwrap();

        let json = serde_json::to_string(&tx.signatures).unwrap();
        let dsigs = serde_json::from_str::<Vec<XfrSignature>>(&json).unwrap();
        assert_eq!(tx.signatures, dsigs);

        let json = serde_json::to_string(&tx.body.proofs).unwrap();
        let dproofs = serde_json::from_str::<TxProofs>(&json).unwrap();
        assert_eq!(tx.body.proofs, dproofs);

        let json = serde_json::to_string(&tx.body.input).unwrap();
        let dinput = serde_json::from_str::<Vec<TxPublicFields>>(&json).unwrap();
        assert_eq!(tx.body.input, dinput);

        let json = serde_json::to_string(&tx.body.output).unwrap();
        let doutput = serde_json::from_str::<Vec<TxOutput>>(&json).unwrap();
        assert_eq!(tx.body.output, doutput);

        let json = serde_json::to_string(&tx).unwrap();
        let dtx = serde_json::from_str::<Tx>(&json).unwrap();

        assert_eq!(tx, dtx);
    }


}
