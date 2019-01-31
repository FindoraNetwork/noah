use bulletproofs::{BulletproofGens, RangeProof, PedersenGens};
use crate::asset::Asset;
use crate::errors::Error as ZeiError;
use crate::serialization::{RangeProofString, CompressedRistrettoString, LockboxString,
                           ScalarString, PublicKeyString};
use crate::setup::PublicParams;
use curve25519_dalek::ristretto::{ CompressedRistretto, RistrettoPoint };
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use organism_utils::crypto::lockbox::Lockbox;
use organism_utils::helpers::{ be_u8_from_u32, slice_to_fixed32 };
use rand::CryptoRng;
use rand::Rng;
use schnorr::PublicKey;
use schnorr::SecretKey;
use std::convert::TryFrom;



#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    /*
     * I represent a transaction. I contain
     * - a range proof (0, val_max) for the senders updated balance and transaction amount,
     * - a Pedersen commitment for the transfer,
     * - a Pedersen commitment of the senders new balance,
     * - and a encrypted box for the receiver that includes the transfered amount and the blinding
     * factor of the transaction commitment.
     * - boolean indicating whether transaction is confidential for asset type or not
     * - A proof of equality of asset type
     */
    pub transaction_range_proof: bulletproofs::RangeProof,
    pub transaction_commitment: CompressedRistretto,
    pub sender_updated_balance_commitment: CompressedRistretto,
    pub lockbox: Lockbox,
    pub do_confidential_asset: bool,
    pub asset_eq_proof: Scalar,
    pub sender_asset_commitment: CompressedRistretto,
    pub receiver_asset_commitment: CompressedRistretto,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxParams{
    /*
     * I am helper structure to send/receive the data for a transaction
     *
     */
    pub receiver_pk: PublicKey,
    pub receiver_asset_commitment: CompressedRistretto,
    pub receiver_asset_opening: Scalar,
    pub transfer_amount: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxParamsString{
    receiver_pk: PublicKeyString,
    receiver_asset_commitment: CompressedRistrettoString,
    receiver_asset_opening: ScalarString,
    transfer_amount: u32,
}

impl TryFrom<TxParamsString> for TxParams{
    type Error = ZeiError;
    fn try_from(tx: TxParamsString) -> Result<TxParams, ZeiError> {
        Ok(
            TxParams{
                receiver_pk: PublicKey::try_from(tx.receiver_pk)?,
                receiver_asset_commitment: CompressedRistretto::try_from(tx.receiver_asset_commitment)?,
                receiver_asset_opening: Scalar::try_from(tx.receiver_asset_opening)?,
                transfer_amount: tx.transfer_amount,
            }
        )
    }
}

impl From<TxParams> for TxParamsString{
    fn from(tx: TxParams) -> TxParamsString {
        TxParamsString{
            receiver_pk: PublicKeyString::from(tx.receiver_pk),
            receiver_asset_commitment: CompressedRistrettoString::from(tx.receiver_asset_commitment),
            receiver_asset_opening: ScalarString::from(tx.receiver_asset_opening),
            transfer_amount: tx.transfer_amount,
        }
    }
}


impl Transaction {
    pub fn new<R>(csprng: &mut R,
                  tx_params: &TxParams,
                  account_balance: u32,
                  account_blind: &Scalar,
                  sender_asset_opening: &Scalar,
                  sender_asset_commitment: &CompressedRistretto,
                  do_confidential_asset: bool) -> Result<(Transaction, Scalar), ZeiError>
    where R: CryptoRng + Rng,
    {
        /*
         * I create a new transaction. 
         * - Create new public parameters
         * - Sample Fresh blinding factor [blind], its a scalar.
         * - Create Commitment ->  g^amount * h^[blind] == CommT
         * - Create rangeproof for amount & use [blind] as randomness == RP_T
         * - Create Commitment ->  g^(Balance - amount) * h^(Opening - blind) == CommS
         * - Create rangeproof for (Balance - transfer_amount) & use Opening - blind as randomness == RP_S
         * - Encrypt transfered amount and blinding factor to receiver
         * - Create and return the transaction
         */

        let mut params = PublicParams::new();
        let blinding_t = Scalar::random(csprng);
        let tx_amount = tx_params.transfer_amount;
        let sender_updated_balance = account_balance - tx_amount;
        let sender_updated_account_blind = account_blind - blinding_t;

        let range_proof_result = RangeProof::prove_multiple(
            &params.bp_gens,
            &params.pc_gens,
            &mut params.transcript,
            &[u64::from(tx_amount), u64::from(sender_updated_balance)],
            &[blinding_t, sender_updated_account_blind],
            32);

        let (proof_agg, commitments_agg) = match range_proof_result {
            Ok((pf_agg, comm_agg)) => (pf_agg, comm_agg),
            Err(_) => {return Err(ZeiError::TxProofError);},
        };

        let mut asset_eq_proof: Scalar;

        asset_eq_proof = Scalar::from(0u8);
        if do_confidential_asset {
            asset_eq_proof = Asset::prove_eq(&tx_params.receiver_asset_opening,
                                    &sender_asset_opening);
        }

        let mut to_encrypt = Vec::new();
        to_encrypt.extend_from_slice(&be_u8_from_u32(tx_amount));
        to_encrypt.extend_from_slice(&blinding_t.to_bytes());
        let lbox = Lockbox::lock(csprng, &tx_params.receiver_pk, &to_encrypt);

        let tx = Transaction {
            transaction_range_proof: proof_agg,
            transaction_commitment: commitments_agg[0],
            sender_updated_balance_commitment: commitments_agg[1],
            lockbox: lbox,
            do_confidential_asset,
            asset_eq_proof,
            sender_asset_commitment: sender_asset_commitment.clone(),
            receiver_asset_commitment: tx_params.receiver_asset_commitment,
        };

       Ok((tx, blinding_t))
    }

    pub fn recover_plaintext(&self, sk: &SecretKey) -> (u32, Scalar) {
        /*
         * I recover the sent amount and blind factor from the encryted box in a transaction
         *
         */

        let unlocked = self.lockbox.unlock(sk);
        let (raw_amount, raw_blind) = unlocked.split_at(4);

        //convert to u32
        let p_amount = u32::from(raw_amount[0]) << 24 |
            u32::from(raw_amount[1]) << 16 |
            u32::from(raw_amount[2]) << 8 |
            u32::from(raw_amount[3]);

        let blind_scalar = Scalar::from_bits(slice_to_fixed32(raw_blind));

        (p_amount, blind_scalar)
    }

}


pub fn validator_verify(tx: &Transaction,
                        sender_prev_com: RistrettoPoint,
                        sender_asset: RistrettoPoint,
                        receiver_asset: RistrettoPoint) -> bool {
    /*
     * Run by validator. I verify the transaction:
     * a) sender new balance commitment must match commitmment in transaction
     * b) Verify range proofs
     * c) Verify same asset type
     * If tx.do_confidential_asset, then sender_asset and receiver_asset are commitments, otherwise
     * they are simple digests of the the asset structure
     */

    let mut transcript = Transcript::new(b"Zei Range Proof");
    let pc_gens = PedersenGens::default();
    //TODO:This probably shouldn't be regenerated every time
    let bp_gens = BulletproofGens::new(32, 2);

    let tx_comm = tx.transaction_commitment.decompress().unwrap();
    let derived_sender_comm = sender_prev_com - tx_comm;
    let tx_sender_updated_balance_comm = tx.sender_updated_balance_commitment.decompress().unwrap();
    let mut vrfy_ok = derived_sender_comm == tx_sender_updated_balance_comm;
    if vrfy_ok {
        let verify_t = RangeProof::verify_multiple(
            &tx.transaction_range_proof,
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &[tx.transaction_commitment, tx.sender_updated_balance_commitment],
            32
        );

        vrfy_ok = verify_t.is_ok();
    }
    if vrfy_ok {
        if tx.do_confidential_asset {
            let h = PedersenGens::default().B_blinding;
            vrfy_ok = Asset::verify_eq(&receiver_asset,
                                       &sender_asset,
                                       tx.asset_eq_proof,
                                       &h);
        }
        else{
            vrfy_ok = sender_asset == receiver_asset;
        }
    }
    vrfy_ok
}


pub fn receiver_verify(tx_amount: u32, tx_blind: Scalar, new_commit: RistrettoPoint, recv_old_commit: RistrettoPoint) -> bool {
    /*
     * Run by receiver: I verify the new commitment to my balance using the new blinding factor
     * and old balance commitment.
     *
     */
    let pc_gens = PedersenGens::default();
    let compute_new_commit = pc_gens.commit(Scalar::from(tx_amount), tx_blind);
    let updated_commitment = compute_new_commit + recv_old_commit;
    new_commit == updated_commitment
}


//serialization of transaction strucures
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionString{
    transaction_range_proof: RangeProofString,
    transaction_commitment: CompressedRistrettoString,
    sender_updated_balance_commitment: CompressedRistrettoString,
    lockbox: LockboxString,
    do_confidential_asset: bool,
    asset_eq_proof: ScalarString,
    sender_asset_commitment: CompressedRistrettoString,
    receiver_asset_commitment: CompressedRistrettoString,
}

impl From<&Transaction> for TransactionString {
    fn from(a: &Transaction) -> TransactionString{
        TransactionString{
            transaction_range_proof: RangeProofString::from(&a.transaction_range_proof),
            transaction_commitment: CompressedRistrettoString::from(a.transaction_commitment),
            sender_updated_balance_commitment: CompressedRistrettoString::from(a.sender_updated_balance_commitment),
            lockbox: LockboxString::from(&a.lockbox),
            do_confidential_asset: a.do_confidential_asset,
            asset_eq_proof: ScalarString::from(a.asset_eq_proof),
            sender_asset_commitment: CompressedRistrettoString::from(a.sender_asset_commitment),
            receiver_asset_commitment: CompressedRistrettoString::from(a.receiver_asset_commitment),
        }
    }
}

impl TryFrom<TransactionString> for Transaction{
    type Error = ZeiError;
    fn try_from(a: TransactionString) -> Result<Transaction, ZeiError> {
        Ok(Transaction{
            transaction_range_proof: RangeProof::try_from(a.transaction_range_proof)?,
            transaction_commitment: CompressedRistretto::try_from(a.transaction_commitment)?,
            sender_updated_balance_commitment: CompressedRistretto::try_from(a.sender_updated_balance_commitment)?,
            lockbox: Lockbox::try_from(a.lockbox)?,
            do_confidential_asset: a.do_confidential_asset,
            asset_eq_proof: Scalar::try_from(a.asset_eq_proof)?,
            sender_asset_commitment: CompressedRistretto::try_from(a.sender_asset_commitment)?,
            receiver_asset_commitment: CompressedRistretto::try_from(a.receiver_asset_commitment)?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::account::Account;
    use curve25519_dalek::scalar::Scalar;
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use merlin::Transcript;
    use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use crate::account::AssetBalance;

    #[test]
    fn test_new_transaction() {
        let asset_id = "default currency";
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);

        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();

        //Account A
        let mut acc_a = Account::new(&mut csprng);
        acc_a.add_asset(&mut csprng, asset_id, false, 50);
        //Account B
        let mut acc_b = Account::new(&mut csprng);
        acc_b.add_asset(&mut csprng, asset_id, false, 50);

        let new_tx = TxParams {
            receiver_pk: acc_b.keys.public,
            transfer_amount: 100u32,
            receiver_asset_opening: Scalar::from(0u8),
            // sender_asset_opening: Scalar::from(0u8),
            // sender_asset_commitment:acc_a.get_asset_balance(asset_id).asset_commitment,
            receiver_asset_commitment:acc_b.get_asset_balance(asset_id).asset_commitment,
        };

        //
        //Create Proofs
        //

        let mut transcript = Transcript::new(b"Zei Range Proof");
        let bp_gens = BulletproofGens::new(32, 2);

        let blinding_t = Scalar::random(&mut csprng);

        let values = &[new_tx.transfer_amount as u64, acc_a.get_balance(asset_id) as u64];
        let blindings = &[blinding_t, acc_a.get_asset_balance(asset_id).balance_blinding];

        let (_, commitments_agg) = RangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            values,
            blindings,
            32,
            ).expect("A real program could handle errors");

        let tx_derived_commit = pc_gens.commit(Scalar::from(new_tx.transfer_amount), blinding_t);

        assert_eq!(tx_derived_commit, commitments_agg[0].decompress().unwrap());
    }

    #[test]
    fn test_confidential_asset_transaction(){
        let asset_id = "default_currency";
        let transfer_amount = 100u32;
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);
        let pc_gens = PedersenGens::default();

        // source account setup
        let mut acc_src = Account::new(&mut csprng);
        acc_src.add_asset(&mut csprng, asset_id, true, 50);
        let mut src_asset_balance = acc_src.get_asset_balance(asset_id);
        src_asset_balance.balance = 10000;
        src_asset_balance.balance_commitment =
            pc_gens.commit(Scalar::from(src_asset_balance.balance), src_asset_balance.balance_blinding).compress();


        // destination account setup
        let mut acc_dst = Account::new(&mut csprng);
        acc_dst.add_asset(&mut csprng, asset_id, true, 50);
        let dst_pk = acc_dst.get_public_key();
        let dst_asset_balance = acc_dst.get_asset_balance(asset_id);

        do_transaction_validation(src_asset_balance, dst_asset_balance,dst_pk, transfer_amount, true);

        // accounts asset do not match
        acc_dst.add_asset(&mut csprng, "other asset", true, 50);

        let dst_asset_balance = acc_dst.get_asset_balance("other asset");
        do_transaction_validation(src_asset_balance, dst_asset_balance,dst_pk, transfer_amount, false);

    }

    #[test]
    fn test_non_confidential_asset_transaction(){
        let asset_id = "default_currency";
        let transfer_amount = 100u32;
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);

        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();

        let mut acc_src = Account::new(&mut csprng);
        acc_src.add_asset(&mut csprng, asset_id, false, 50);
        let mut src_asset_balance = acc_src.get_asset_balance(asset_id);
        src_asset_balance.balance = 10000;
        src_asset_balance.balance_commitment =
            pc_gens.commit(Scalar::from(src_asset_balance.balance),
                           src_asset_balance.balance_blinding).compress();


        // destination account setup
        let mut acc_dst = Account::new(&mut csprng);
        acc_dst.add_asset(&mut csprng, asset_id, false, 50);
        let dst_pk = acc_dst.get_public_key();
        let dst_asset_balance = acc_dst.get_asset_balance(asset_id);

        do_transaction_validation(src_asset_balance, dst_asset_balance, dst_pk,transfer_amount, true);
    }

    fn do_transaction_validation(src_asset_balance: &AssetBalance,
                                 dst_asset_balance: &AssetBalance,
                                 dst_pk: PublicKey,
                                 transfer_amount: u32, expected: bool){

        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);

        let new_tx = TxParams {
            receiver_pk: dst_pk,
            transfer_amount: transfer_amount,
            receiver_asset_opening: dst_asset_balance.asset_blinding,
            receiver_asset_commitment: src_asset_balance.asset_commitment,
        };

        let (tx,_)  = Transaction::new(&mut csprng,
                                       &new_tx,
                                       src_asset_balance.balance,
                                       &src_asset_balance.balance_blinding,
                                       &src_asset_balance.asset_blinding,
                                       &src_asset_balance.asset_commitment,
                                       true).unwrap();

        let vrfy_ok = validator_verify(&tx,
                                       src_asset_balance.balance_commitment.decompress().unwrap(),
                                       src_asset_balance.asset_commitment.decompress().unwrap(),
                                       dst_asset_balance.asset_commitment.decompress().unwrap());
        assert_eq!(expected, vrfy_ok);

    }

    #[test]
    fn test_transaction_serialization(){
        let asset_id = "default_currency";
        let transfer_amount = 100u32;
        let mut csprng: ChaChaRng;
        csprng  = ChaChaRng::from_seed([0u8; 32]);

        // source account setup
        let mut acc_src = Account::new(&mut csprng);
        acc_src.add_asset(&mut csprng, asset_id, true, 100);

        // destination account stup
        let mut acc_dst = Account::new(&mut csprng);
        acc_dst.add_asset(&mut csprng, asset_id, true, 0);

        let new_tx = TxParams {
            receiver_pk: acc_dst.keys.public,
            transfer_amount: transfer_amount,
            receiver_asset_opening: acc_dst.balances[asset_id].asset_blinding,
            receiver_asset_commitment: acc_dst.balances[asset_id].asset_commitment,
        };

        let (tx,_)  = Transaction::new(&mut csprng,
                                       &new_tx,
                                       acc_src.balances[asset_id].balance,
                                       &acc_src.balances[asset_id].balance_blinding,
                                       &acc_src.balances[asset_id].asset_blinding,
                                       &acc_src.balances[asset_id].asset_commitment,
                                       true).unwrap();

        let tx_json = serde_json::to_string(&TransactionString::from(&tx)).unwrap();
        let desarialized_tx = Transaction::try_from(
            serde_json::from_str::<TransactionString>(&tx_json).unwrap()).unwrap();

        assert_eq!(tx.transaction_commitment, desarialized_tx.transaction_commitment);
        assert_eq!(tx.receiver_asset_commitment, desarialized_tx.receiver_asset_commitment);
        assert_eq!(tx.sender_asset_commitment, desarialized_tx.sender_asset_commitment);
        assert_eq!(tx.do_confidential_asset, desarialized_tx.do_confidential_asset);
        assert_eq!(tx.asset_eq_proof, desarialized_tx.asset_eq_proof);
        assert_eq!(tx.sender_updated_balance_commitment, desarialized_tx.sender_updated_balance_commitment);
        assert_eq!(tx.lockbox.rand, desarialized_tx.lockbox.rand);
        assert_eq!(tx.lockbox.data.cipher, desarialized_tx.lockbox.data.cipher);
        assert_eq!(tx.lockbox.data.nonce, desarialized_tx.lockbox.data.nonce);
        assert_eq!(tx.lockbox.data.tag, desarialized_tx.lockbox.data.tag);
    }
}
