//Transctions in zei

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{ CompressedRistretto, RistrettoPoint };
use merlin::Transcript;
use curve25519_dalek::scalar::Scalar;
use rand::OsRng;
use crate::core::lockbox::{Lockbox, lock, unlock};
use crate::core::util::{ be_u8_from_u32, slice_to_fixed32 };
use crate::core::errors::Error;
use crate::core::elgamal::{SecretKey, PublicKey};


//A Confidential transaction
// range proof that balance - balance_inc is between (0, val_max)
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
        //this transaction range proof
        transaction_range_proof: bulletproofs::RangeProof,
        //transactions pedderson commitment
        transaction_commitment: CompressedRistretto,
        //senders updated balance range proof
        sender_updated_balance_range_proof: bulletproofs::RangeProof,
        //senders updated balance pedderson commitment
        sender_updated_balance_commitment: CompressedRistretto,
        //reciever updated commit
        receiver_new_commit: CompressedRistretto,
        //lock box
        lockbox: Lockbox
}


pub fn new_transaction(dest_pk: &PublicKey, transfer_amount: u32, account_balance: u32, account_blind: Scalar, receiver_commit: RistrettoPoint) -> Transaction {
        //Common Reference String
        let mut transcript = Transcript::new(b"Zei Range Proof");
        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();
        //32bit range for now & one prover
        let bp_gens = BulletproofGens::new(32, 1);

        //1. Sample Fresh blinding factor [blind], its a scalar
        let mut csprng: OsRng = OsRng::new().unwrap();
        let blinding_t = Scalar::random(&mut csprng);

        //2. Create Commitment ->  g^amount * h^[blind] == CommT
        //let commit_t = pc_gens.commit(Scalar::from(transfer_amount), blinding_t);

        //3. Create rangeproof for amount & use [blind] as randomness == RP_T
        let (range_proof_t, commit_t)  = RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                transfer_amount as u64,
                &blinding_t,
                32,
        ).expect("HANDLE ERRORS BETTER");

        //4. create Commitment ->  g^(Balance - amount) * h^(Opening - blind) == CommS
        let sender_updated_balance = account_balance - transfer_amount;
        //updated account blind
        let sender_updated_acount_blind = account_blind - blinding_t;

        //5. Create rangeproof for (Balance - transfer_amount) & use Opening - blind as randomness == RP_S
        let (range_proof_s, commit_s) = RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                sender_updated_balance as u64,
                &sender_updated_acount_blind,
                32,
        ).expect("HANDLE ERRORS BETTER");

        //6. Multiply Commitment ->  oldCommR * CommT == CommR
        let new_commit_reciever = receiver_commit + commit_t.decompress().unwrap();

        //7. Encrypt to receiver pubkey both the transfer_amount transferred and the blinding factor [blind] 
        let mut to_encrypt = Vec::new();
        //first add transfer_amount which is fixed 4 bytes in big endian
        to_encrypt.extend_from_slice(&be_u8_from_u32(transfer_amount));
        //next add the blind
        to_encrypt.extend_from_slice(&blinding_t.to_bytes());
        //lock em up
        let lbox = lock(dest_pk, &to_encrypt);

        return Transaction {
                transaction_range_proof: range_proof_t,
                transaction_commitment: commit_t,
                sender_updated_balance_range_proof: range_proof_s,
                sender_updated_balance_commitment: commit_s,
                receiver_new_commit: new_commit_reciever.compress(),
                lockbox: lbox
        };
}




//verify transaction under sk
pub fn verify_transaction(tx: &Transaction) -> Result<bool , Error> {
        //Common Reference String
        let mut transcript = Transcript::new(b"Zei Range Proof");
        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();
        //32bit range for now & one prover
        let bp_gens = BulletproofGens::new(32, 1);
       
        //This should take C_t as input
        //veriy the transactions proofs
        let veriy_t = RangeProof::verify_single(
                &tx.transaction_range_proof,
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &tx.transaction_commitment,
                32
        );
        //This should take  C_A'=C_A-C_T as input
        //verify the sender proofs
        let veriy_s = RangeProof::verify_single(
                &tx.sender_updated_balance_range_proof,
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &tx.sender_updated_balance_commitment,
                32
        );


        return Ok(true);
}

//Validate the sender proofs and commitment
// pub fn verify_sender_tx(tx: &Transaction) ->  Result<bool , Error> {

// }

//helper function to recover the sent amount and blind factor
pub fn recover_plaintext(sk: &SecretKey, lbox: &Lockbox) -> (u32, Scalar) {
        //unlock encrypted box
        let unlocked = unlock(sk, lbox);
        //extract balance value & blind value
        let (raw_amount, raw_blind) = unlocked.split_at(5);

        //convert to u32
        let p_amount = u32::from(raw_amount[0]) << 24 |
        u32::from(raw_amount[1]) << 16 |
        u32::from(raw_amount[2]) << 8 |
        u32::from(raw_amount[3]);

        //recover blind from bytes to scalar
        let recovered_blind_scalar = Scalar::from_bits(slice_to_fixed32(raw_blind));

        return (p_amount, recovered_blind_scalar);
}


//veriy commitments 
fn reciever_verify(tx_amount: u32, tx_blind: Scalar, new_commit: RistrettoPoint, recv_old_commit: RistrettoPoint) -> bool {
        //def pederson from lib with Common Reference String
        let pc_gens = PedersenGens::default();

        let compute_new_commit = pc_gens.commit(Scalar::from(tx_amount), tx_blind);

        let updated_commitmen = compute_new_commit + recv_old_commit;

        if new_commit == updated_commitmen { 
                return true; 
        } else {
                return false;
        }
}


#[cfg(test)]
mod test {
        //use crate::core::elgamal::{SecretKey, PublicKey};

        // #[test]
        // fn test_new_transaction() {
        //         //def pederson from lib with Common Reference String
        //         let pc_gens = PedersenGens::default();

        //         let mut csprng: OsRng = OsRng::new().unwrap();

        //         //Account A
        //         //generate sk
        //         let acc_a_sk = SecretKey::new(&mut csprng).unwrap();
        //         //generate our pk
        //         let acc_a_pk = PublicKey::from_secret(sk);

        //         //Account B
        //         //generate sk
        //         let acc_b_sk = SecretKey::new(&mut csprng).unwrap();
        //         //generate our pk
        //         let acc_b_pk = PublicKey::from_secret(sk);

        //         //the initial commitment is to zero
        //         let acc_a_comm_inital = pc_gens.commit(Scalar::from(0), Scalar::from(0));
        //         let acc_b_comm_inital = pc_gens.commit(Scalar::from(0), Scalar::from(0));

        //         //create a dummy tx
        //         let tx = new_transaction(acc_b_pk, 100u32, 0u32, acc_a_comm_inital, acc_b_comm_inital);

        //         //verify reciver commitment
        //         assert_eq!(reciever_verify(p_amount, recovered_blind_scalar, tx.receiver_new_commit, acc_b_comm_inital), true);


        // }
}