//Hidden Accounts

use curve25519_dalek::scalar::Scalar;
use crate::core::keypair::Keypair;

//An Account is a triple:
// Counter, incremented after each transaction
// Balance, amount of coins in account, plaintext known to user
// Opening, the blinding factor that is used to send transaction 

pub type Balance = u32;

pub struct Account {
    //account tx count
    counter: u128,
    //Hidden
    balance: Balance,
    //opening from latest payment
    opening: Scalar,
    //account keys
    keys: Keypair
}

impl Account {

    pub fn new() -> Account {
        Account {
            counter: 0,
            balance: 0,
            opening: 0,
            keys: Keypair::new()
        }
    }

    pub fn send(&mut self, dest: PublicKey, amount: Balance){
        //sample some randomness for the new opening 
        //TODO: Handle Errors better
        let mut csprng: OsRng = OsRng::new().unwrap();
        let new_opening = Scalar::random(&mut csprng);

        //update account balance
        self.balance -= amount;



        //update our account opening
        self.opening = self.opening - new_opening;
        //increment counter
        self.counter += 1;
    }

    //once a transaction has been sent to us we need to apply it to our account
    pub fn recieve(&mut self, tx: Transaction) {

        //update balance


        //update our account opening
        self.opening = self.opening + tx.opening;
    }
}



