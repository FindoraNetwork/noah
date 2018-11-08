![alt text](https://github.com/eianio/zei/raw/master/zei_logo.png)

**Confidential Payments for Accounts**

Zei is a library to help manage an account system that blindes transaction amounts.
It Implements Confidential Transactions that was first proposed by [Greg Maxwell](https://people.xiph.org/~greg/confidential_values.txt). It however utilizes [Bulletproofs by Benedikt et al.](https://eprint.iacr.org/2017/1066.pdf) for shorter Rangeproofs. Furthermore, Elgamal Publickey encryption over the [Ristretto Group](https://ristretto.group) is utilized to reveal plaintext amounts & blinding factors to the reciever.
This implementation uses Pedersen Commitments and is open to account poisoning. 


## NodeJS API

### Create a transaction

The account api has an send() function that consumes a JSON structure that needs to be constructed
with data from the stellar network.

Stellar accounts have there own signature keypairs that are used to send transactions on the network.
These accounts also have arbitary KEY-VALUE pairs that may be set.
We will set the hidden account publickey as the KEY & set the latest balance commitment as a VALUE.
After each hidden transaction the commitments must be updated to reflect the new state.

#### How to create a new Hidden Account with Zei

```javascript
//Accounts are stored by the owner as a json string. 
//This string contains sensitive information so must be handled with care.
var account = create_account();
```

#### How to Send a Confidential Transaction

```javascript
//This is a JSON string
var new_tx = {
    receiver: "", //public key for destination secret account
    receiver_commit: "", //the latest commitment associated with that public key
    transfer_amount: "", //the senders desired amount
}
```

