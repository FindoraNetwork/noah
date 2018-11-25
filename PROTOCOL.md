# Zei Protocol Outline

## PublicKey based NonInteractive Encryption

We desire to send an ecrypted packet so that only the holder of the secret key accoiated with
a Publickey can unlock the packet. This is used in Zei to send plaintext balance and the blinding used for a transaction.
We assume an authenticated cipher is used such as AES_GCM or XSALSA20_POLY1305 as we use.

    Sender -> Receiver (pk)
    1. Sample Some Fresh Randomness (R)
    2. Take pk^R = KEY , this key is used for encryption
    3. Encrypt: ENC(HASH(KEY), message) = cipherText
    4. Send (cipherText, g^R) to recipient
    5. Receiver Must Derive shared key
        5a. Knows g^x = pk. x is secret key
        5b. Recall sender took pk^R as key, thus REDERIVED_KEY == pk^R == (g^x)^R == g^xR == (g^R)^x
    6. Decrypt: DEC(HASH(REDERIVED_KEY), cipherText)


## Confidential Payments for Accounts

### Accounts

We use an Account Model. An account is defined as:

    type Account = {
        counter: u128,
        balance: u64,
        opening: Scalar,
        commitment: CurvePoint,
    }

    - u128 = unsigned 128 bit integer
    - u64 = unsigned 64 bit integer
    - Scalar = unsigned 256bit integer
    - CurvePoint = A point that lies on an eliptic curve

### Keypair & Addresses

Each account is associated with a keypair, in this case an Schnorr keypair over the Ristretto curve.

We also use an accounts public key as the address on the network. This is used to encrypt packets to that account only.
Zei Network Addresses are the base58 of the account Public key with the 'ZEI_' prefix added.

```
ZEI_gvcCi6ovrMgnBN7bMdNaxyRXoZxM1NrpGM9jY8whNizeMizCs
```
Each account has secret storage that the owner stores. Here there is the plaintext balance for that account and the opening Scalar value that is needed to spend the transactions.

### Ledger
Accounts are tracked on a Ledger. A ledger is a mapping between Address and commitments.

    type Ledger = {
        Address => Commitment
    }

    An address is an accounts Public Key.
    A commitment is a curvepoint. 


### Hidden Transactions
Hidden Transactions hide the amount that is being sent. 

Pedersen commitment in the Elliptic Curve context:

>                C = mG + rH

G is now a generator point (sometimes called base point)

C is a point on the EC. 

So an EC point (for a 256 bit curve, anyway) can be encoded into 33 bytes.

#### Sending a Transaction

To send a transacting using an account:

    1. A before a Transaction can be generated we need to know:

        a. Public Key of the Reciever
        b. Latest commitment of that reciever
        c. The transfer amount

    2. We must generate a new transaction with the needed proofs and commitments.
      We also send a reciver encrypted package of the plaintext balance and new blinding.


        a. Reduce account local balance with current transfer ammount
        b. Sample Fresh blinding factor [blind], its a scalar (blinding_t)
        c. Create Commitment ->  g^amount * h^[blind] == comm_t
        d. Create Commitment ->  g^(Balance - amount) * h^(Opening - blind) == new_comm_sender
        e. Create rangeproof for amount & use [blind] as randomness == RP_T
        f. Create rangeproof for (Balance - transfer_amount) & use Opening - blind as randomness == RP_S
        g. Multiply Commitment ->  oldCommR * CommT == CommR
        h. Encrypt to receiver pubkey both the transfer_amount transferred and the blinding factor [blind] 
    
#### Recieve a Transaction

When a new transaction is found on the network for this account we must process it and reflect our local account with our updated balance and new openning. This is crucial as the new opening allows us to spend from the account.