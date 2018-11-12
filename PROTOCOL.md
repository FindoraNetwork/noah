# Zei Protocol Outline

## Public Key based non interactive encryption


Sender -> Receiver (pk)
1. Sample Some Fresh Randomness (R)
2. Take pk^R = KEY , this key is used for encryption
3. Encrypt: AES_ENC(HASH(KEY), message) = cipherText
4. Send (cipherText, g^R) to recipient
5. Receiver Must Derive shared key
     5a. Knows g^x = pk. x is secret key
     5b. Recall sender took pk^R as key, thus REDERIVED_KEY == pk^R == (g^x)^R == g^xR == (g^R)^x
6. Decrypt: AES_DEC(HASH(REDERIVED_KEY), cipherText)


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

Each account is associated with a keypair, in this case an elgamal keypair over the Ristretto curve.

Generating an Elgamal Keypair:

    1. Sample some randomness at 32byte length as a Scalar. This is the secret key.
    2. Too generate a public key for this secret key we multiply this scalar over the basepoint of the chosen curve.
        In this case it is over the ristretto curve.

We also use an accounts public key as the address on the network. This is used to encrypt packets to that account only.

### Ledger
Accounts are tracked on a Ledger. A ledger is a mapping between Address and commitments.

    type Ledger = {
        Address => Commitment
    }

    An address is an accounts Public Key.
    A commitment is a curvepoint. 


### Hidden Transactions
Hidden Transactions hide the amount that is being sent. 
