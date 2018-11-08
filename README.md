# Zei

** Confidential Payments for Accounts **


## NodeJS API

### Create a transaction

The account api has an send() function that consumes a JSON structure that needs to be constructed
with data from the stellar network.

Stellar accounts have there own signatire keypairs that are used to send transactions on the network.
These accounts also have arbitary KEY-VALUE pairs that may be set.
We will set the hidden account publickey as the KEY & set the latest balance commitment as a VALUE.

#### How to create a new Confidential Account with Zei

#### How to Send a Confidential Transaction

```javascript
//This is a JSON string
var new_tx = {
    receiver: "", //public key for destination secret account
    receiver_commit: "", //the latest commitment associated with that public key
    transfer_amount: "", //the senders desired amount
}
```

