# zei

Confidential Payments for Accounts



## NodeJS API

### Create a transaction

The account api has an send() function that consumes a JSON structure that needs to be constructed
with data from the stellar network;

```javascript
//This is a JSON string
var new_tx = {
    receiver: "", //public key for destination secret account
    receiver_commit: "", //the latest commitment associated with that public key
    transfer_amount: "", //the senders desired amount
}
```

