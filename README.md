![alt text](https://github.com/eianio/zei/raw/master/zei_logo.png)

**Confidential Payments for Accounts**

Zei is a library to help manage an account system that blindes transaction amounts.
It Implements Confidential Transactions that was first proposed by [Greg Maxwell](https://people.xiph.org/~greg/confidential_values.txt). It however utilizes [Bulletproofs by Benedikt et al.](https://eprint.iacr.org/2017/1066.pdf) for shorter Rangeproofs. Furthermore, Elgamal Publickey encryption over the [Ristretto Group](https://ristretto.group) is utilized to reveal plaintext amounts & blinding factors to the reciever.
This implementation uses Pedersen Commitments and is vulnerable to account poisoning. 


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

//An example of what it returns, never change this data, only zei should.
    {
        "counter": 0,

        "balance": 0,

        "opening": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],

        "commitment": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],

        "keys":{
            "secret": [100,208,32,60,172,238,201,237,185,80,243,255,62,180,99,93,101,224,179,85,152,184,185,53,146,2,145,110,163,204,16,7],

            "public": [10,127,221,55,39,154,45,154,100,222,164,174,229,244,209,217,66,171,184,21,117,176,88,205,130,21,21,208,15,220,201,103]
        }
    }
```
Using the above JSON as an example the address to this account is *keys.public*

#### How to get an acconts Public Address & convert into HEX

```javascript

//helper function to convert a byte array to hex string
function toHexString(byteArray) {
    return byteArray.reduce((output, elem) => 
      (output + ('0' + elem.toString(16)).slice(-2)),
      '');
}

//create a new ZEI account
var account = create_account();
//convert the JSON into JS object to use.
var parsed = JSON.parse(account);

//console.log(account);
//console.log(parsed);

//This example uses 'ZEI_' extension to denote our address 
console.log("Account address in hex is : ZEI_" + toHexString(parsed.keys.public));
//Account address in hex is : ZEI_a2305a019d05a19f7f1dbbb93ed172da356fc702dcd797d25681fdbe710ae56e

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

