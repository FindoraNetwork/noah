![alt text](https://github.com/eianio/zei/raw/master/zei_logo.png)

**Confidential Payments for Accounts**

Zei is a library to help manage an account system that hides transaction amounts.
It Implements Confidential Transactions that was first proposed by [Greg Maxwell](https://people.xiph.org/~greg/confidential_values.txt). It however utilizes [Bulletproofs by Benedikt et al.](https://eprint.iacr.org/2017/1066.pdf) for shorter Rangeproofs. Furthermore, [Elgamal](https://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf) Publickey encryption over the [Ristretto Group](https://ristretto.group) is utilized to reveal plaintext amounts & blinding factors to the reciever.
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

#### How to get an accounts Public Address & convert into HEX

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
//This is a JSON string, the key names must be the same!!!
var new_tx = {
    receiver: "", //public key for destination secret account
    receiver_commit: "", //the latest commitment associated with that public key
    transfer_amount: "", //the senders desired amount
};

//pass serilized account JSON as function argument first and the second is serilzed new tx info.
var jsobj = create_tx(account, JSON.stringify(new_tx));
//This jsobj containts two items.
//The key 'account' has the updated account JSON as a string
//The key 'tx' has the transaction packed up as JSON as a string
//It is important to keep the account as it is now updated as if the transaction is accepted by network

//As a results a full transaction is generated as seen bellow.

```

#### How to Recieve a Confidential Transaction
When an account hears about a new transaction that has been sent to it,
it will apply that transaction to its local account to update its balance and latest
blinding factor so it may spend the funds.

```javascript
//This is a JSON string, it is the transaction that we heared from the network for us
//We pass our account JSON and the transaction JSON and get back our asccount JSON updated.
var updated_account = recieve_tx(account, tx);

//As a results a full transaction is generated as seen bellow.

```

### Example

```javascript


//Create Accounts, these are JSON
var sender = create_account();
var reciever = create_account();

//Parse JSON into JS object
var sender_p = JSON.parse(sender);
var reciever_p = JSON.parse(reciever);

//set the account balances to some values
sender.balance = 100;
reciever.balance = 10;

```

//https://gist.github.com/tauzen/3d18825ae41ff3fc8981
function byteToHexString(uint8arr) {
  if (!uint8arr) {
    return '';
  }
  
  var hexStr = '';
  for (var i = 0; i < uint8arr.length; i++) {
    var hex = (uint8arr[i] & 0xff).toString(16);
    hex = (hex.length === 1) ? '0' + hex : hex;
    hexStr += hex;
  }
  
  return hexStr.toUpperCase();
}

function hexStringToByte(str) {
  if (!str) {
    return new Uint8Array();
  }
  
  var a = [];
  for (var i = 0, len = str.length; i < len; i+=2) {
    a.push(parseInt(str.substr(i,2),16));
  }
  
  return new Uint8Array(a);
}