var z = require('../native');

//
// Export Methods
//


//export method to generate keypairs
module.exports.create_account = z.create_account;
//export method to construct a transaction
module.exports.create_tx = z.create_tx;
//export method to apply a transaction that has been sent to an account to update its state
module.exports.recieve_tx = z.recieve_tx;

/*

//
//TEST DEMO
//

//Create Accounts, these are JSON
var sender = z.create_account();
var reciever = z.create_account();

//Parse JSON into JS object
var sender_p = JSON.parse(sender);
var reciever_p = JSON.parse(reciever);

//set the account balances to some values
sender.balance = 100;
reciever.balance = 10;

console.log("Parsed Account: ");
console.log(parsed);
var new_tx = {
    receiver: parsedB.keys.public, //public key for destination secret account
    receiver_commit: parsedB.commitment, //the latest commitment associated with that public key
    transfer_amount: 10, //the senders desired amount
};

var myJSON = JSON.stringify(new_tx);
console.log(myJSON);

//console.log(z.create_tx(account, myJSON));


//console.log("Account address in hex is : ZEI_" + toHexString(parsed.keys.public));


*/