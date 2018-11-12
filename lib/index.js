var z = require('../native');

//export method to generate keypairs
module.exports.create_account = z.create_account;
//export method to construct a transaction
module.exports.create_tx = z.create_tx;
//export method to apply a transaction that has been sent to an account to update its state
module.exports.recieve_tx = z.recieve_tx;


// var account = z.create_account();
// var accountB = z.create_account();
// var parsed = JSON.parse(account);
// var parsedB = JSON.parse(accountB);
// //set the account balnce
// parsed.balance = 100;
// parsedB.balance = 10;

// //console.log(parsed);

// var new_tx = {
//     receiver: parsedB.keys.public, //public key for destination secret account
//     receiver_commit: parsedB.commitment, //the latest commitment associated with that public key
//     transfer_amount: 10, //the senders desired amount
// };

// var myJSON = JSON.stringify(new_tx);
// console.log(myJSON);

// console.log(z.create_tx(myJSON, account));


// console.log("Account address in hex is : ZEI_" + toHexString(parsed.keys.public));