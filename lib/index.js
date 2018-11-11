var z = require('../native');

//export method to generate keypairs
module.exports.create_account = z.create_account;
//export method to construct a transaction
module.exports.create_tx = z.create_tx;


// var account = z.create_account();
// var parsed = JSON.parse(account);
var new_tx = {
    receiver: "efe", //public key for destination secret account
    receiver_commit: "", //the latest commitment associated with that public key
    transfer_amount: "", //the senders desired amount
};

var myJSON = JSON.stringify(new_tx);


console.log(z.create_tx(myJSON));
// //console.log(parsed);

// console.log("Account address in hex is : ZEI_" + toHexString(parsed.keys.public));