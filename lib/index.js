var z = require('../native');

//export method to generate keypairs
module.exports.create_account = z.create_account;
//export method to construct a transaction
//module.exports.create_tx = z.create_tx;

// function toHexString(byteArray) {
//     return byteArray.reduce((output, elem) => 
//       (output + ('0' + elem.toString(16)).slice(-2)),
//       '');
// }

// var account = z.create_account();
// var parsed = JSON.parse(account);

// console.log(account);
// //console.log(parsed);

// console.log("Account address in hex is : ZEI_" + toHexString(parsed.keys.public));