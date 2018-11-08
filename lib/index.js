var z = require('../native');

//export method to generate keypairs
module.exports.create_account = z.create_account;
//export method to construct a transaction
//module.exports.create_tx = z.create_tx;

console.log(z.create_account());