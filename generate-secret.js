const crypto = require('crypto');
const secret = crypto.randomBytes(32).toString('hex');
console.log('Generated JWT Secret:');
console.log(secret);
console.log('\nCopy this secret and use it in your configuration.'); 