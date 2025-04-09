const { exec } = require('child_process');
const path = require('path');

// Configuration
const config = {
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'test',
  port: 3000
};

// Set environment variables for JWT
process.env.JWT_SECRET = '2c6e96d023f3c9eea935ff4ebc9370d9eb2d139553a86cd60b5ab600ca2a2d46';

// Build the command
const command = `node ${path.join(__dirname, 'bin', 'index.js')} -h ${config.host} -u ${config.user} -p "${config.password}" -d ${config.database} -n ${config.port}`;

console.log('Starting xmysql server with configuration:');
console.log(`- Host: ${config.host}`);
console.log(`- Database: ${config.database}`);
console.log(`- User: ${config.user}`);
console.log(`- Port: ${config.port}`);
console.log(`- JWT Secret: ${process.env.JWT_SECRET.substring(0, 10)}...`);
console.log('\nCommand:', command);

// Execute the command
const child = exec(command);

child.stdout.on('data', (data) => {
  console.log(data);
});

child.stderr.on('data', (data) => {
  console.error(data);
});

child.on('close', (code) => {
  console.log(`Child process exited with code ${code}`);
}); 