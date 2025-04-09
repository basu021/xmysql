const express = require('express');
const mysql = require('mysql');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cors = require('cors');
const Xapi = require('./lib/xapi');

const app = express();

// Middleware
app.use(morgan('tiny'));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL configuration
const mysqlConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'test',
  password: process.env.DB_PASSWORD || 'test',
  database: process.env.DB_NAME || 'test',
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10
};

// Create MySQL pool
const mysqlPool = mysql.createPool(mysqlConfig);

// Initialize database schema
function initializeDatabase(callback) {
  mysqlPool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      return callback(err);
    }

    // Create users table if it doesn't exist
    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user'
      )
    `;

    connection.query(createUsersTable, (err) => {
      if (err) {
        connection.release();
        console.error('Error creating users table:', err);
        return callback(err);
      }

      // Get all tables in the database
      connection.query('SHOW TABLES', (err, tables) => {
        connection.release();
        if (err) {
          console.error('Error getting tables:', err);
          return callback(err);
        }

        console.log('Database schema initialized successfully');
        console.log('Available tables:', tables.map(t => Object.values(t)[0]));
        callback(null);
      });
    });
  });
}

// Initialize database and start server
initializeDatabase((err) => {
  if (err) {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  }

  // Initialize Xmysql with proper configuration
  const xapiConfig = {
    ...mysqlConfig,
    apiPrefix: '/api/',
    readOnly: false
  };

  const xapi = new Xapi(xapiConfig, mysqlPool, app);

  // Start server
  const PORT = process.env.PORT || 3000;

  xapi.init((err, stat) => {
    if (err) {
      console.error('Error initializing Xmysql:', err);
      return;
    }
    
    app.listen(PORT, () => {
      console.log(`Xmysql server running on port ${PORT}`);
      console.log('REST APIs are ready to use!');
      console.log('\nMySQL Configuration:');
      console.log(`- Host: ${mysqlConfig.host}`);
      console.log(`- Database: ${mysqlConfig.database}`);
      console.log(`- User: ${mysqlConfig.user}`);
      console.log('\nAvailable endpoints:');
      console.log('- GET /api/tables - List all tables');
      console.log('- GET /api/users - List all users');
      console.log('- POST /api/users - Create a new user');
    });
  });
}); 