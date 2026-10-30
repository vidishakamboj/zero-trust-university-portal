
require("dotenv").config();
const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "zero_trust_university",
  waitForConnections: true,
  connectionLimit: 10
});

module.exports = db;
