
const db = require("./config/database");

async function testConnection() {
  try {
    const [rows] = await db.query("SHOW TABLES");

    console.log("MySQL Connected Successfully!");
    console.log("Tables:", rows);

  } catch (error) {
    console.error("Connection Failed:", error.message);
  } finally {
    await db.end();
  }
}

testConnection();
