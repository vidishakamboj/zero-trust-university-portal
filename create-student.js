
require("dotenv").config();

const bcrypt = require("bcrypt");
const db = require("./config/database");

async function createStudent() {
  try {
    const universityId = "STU2026001";
    const password = "Student@12345";

    const passwordHash = await bcrypt.hash(password, 12);

    await db.execute(
      `INSERT INTO users
       (university_id, full_name, email, password_hash, role)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
       password_hash = VALUES(password_hash)`,
      [
        universityId,
        "Demo Student",
        "demo.student@example.com",
        passwordHash,
        "student"
      ]
    );

    console.log("Demo student account created!");
  } catch (error) {
    console.error("Error:", error.message);
  } finally {
    await db.end();
  }
}

createStudent();
