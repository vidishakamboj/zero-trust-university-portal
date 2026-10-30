
require("dotenv").config();

const bcrypt = require("bcrypt");
const db = require("./config/database");

async function fixLogin() {
  const universityId = "STU2026001";
  const password = "Student@12345";

  try {
    console.log("Checking database:", process.env.DB_NAME);

    const [rows] = await db.execute(
      `SELECT id, university_id, full_name,
              password_hash, role, account_status
       FROM users
       WHERE university_id = ?`,
      [universityId]
    );

    if (rows.length === 0) {
      console.log("Student not found. Creating demo account...");

      const hash = await bcrypt.hash(password, 12);

      await db.execute(
        `INSERT INTO users
         (university_id, full_name, email,
          password_hash, role, account_status)
         VALUES (?, ?, ?, ?, 'student', 'active')`,
        [
          universityId,
          "Demo Student",
          "demo.student@example.com",
          hash
        ]
      );

    } else {
      console.log("Student found. Repairing demo credentials...");

      const hash = await bcrypt.hash(password, 12);

      await db.execute(
        `UPDATE users
         SET password_hash = ?,
             account_status = 'active',
             role = 'student'
         WHERE university_id = ?`,
        [hash, universityId]
      );
    }

    const [verifiedRows] = await db.execute(
      `SELECT university_id, password_hash,
              account_status, role
       FROM users
       WHERE university_id = ?`,
      [universityId]
    );

    const user = verifiedRows[0];

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    console.log("------------------------------");
    console.log("University ID:", user.university_id);
    console.log("Role:", user.role);
    console.log("Account Status:", user.account_status);
    console.log("Password Matches:", passwordCorrect);
    console.log("------------------------------");

    if (
      passwordCorrect &&
      user.account_status === "active" &&
      user.role === "student"
    ) {
      console.log("SUCCESS: Demo account is ready.");
    } else {
      console.log("FAILED: Account verification unsuccessful.");
    }

  } catch (error) {
    console.error("DATABASE ERROR:", error.message);
  } finally {
    await db.end();
  }
}

fixLogin();
