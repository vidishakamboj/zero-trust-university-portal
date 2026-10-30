
require("dotenv").config();

const bcrypt = require("bcrypt");
const db = require("./config/database");

async function setupDemoStudent() {
  try {
    const universityId = "STU2026001";
    const password = "Student@12345";

    const passwordHash = await bcrypt.hash(password, 12);

    const [existing] = await db.execute(
      "SELECT id FROM users WHERE university_id = ?",
      [universityId]
    );

    if (existing.length === 0) {
      await db.execute(
        `INSERT INTO users
         (university_id, full_name, email,
          password_hash, role, account_status)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          universityId,
          "Demo Student",
          "demo.student@example.com",
          passwordHash,
          "student",
          "active"
        ]
      );

      console.log("Demo student CREATED successfully.");
    } else {
      await db.execute(
        `UPDATE users
         SET password_hash = ?,
             account_status = 'active',
             role = 'student'
         WHERE university_id = ?`,
        [passwordHash, universityId]
      );

      console.log("Demo student UPDATED successfully.");
    }

    // Verify the stored password
    const [users] = await db.execute(
      `SELECT university_id, password_hash,
              role, account_status
       FROM users
       WHERE university_id = ?`,
      [universityId]
    );

    const user = users[0];
    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    console.log("University ID:", user.university_id);
    console.log("Role:", user.role);
    console.log("Account status:", user.account_status);
    console.log("Password verification:", passwordMatches);

    if (!passwordMatches) {
      throw new Error("Password verification failed.");
    }

    console.log("Demo account is ready for login.");

  } catch (error) {
    console.error("Setup failed:", error.message);
    process.exitCode = 1;
  } finally {
    await db.end();
  }
}

setupDemoStudent();
