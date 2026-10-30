require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const helmet = require("helmet");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const { PNG } = require("pngjs");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");

const db = require("./config/database");

const {
  zeroTrustStudent,
  logSecurityEvent,
  IDLE_TIMEOUT
} = require("./middleware/zeroTrust");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET missing in .env");
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  name: "zt.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: IDLE_TIMEOUT
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many attempts. Try again later."
  }
});

const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: "Too many OTP attempts. Please try again later."
});

// =====================================
// CAPTCHA
// =====================================

const font = {
  A: ["01110","10001","10001","11111","10001","10001","10001"],
  B: ["11110","10001","10001","11110","10001","10001","11110"],
  C: ["01111","10000","10000","10000","10000","10000","01111"],
  D: ["11110","10001","10001","10001","10001","10001","11110"],
  E: ["11111","10000","10000","11110","10000","10000","11111"],
  F: ["11111","10000","10000","11110","10000","10000","10000"],
  G: ["01111","10000","10000","10111","10001","10001","01111"],
  H: ["10001","10001","10001","11111","10001","10001","10001"],
  J: ["00111","00010","00010","00010","10010","10010","01100"],
  K: ["10001","10010","10100","11000","10100","10010","10001"],
  M: ["10001","11011","10101","10101","10001","10001","10001"],
  N: ["10001","11001","10101","10011","10001","10001","10001"],
  P: ["11110","10001","10001","11110","10000","10000","10000"],
  R: ["11110","10001","10001","11110","10100","10010","10001"],
  S: ["01111","10000","10000","01110","00001","00001","11110"],
  T: ["11111","00100","00100","00100","00100","00100","00100"],
  U: ["10001","10001","10001","10001","10001","10001","01110"],
  V: ["10001","10001","10001","10001","10001","01010","00100"],
  W: ["10001","10001","10001","10101","10101","10101","01010"],
  X: ["10001","10001","01010","00100","01010","10001","10001"],
  Y: ["10001","10001","01010","00100","00100","00100","00100"],
  Z: ["11111","00001","00010","00100","01000","10000","11111"],
  2: ["01110","10001","00001","00010","00100","01000","11111"],
  3: ["11110","00001","00001","01110","00001","00001","11110"],
  4: ["00010","00110","01010","10010","11111","00010","00010"],
  5: ["11111","10000","10000","11110","00001","00001","11110"],
  6: ["01111","10000","10000","11110","10001","10001","01110"],
  7: ["11111","00001","00010","00100","01000","01000","01000"],
  8: ["01110","10001","10001","01110","10001","10001","01110"],
  9: ["01110","10001","10001","01111","00001","00001","11110"]
};

function pixel(p, x, y, r, g, b) {
  if (x < 0 || y < 0 || x >= p.width || y >= p.height) {
    return;
  }

  const i = (p.width * y + x) * 4;

  p.data[i] = r;
  p.data[i + 1] = g;
  p.data[i + 2] = b;
  p.data[i + 3] = 255;
}

app.get("/captcha", (req, res) => {
  try {
    const chars = Object.keys(font);
    let code = "";

    for (let i = 0; i < 5; i++) {
      code += chars[crypto.randomInt(chars.length)];
    }

    const p = new PNG({
      width: 190,
      height: 65
    });

    for (let y = 0; y < 65; y++) {
      for (let x = 0; x < 190; x++) {
        pixel(p, x, y, 237, 246, 255);
      }
    }

    for (let n = 0; n < 5; n++) {
      const pattern = font[code[n]];

      for (let y = 0; y < 7; y++) {
        for (let x = 0; x < 5; x++) {
          if (pattern[y][x] === "1") {
            for (let dy = 0; dy < 4; dy++) {
              for (let dx = 0; dx < 4; dx++) {
                pixel(
                  p,
                  12 + n * 35 + x * 4 + dx,
                  18 + y * 4 + dy,
                  0, 31, 63
                );
              }
            }
          }
        }
      }
    }

    for (let i = 0; i < 130; i++) {
      pixel(
        p,
        crypto.randomInt(190),
        crypto.randomInt(65),
        145, 181, 207
      );
    }

    req.session.captcha = code.toLowerCase();
    req.session.captchaTime = Date.now();

    res.set("Cache-Control", "no-store");
    res.type("png").send(PNG.sync.write(p));

  } catch (error) {
    console.error("CAPTCHA:", error);
    res.status(500).send("CAPTCHA unavailable");
  }
});

function checkCaptcha(req, value) {
  const expected = req.session.captcha;
  const time = req.session.captchaTime;

  delete req.session.captcha;
  delete req.session.captchaTime;

  return (
    typeof value === "string" &&
    Boolean(expected) &&
    Boolean(time) &&
    Date.now() - time < 300000 &&
    value.trim().toLowerCase() === expected
  );
}

// =====================================
// LOGIN AND REGISTRATION PAGES
// =====================================

app.get("/", (req, res) => {
  if (req.session.user && req.session.mfaVerified === true) {
    return res.redirect("/student/dashboard");
  }

  const pending = req.session.pendingMfa;

  if (
    pending &&
    Date.now() - pending.createdAt < 5 * 60 * 1000 &&
    pending.attempts < 5
  ) {
    return res.redirect("/mfa");
  }

  res.render("login");
});

app.get("/register", (req, res) => {
  if (req.session.user && req.session.mfaVerified === true) {
    return res.redirect("/student/dashboard");
  }

  res.render("register");
});

// =====================================
// REGISTER STUDENT
// =====================================

app.post("/register", limiter, async (req, res) => {
  try {
    const {
      fullName,
      universityId,
      email,
      password,
      confirmPassword,
      captcha
    } = req.body;

    if (
      ![
        fullName,
        universityId,
        email,
        password,
        confirmPassword,
        captcha
      ].every(x => typeof x === "string")
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    const name = fullName.trim();
    const id = universityId.trim();
    const mail = email.trim().toLowerCase();

    if (
      name.length < 2 ||
      name.length > 100 ||
      !/^[a-zA-Z0-9_-]{4,30}$/.test(id) ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail) ||
      mail.length > 254 ||
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter valid name, Student ID, email and password."
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match."
      });
    }

    if (!checkCaptcha(req, captcha)) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired CAPTCHA."
      });
    }

    const [found] = await db.execute(
      `SELECT id FROM users
       WHERE university_id = ? OR email = ?
       LIMIT 1`,
      [id, mail]
    );

    if (found.length) {
      return res.status(409).json({
        success: false,
        message: "Student ID or email already registered."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const [result] = await db.execute(
      `INSERT INTO users
       (
         university_id,
         full_name,
         email,
         password_hash,
         role,
         account_status
       )
       VALUES (?, ?, ?, ?, 'student', 'active')`,
      [id, name, mail, hash]
    );

    await db.execute(
      `INSERT IGNORE INTO course_enrollments
       (student_id, course_id)
       SELECT ?, id FROM courses`,
      [result.insertId]
    );

    res.json({
      success: true,
      message: "Registration successful. Please log in.",
      redirect: "/"
    });

  } catch (error) {
    console.error("Register:", error);

    res.status(error.code === "ER_DUP_ENTRY" ? 409 : 500).json({
      success: false,
      message: error.code === "ER_DUP_ENTRY"
        ? "Student ID or email already exists."
        : "Registration failed. Check terminal."
    });
  }
});
// =====================================
// STUDENT LOGIN
// =====================================

app.post("/login", limiter, async (req, res) => {
  try {
    const { universityId, password, captcha } = req.body;

    if (
      typeof universityId !== "string" ||
      typeof password !== "string" ||
      !universityId.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter Student ID and password."
      });
    }

    if (!checkCaptcha(req, captcha)) {
      await logSecurityEvent(req, {
        universityId: universityId.trim(),
        eventType: "LOGIN_CAPTCHA_FAILED",
        status: "DENIED",
        details: "Invalid or expired CAPTCHA"
      });

      return res.status(400).json({
        success: false,
        message: "Invalid or expired CAPTCHA."
      });
    }

    const [rows] = await db.execute(
      `SELECT id, university_id, full_name,
              password_hash, role, account_status
       FROM users
       WHERE university_id = ?
       LIMIT 1`,
      [universityId.trim()]
    );

    const user = rows[0];
    const valid = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (
      !user ||
      !valid ||
      String(user.account_status ?? "").trim().toLowerCase() !== "active" ||
      String(user.role ?? "").trim().toLowerCase() !== "student"
    ) {
      await logSecurityEvent(req, {
        userId: user ? user.id : null,
        universityId: universityId.trim(),
        eventType: "LOGIN_FAILED",
        status: "DENIED",
        details: "Invalid credentials or account not permitted"
      });

      return res.status(401).json({
        success: false,
        message: "Invalid credentials or inactive account."
      });
    }

    // Password + CAPTCHA verified.
    // Full login is NOT granted until OTP verification.

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({
          success: false,
          message: "Session creation failed."
        });
      }

      req.session.pendingMfa = {
        userId: user.id,
        universityId: user.university_id,
        createdAt: Date.now(),
        attempts: 0
      };

      req.session.save(error => {
        if (error) {
          return res.status(500).json({
            success: false,
            message: "Session save failed."
          });
        }

        return res.json({
          success: true,
          message: "Password verified. Complete OTP verification.",
          redirect: "/mfa"
        });
      });
    });

  } catch (error) {
    console.error("Login:", error);

    res.status(500).json({
      success: false,
      message: "Login failed. Check terminal."
    });
  }
});

// =====================================
// PHASE 2 - AUTHENTICATOR MFA
// =====================================

const MFA_PENDING_MS = 5 * 60 * 1000;
const MFA_MAX_ATTEMPTS = 5;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

function mfaPage(content) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width, initial-scale=1">

  <title>Zero Trust University | MFA</title>
</head>

<body style="
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  background:#001f3f;
  font-family:Arial,sans-serif;
  color:#17324d;
">

  <main style="
    width:90%;
    max-width:420px;
    background:white;
    padding:32px;
    border-radius:14px;
    text-align:center;
    box-sizing:border-box;
  ">

    <h2>Zero Trust University</h2>
    <h3>Multi-Factor Authentication</h3>

    ${content}

  </main>

</body>
</html>`;
}

function validPending(req) {
  const pending = req.session.pendingMfa;

  if (!pending) {
    return null;
  }

  if (!Number.isInteger(pending.userId)) {
    return null;
  }

  if (
    Date.now() - pending.createdAt >= MFA_PENDING_MS ||
    pending.attempts >= MFA_MAX_ATTEMPTS
  ) {
    return null;
  }

  return pending;
}

// =====================================
// DISPLAY MFA PAGE
// =====================================

app.get("/mfa", async (req, res, next) => {
  res.set("Cache-Control", "no-store");

  try {
    if (
      req.session.user &&
      req.session.mfaVerified === true
    ) {
      return res.redirect("/student/dashboard");
    }

    const pending = validPending(req);

    if (!pending) {
      return res.redirect("/");
    }

    const [rows] = await db.execute(
      `SELECT mfa_secret, role, account_status
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [pending.userId]
    );

    if (
      !rows.length ||
      String(rows[0].role ?? "").trim().toLowerCase() !== "student" ||
      String(rows[0].account_status ?? "").trim().toLowerCase() !== "active"
    ) {
      console.error("MFA SETUP DENIED: Student missing, unauthorized, or inactive");
      return res.status(403).send("Student account is not active or authorized.");
    }

    let setup = `
      <p>
        Open your Authenticator App and enter
        its current 6-digit verification code.
      </p>
    `;

    // First-time authenticator setup
    if (!rows[0].mfa_secret) {
      if (!req.session.pendingMfaSecret) {
        req.session.pendingMfaSecret =
          authenticator.generateSecret();
      }

      const secret = req.session.pendingMfaSecret;

      const uri = authenticator.keyuri(
        pending.universityId,
        "Zero Trust University",
        secret
      );

      const qr = await QRCode.toDataURL(uri);

      setup = `
        <p>
          First-time setup: scan this QR code
          using Google or Microsoft Authenticator.
        </p>

        <img
          src="${qr}"
          alt="Authenticator setup QR"
          width="190"
          height="190"
        >

        <p>Or enter this setup key manually:</p>

        <code style="overflow-wrap:anywhere">
          ${escapeHtml(secret)}
        </code>
      `;
    }

    return res.send(mfaPage(`
      ${setup}

      <form method="POST" action="/mfa/verify">

        <input
          type="text"
          name="otp"
          placeholder="Enter 6-digit OTP"
          inputmode="numeric"
          pattern="[0-9]{6}"
          maxlength="6"
          autocomplete="one-time-code"
          required
          style="
            padding:12px;
            width:85%;
            margin:16px 0;
            box-sizing:border-box;
          "
        >

        <button
          type="submit"
          style="
            padding:12px 24px;
            background:#001f3f;
            color:white;
            border:0;
            border-radius:6px;
            cursor:pointer;
          "
        >
          Verify OTP
        </button>

      </form>

      <p>
        <a href="/mfa/cancel">
          Cancel and log in again
        </a>
      </p>
    `));

  } catch (error) {
    next(error);
  }
});

// =====================================
// CANCEL MFA
// =====================================

app.get("/mfa/cancel", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).send(
        "Could not reset login."
      );
    }

    res.clearCookie("zt.sid");
    return res.redirect("/");
  });
});

// =====================================
// VERIFY MFA OTP
// =====================================

app.post(
  "/mfa/verify",
  mfaLimiter,
  async (req, res, next) => {

    res.set("Cache-Control", "no-store");

    try {
      const pending = validPending(req);

      if (!pending) {
        return res.status(401).send(mfaPage(`
          <p>
            Verification expired or too many attempts.
          </p>

          <a href="/mfa/cancel">
            Log in again
          </a>
        `));
      }

      const [rows] = await db.execute(
        `SELECT
           id,
           university_id,
           full_name,
           role,
           account_status,
           mfa_secret
         FROM users
         WHERE id = ?
         LIMIT 1`,
        [pending.userId]
      );

      const user = rows[0];

      if (!user) {
        console.error("MFA DENIED: No user for pending ID", pending.userId);
        return res.status(403).send("Access denied: Student account not found.");
      }

      const normalizedRole = String(user.role ?? "").trim().toLowerCase();
      const normalizedStatus = String(user.account_status ?? "").trim().toLowerCase();

      if (normalizedRole !== "student") {
        console.error("MFA DENIED: Role not student", { userId: user.id, role: normalizedRole });
        return res.status(403).send("Access denied: Student role required.");
      }

      if (normalizedStatus !== "active") {
        console.error("MFA DENIED: Account inactive", { userId: user.id, status: normalizedStatus });
        return res.status(403).send("Access denied: Student account inactive.");
      }

      const otp =
        typeof req.body.otp === "string"
          ? req.body.otp.trim()
          : "";

      const secret =
        user.mfa_secret ||
        req.session.pendingMfaSecret;

      const verified =
        Boolean(secret) &&
        /^[0-9]{6}$/.test(otp) &&
        authenticator.check(otp, secret);

      // Wrong OTP
      if (!verified) {
        pending.attempts++;

        await logSecurityEvent(req, {
          userId: user.id,
          universityId: user.university_id,
          eventType: "MFA_FAILED",
          status: "DENIED",
          details: "Invalid authenticator code"
        });

        return res.status(401).send(mfaPage(`
          <p style="color:#b42318">
            Invalid OTP.
          </p>

          <a href="/mfa">
            Try again
          </a>
        `));
      }

      // Save secret only after correct first OTP
      if (!user.mfa_secret) {
        const [result] = await db.execute(
          `UPDATE users
           SET mfa_secret = ?
           WHERE id = ?
             AND mfa_secret IS NULL`,
          [secret, user.id]
        );

        if (result.affectedRows !== 1) {
          return res.status(409).send(
            "MFA setup changed. Please log in again."
          );
        }
      }

      
      // ==========================================
      // CREATE FULLY AUTHENTICATED STUDENT SESSION
      // ==========================================

      req.session.regenerate((error) => {
        if (error) {
          console.error("Session regeneration failed:", error);
          return next(error);
        }

        const now = Date.now();

        // Store identity of the OTP-verified student
        req.session.user = {
          id: user.id,
          universityId: user.university_id,
          fullName: user.full_name,
          role: "student"
        };

        // Mark MFA as successfully verified
        req.session.mfaVerified = true;

        // Initialize session security timestamps
        req.session.issuedAt = now;
        req.session.lastActivity = now;
        req.session.cookie.maxAge = IDLE_TIMEOUT;

        // Persist session before redirecting
        req.session.save(async (saveError) => {
          if (saveError) {
            console.error("Session save failed:", saveError);
            return next(saveError);
          }

          // Record successful MFA verification
          await logSecurityEvent(req, {
            userId: user.id,
            universityId: user.university_id,
            eventType: "MFA_SUCCESS",
            status: "SUCCESS",
            details: "Authenticator OTP verified"
          });

          // Record successful student login
          await logSecurityEvent(req, {
            userId: user.id,
            universityId: user.university_id,
            eventType: "LOGIN_SUCCESS",
            status: "SUCCESS",
            details: "Password, CAPTCHA and MFA verified"
          });

          console.log("MFA SUCCESS: Student session created", {
            userId: user.id,
            role: user.role,
            mfaVerified: req.session.mfaVerified
          });

          return res.redirect("/student/dashboard");
        });
      });


    } catch (error) {
      next(error);
    }
  }
);
// =====================================
// PROTECTED STUDENT ROUTES
// =====================================

// Keep the Zero Trust authorization in its dedicated middleware.
// Diagnostic output shows whether a request reaches this middleware.
// It never logs passwords, OTPs, secrets, or session cookies.
const requireStudent = (req, res, next) => {
  console.log("STUDENT ROUTE CHECK", {
    path: req.path,
    sessionUserId: req.session?.user?.id ?? null,
    mfaVerified: req.session?.mfaVerified === true,
    hasSession: Boolean(req.session)
  });
  return zeroTrustStudent(req, res, next);
};

// =====================================
// STUDENT DASHBOARD
// =====================================

app.get(
  "/student/dashboard",
  requireStudent,
  async (req, res, next) => {
    try {
      const id = req.session.user.id;

      const [
        [attendance],
        [courses],
        [assignments],
        [results]
      ] = await Promise.all([
        db.execute(
          `SELECT
             COALESCE(SUM(attended_classes), 0) attended,
             COALESCE(SUM(total_classes), 0) total
           FROM student_attendance
           WHERE student_id = ?`,
          [id]
        ),

        db.execute(
          `SELECT COUNT(*) total
           FROM course_enrollments
           WHERE student_id = ?`,
          [id]
        ),

        db.execute(
          `SELECT COUNT(*) total
           FROM assignments a
           JOIN course_enrollments e
             ON e.course_id = a.course_id
           WHERE e.student_id = ?`,
          [id]
        ),

        db.execute(
          `SELECT COUNT(*) total
           FROM student_results
           WHERE student_id = ?`,
          [id]
        )
      ]);

      const attended = Number(
        attendance[0].attended
      );

      const total = Number(
        attendance[0].total
      );

      res.render("student", {
        user: req.session.user,

        stats: {
          attendance: total
            ? ((attended / total) * 100).toFixed(1) + "%"
            : "N/A",

          courses: courses[0].total,
          assignments: assignments[0].total,
          results: results[0].total
        }
      });

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// DETAIL PAGE HELPER
// =====================================

function page(req, res, title, columns, rows) {
  res.render("student-page", {
    title,
    user: req.session.user,
    columns,
    rows
  });
}

// =====================================
// STUDENT PROFILE
// =====================================

app.get(
  "/student/profile",
  requireStudent,
  async (req, res, next) => {
    try {
      const [users] = await db.execute(
        `SELECT
           full_name,
           university_id,
           email,
           role
         FROM users
         WHERE id = ?`,
        [req.session.user.id]
      );

      const u = users[0];

      page(
        req,
        res,
        "My Profile",
        ["Field", "Information"],
        [
          ["Full Name", u.full_name],
          ["University ID", u.university_id],
          ["Email", u.email],
          ["Role", u.role]
        ]
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// STUDENT COURSES
// =====================================

app.get(
  "/student/courses",
  requireStudent,
  async (req, res, next) => {
    try {
      const [rows] = await db.execute(
        `SELECT
           c.course_code,
           c.course_name
         FROM courses c
         JOIN course_enrollments e
           ON e.course_id = c.id
         WHERE e.student_id = ?
         ORDER BY c.course_name`,
        [req.session.user.id]
      );

      page(
        req,
        res,
        "My Courses",
        ["Course Code", "Course Name"],

        rows.map(x => [
          x.course_code,
          x.course_name
        ])
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// STUDENT ATTENDANCE
// =====================================

app.get(
  "/student/attendance",
  requireStudent,
  async (req, res, next) => {
    try {
      const [rows] = await db.execute(
        `SELECT
           c.course_code,
           c.course_name,
           a.attended_classes,
           a.total_classes,

           ROUND(
             a.attended_classes * 100.0 /
             NULLIF(a.total_classes, 0),
             1
           ) percentage

         FROM student_attendance a

         JOIN courses c
           ON c.id = a.course_id

         JOIN course_enrollments e
           ON e.student_id = a.student_id
           AND e.course_id = a.course_id

         WHERE a.student_id = ?
         ORDER BY c.course_name`,
        [req.session.user.id]
      );

      page(
        req,
        res,
        "My Attendance",

        [
          "Course Code",
          "Subject",
          "Present",
          "Total Classes",
          "Attendance"
        ],

        rows.map(x => [
          x.course_code,
          x.course_name,
          x.attended_classes,
          x.total_classes,

          x.percentage === null
            ? "N/A"
            : x.percentage + "%"
        ])
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// STUDENT ASSIGNMENTS
// =====================================

app.get(
  "/student/assignments",
  requireStudent,
  async (req, res, next) => {
    try {
      const [rows] = await db.execute(
        `SELECT
           a.title,
           c.course_name,
           DATE_FORMAT(
             a.due_date,
             '%d-%m-%Y'
           ) due_date

         FROM assignments a

         JOIN courses c
           ON c.id = a.course_id

         JOIN course_enrollments e
           ON e.course_id = a.course_id

         WHERE e.student_id = ?
         ORDER BY a.due_date`,
        [req.session.user.id]
      );

      page(
        req,
        res,
        "My Assignments",

        [
          "Assignment",
          "Subject",
          "Due Date"
        ],

        rows.map(x => [
          x.title,
          x.course_name,
          x.due_date
        ])
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// STUDENT RESULTS
// =====================================

app.get(
  "/student/results",
  requireStudent,
  async (req, res, next) => {
    try {
      const [rows] = await db.execute(
        `SELECT
           c.course_code,
           c.course_name,
           r.marks_obtained,
           r.max_marks

         FROM student_results r

         JOIN courses c
           ON c.id = r.course_id

         JOIN course_enrollments e
           ON e.student_id = r.student_id
           AND e.course_id = r.course_id

         WHERE r.student_id = ?`,
        [req.session.user.id]
      );

      page(
        req,
        res,
        "My Results",

        [
          "Course Code",
          "Subject",
          "Obtained Marks",
          "Maximum Marks"
        ],

        rows.map(x => [
          x.course_code,
          x.course_name,
          x.marks_obtained,
          x.max_marks
        ])
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// SECURITY CENTER
// =====================================

app.get(
  "/student/security",
  requireStudent,
  async (req, res, next) => {
    try {
      const [events] = await db.execute(
        `SELECT
           event_type,
           event_status,
           ip_address,
           details,

           DATE_FORMAT(
             created_at,
             '%d-%m-%Y %H:%i:%s'
           ) AS event_time

         FROM audit_events
         WHERE user_id = ?

         ORDER BY created_at DESC, id DESC
         LIMIT 25`,
        [req.session.user.id]
      );

      page(
        req,
        res,
        "Security Center",

        [
          "Security Feature / Event",
          "Details",
          "Status / Time"
        ],

        [
          [
            "Authentication",
            "Password and CAPTCHA",
            "Verified at login"
          ],

          [
            "Authorization",
            "Student role and active account",
            "Checked on each request"
          ],

          [
            "Session",
            "15-minute idle timeout",
            "Enabled"
          ],

          [
            "Session Lifetime",
            "8-hour absolute maximum",
            "Enabled"
          ],

          [
            "Student Records",
            "Access scoped to signed-in student",
            "Enforced"
          ],

          [
            "MFA",
            "Authenticator App (TOTP)",
            "Verified"
          ],

          ...events.map(e => [
            e.event_type,

            [
              e.event_status,
              e.details,
              e.ip_address
            ]
              .filter(Boolean)
              .join(" | "),

            e.event_time
          ])
        ]
      );

    } catch (error) {
      next(error);
    }
  }
);

// =====================================
// SECURE LOGOUT
// =====================================

app.post("/logout", async (req, res) => {
  const user = req.session.user;

  if (user) {
    await logSecurityEvent(req, {
      userId: user.id,
      universityId: user.universityId,
      eventType: "LOGOUT",
      status: "SUCCESS",
      details: "Student signed out"
    });
  }

  req.session.destroy(error => {
    if (error) {
      return res.status(500).send(
        "Logout failed"
      );
    }

    res.clearCookie("zt.sid");
    res.redirect("/");
  });
});

// =====================================
// ERROR HANDLING
// =====================================

app.use((error, req, res, next) => {
  console.error(
    "Application error:",
    error
  );

  res.status(500).send(
    "Server error. Check VS Code terminal."
  );
});

// =====================================
// START SERVER
// =====================================

app.listen(PORT, () => {
  console.log(
    `Zero Trust University running at http://localhost:${PORT}`
  );
  console.log("Loaded server.js with student-route diagnostics enabled");
});
