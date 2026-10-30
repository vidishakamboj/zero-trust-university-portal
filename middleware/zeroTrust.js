const db = require("../config/database");

const IDLE_TIMEOUT = 15 * 60 * 1000;
const ABSOLUTE_TIMEOUT = 8 * 60 * 60 * 1000;

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "").slice(0, 45);
}

async function logSecurityEvent(req, {
  userId = null,
  universityId = null,
  eventType,
  status,
  details = null
}) {
  try {
    await db.execute(
      `INSERT INTO audit_events
       (user_id, university_id, event_type, event_status, ip_address, details)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, universityId, eventType, status, getClientIp(req), details]
    );
  } catch (error) {
    console.error("Audit logging failed:", error.message);
  }
}

function destroySession(req, res, status, message) {
  if (!req.session) return res.redirect("/");
  req.session.destroy(error => {
    if (error) return res.status(500).send("Unable to end session.");
    res.clearCookie("zt.sid");
    if (status === 401) return res.redirect("/");
    return res.status(status).send(message);
  });
}

async function zeroTrustStudent(req, res, next) {
  try {
    const sessionUser = req.session?.user;
    if (!sessionUser?.id) {
      console.error("ZERO TRUST: No authenticated session");
      return res.redirect("/");
    }

    if (req.session.mfaVerified !== true) {
      console.error("ZERO TRUST: MFA not verified");
      await logSecurityEvent(req, {
        userId: sessionUser.id,
        universityId: sessionUser.universityId,
        eventType: "MFA_ACCESS_DENIED",
        status: "DENIED",
        details: "MFA verification required"
      });
      return res.status(403).send("Access denied: OTP verification required.");
    }

    const now = Date.now();
    const issuedAt = Number(req.session.issuedAt || 0);
    const lastActivity = Number(req.session.lastActivity || 0);
    if (!issuedAt || !lastActivity || now - issuedAt > ABSOLUTE_TIMEOUT || now - lastActivity > IDLE_TIMEOUT) {
      console.error("ZERO TRUST: Session expired");
      await logSecurityEvent(req, {
        userId: sessionUser.id,
        universityId: sessionUser.universityId,
        eventType: "SESSION_EXPIRED",
        status: "DENIED",
        details: "Idle or absolute session timeout"
      });
      return destroySession(req, res, 401, "Session expired");
    }

    const studentId = Number(sessionUser.id);
    if (!Number.isSafeInteger(studentId) || studentId <= 0) {
      console.error("ZERO TRUST: Invalid session user ID");
      return destroySession(req, res, 403, "Access denied: Invalid session user ID.");
    }

    const [rows] = await db.execute(
      `SELECT id, university_id, full_name, role, account_status
       FROM users WHERE id = ? LIMIT 1`,
      [studentId]
    );
    const user = rows[0];
    if (!user) {
      console.error("ZERO TRUST: User not found", studentId);
      return destroySession(req, res, 403, "Access denied: Student not found.");
    }

    const role = String(user.role ?? "").trim().toLowerCase();
    const status = String(user.account_status ?? "").trim().toLowerCase();
    if (role !== "student" || status !== "active") {
      console.error("ZERO TRUST: Unauthorized student account", { userId: studentId, role, status });
      await logSecurityEvent(req, {
        userId: user.id,
        universityId: user.university_id,
        eventType: "ACCESS_DENIED",
        status: "DENIED",
        details: "Invalid student role or inactive account"
      });
      return destroySession(req, res, 403, "Access denied: Student role or account status invalid.");
    }

    // Database ID is authoritative. University ID is refreshed from the same user record.
    req.session.user = {
      id: user.id,
      universityId: user.university_id,
      fullName: user.full_name,
      role: "student"
    };
    req.session.lastActivity = now;
    req.session.touch();
    res.set("Cache-Control", "no-store");
    return next();
  } catch (error) {
    console.error("ZERO TRUST MIDDLEWARE ERROR:", error);
    return next(error);
  }
}

module.exports = {
  zeroTrustStudent,
  logSecurityEvent,
  IDLE_TIMEOUT,
  ABSOLUTE_TIMEOUT
};
