const crypto = require("crypto");
const db = require("../config/database");

// Risk score settings
const RISK_CONFIG = {
  FAILED_ATTEMPT_POINTS: 15,
  NEW_DEVICE_POINTS: 25,
  MAX_FAILED_ATTEMPT_POINTS: 60,
  HIGH_RISK_THRESHOLD: 70,
  MEDIUM_RISK_THRESHOLD: 30,
  LOOKBACK_MINUTES: 30
};

// Get client's IP address
function getClientIp(req) {
  return String(
    req.ip || req.socket.remoteAddress || "unknown"
  ).slice(0, 45);
}

// Generate a fingerprint from browser information.
// Note: This is a browser signature, not a reliable device ID.
function getDeviceFingerprint(req) {
  const userAgent = String(
    req.headers["user-agent"] || "unknown"
  );

  return crypto
    .createHash("sha256")
    .update(userAgent)
    .digest("hex");
}

// Count recent failed login attempts for this account
async function getRecentFailedAttempts(userId) {
  const minutes = RISK_CONFIG.LOOKBACK_MINUTES;

  const [rows] = await db.execute(
    `SELECT COUNT(*) AS failed_count
     FROM audit_events
     WHERE user_id = ?
       AND event_type = 'LOGIN_FAILED'
       AND created_at >= DATE_SUB(
         NOW(), INTERVAL ${minutes} MINUTE
       )`,
    [userId]
  );

  return Number(rows[0]?.failed_count || 0);
}

// Check whether browser signature has been seen
// on a previously successful login.
async function isNewDevice(userId, fingerprint) {
  const [rows] = await db.execute(
    `SELECT id
     FROM login_risk_events
     WHERE user_id = ?
       AND device_fingerprint = ?
       AND login_success = 1
     LIMIT 1`,
    [userId, fingerprint]
  );

  return rows.length === 0;
}

// Calculate risk before MFA
async function assessLoginRisk(req, userId) {
  const ipAddress = getClientIp(req);
  const deviceFingerprint = getDeviceFingerprint(req);

  const failedAttempts =
    await getRecentFailedAttempts(userId);

  const newDevice =
    await isNewDevice(userId, deviceFingerprint);

  let riskScore = 0;
  const reasons = [];

  if (failedAttempts > 0) {
    const failedPoints = Math.min(
      failedAttempts * RISK_CONFIG.FAILED_ATTEMPT_POINTS,
      RISK_CONFIG.MAX_FAILED_ATTEMPT_POINTS
    );

    riskScore += failedPoints;

    reasons.push(
      `${failedAttempts} recent failed login attempts`
    );
  }

  if (newDevice) {
    riskScore += RISK_CONFIG.NEW_DEVICE_POINTS;
    reasons.push("Unrecognized browser signature");
  }

  riskScore = Math.min(riskScore, 100);

  let riskLevel = "LOW";

  if (riskScore >= RISK_CONFIG.HIGH_RISK_THRESHOLD) {
    riskLevel = "HIGH";
  } else if (
    riskScore >= RISK_CONFIG.MEDIUM_RISK_THRESHOLD
  ) {
    riskLevel = "MEDIUM";
  }

  return {
    userId,
    ipAddress,
    deviceFingerprint,
    failedAttempts,
    newDevice,
    riskScore,
    riskLevel,
    reasons
  };
}

// Save the assessment to MySQL
async function saveRiskEvent(assessment, loginSuccess = false) {
  const [result] = await db.execute(
    `INSERT INTO login_risk_events
     (
       user_id,
       ip_address,
       device_fingerprint,
       failed_attempts,
       new_device,
       risk_score,
       risk_level,
       risk_reasons,
       login_success
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      assessment.userId,
      assessment.ipAddress,
      assessment.deviceFingerprint,
      assessment.failedAttempts,
      assessment.newDevice ? 1 : 0,
      assessment.riskScore,
      assessment.riskLevel,
      JSON.stringify(assessment.reasons),
      loginSuccess ? 1 : 0
    ]
  );

  return result.insertId;
}

module.exports = {
  assessLoginRisk,
  saveRiskEvent,
  getDeviceFingerprint,
  RISK_CONFIG
};