
const express = require("express");
const router = express.Router();
const db = require("../config/database");

// Student authentication middleware
router.use((req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/");
  }

  if (req.session.user.role !== "student") {
    return res.status(403).send("Access Denied");
  }

  res.setHeader("Cache-Control", "no-store");
  next();
});

// Helper for student pages
function renderPage(req, res, title, columns, rows) {
  res.render("student-page", {
    title,
    user: req.session.user,
    columns,
    rows
  });
}

function serverError(res, error) {
  console.error("Student route error:", error);
  res.status(500).send("Unable to load page.");
}

// DASHBOARD - real logged-in user
router.get("/dashboard", async (req, res) => {
  try {
    const [users] = await db.execute(
      `SELECT full_name, university_id, account_status
       FROM users
       WHERE id = ? AND role = 'student'`,
      [req.session.user.id]
    );

    if (
      !users.length ||
      users[0].account_status !== "active"
    ) {
      return res.status(403).send("Account unavailable.");
    }

    const student = users[0];

    const [attendance] = await db.execute(
      `SELECT
         COALESCE(SUM(attended_classes), 0) AS attended,
         COALESCE(SUM(total_classes), 0) AS total
       FROM student_attendance
       WHERE student_id = ?`,
      [req.session.user.id]
    );

    const [courses] = await db.execute(
      `SELECT COUNT(*) AS total
       FROM course_enrollments
       WHERE student_id = ?`,
      [req.session.user.id]
    );

    const [assignments] = await db.execute(
      `SELECT COUNT(*) AS total
       FROM assignments a
       JOIN course_enrollments e
         ON a.course_id = e.course_id
       WHERE e.student_id = ?`,
      [req.session.user.id]
    );

    const [results] = await db.execute(
      `SELECT COUNT(*) AS total
       FROM student_results
       WHERE student_id = ?`,
      [req.session.user.id]
    );

    const attended = Number(attendance[0].attended);
    const total = Number(attendance[0].total);

    const attendancePercentage = total > 0
      ? ((attended / total) * 100).toFixed(1) + "%"
      : "N/A";

    res.render("student", {
      user: {
        ...req.session.user,
        fullName: student.full_name,
        universityId: student.university_id
      },
      stats: {
        attendance: attendancePercentage,
        courses: courses[0].total,
        assignments: assignments[0].total,
        results: results[0].total
      }
    });

  } catch (error) {
    serverError(res, error);
  }
});

// PROFILE
router.get("/profile", async (req, res) => {
  try {
    const [data] = await db.execute(
      `SELECT full_name, university_id, email, role
       FROM users WHERE id = ?`,
      [req.session.user.id]
    );

    if (!data.length) {
      return res.status(404).send("Student not found.");
    }

    const student = data[0];

    renderPage(req, res, "My Profile",
      ["Field", "Information"],
      [
        ["Full Name", student.full_name],
        ["University ID", student.university_id],
        ["Email", student.email],
        ["Role", student.role]
      ]
    );
  } catch (error) {
    serverError(res, error);
  }
});

// ATTENDANCE
router.get("/attendance", async (req, res) => {
  try {
    const [data] = await db.execute(
      `SELECT c.course_code, c.course_name,
              a.attended_classes, a.total_classes,
              ROUND(
                a.attended_classes * 100.0 /
                NULLIF(a.total_classes, 0), 1
              ) AS percentage
       FROM student_attendance a
       JOIN courses c ON c.id = a.course_id
       JOIN course_enrollments e
         ON e.course_id = a.course_id
         AND e.student_id = a.student_id
       WHERE a.student_id = ?
       ORDER BY c.course_name`,
      [req.session.user.id]
    );

    renderPage(req, res, "My Attendance",
      ["Code", "Subject", "Present", "Total", "Attendance"],
      data.map(row => [
        row.course_code,
        row.course_name,
        row.attended_classes,
        row.total_classes,
        row.percentage === null
          ? "N/A"
          : row.percentage + "%"
      ])
    );
  } catch (error) {
    serverError(res, error);
  }
});

// COURSES
router.get("/courses", async (req, res) => {
  try {
    const [data] = await db.execute(
      `SELECT c.course_code, c.course_name
       FROM course_enrollments e
       JOIN courses c ON c.id = e.course_id
       WHERE e.student_id = ?
       ORDER BY c.course_name`,
      [req.session.user.id]
    );

    renderPage(req, res, "My Courses",
      ["Course Code", "Course Name"],
      data.map(row => [
        row.course_code,
        row.course_name
      ])
    );
  } catch (error) {
    serverError(res, error);
  }
});

// ASSIGNMENTS
router.get("/assignments", async (req, res) => {
  try {
    const [data] = await db.execute(
      `SELECT a.title, c.course_name,
              DATE_FORMAT(
                a.due_date, '%d-%m-%Y'
              ) AS due_date
       FROM assignments a
       JOIN courses c ON c.id = a.course_id
       JOIN course_enrollments e
         ON e.course_id = a.course_id
       WHERE e.student_id = ?
       ORDER BY a.due_date`,
      [req.session.user.id]
    );

    renderPage(req, res, "My Assignments",
      ["Assignment", "Subject", "Due Date"],
      data.map(row => [
        row.title,
        row.course_name,
        row.due_date
      ])
    );
  } catch (error) {
    serverError(res, error);
  }
});

// RESULTS
router.get("/results", async (req, res) => {
  try {
    const [data] = await db.execute(
      `SELECT c.course_code, c.course_name,
              r.marks_obtained, r.max_marks
       FROM student_results r
       JOIN courses c ON c.id = r.course_id
       JOIN course_enrollments e
         ON e.course_id = r.course_id
         AND e.student_id = r.student_id
       WHERE r.student_id = ?`,
      [req.session.user.id]
    );

    renderPage(req, res, "My Results",
      ["Code", "Subject", "Marks", "Maximum"],
      data.map(row => [
        row.course_code,
        row.course_name,
        row.marks_obtained,
        row.max_marks
      ])
    );
  } catch (error) {
    serverError(res, error);
  }
});

// SECURITY CENTER
router.get("/security", async (req, res) => {
  try {
    const [events] = await db.execute(
      `SELECT event_type, ip_address,
              DATE_FORMAT(
                created_at, '%d-%m-%Y %H:%i'
              ) AS event_time
       FROM security_events
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 10`,
      [req.session.user.id]
    );

    renderPage(req, res, "Security Center",
      ["Feature / Event", "Details", "Status / Time"],
      [
        ["Authentication", "Session active", "Verified"],
        ["Role", req.session.user.role, "Student"],
        ["CAPTCHA", "Checked at login", "Verified"],
        ["OTP", "Not implemented", "-"],
        ["Adaptive Risk", "Not implemented", "-"],
        ...events.map(event => [
          event.event_type,
          event.ip_address || "Unknown",
          event.event_time
        ])
      ]
    );
  } catch (error) {
    serverError(res, error);
  }
});

module.exports = router;
