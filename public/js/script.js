
document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const form = loginForm || registerForm;

  if (!form) return;

  const get = id => document.getElementById(id);
  const message = get("message");
  const submitBtn = get("submitBtn");

  function refreshCaptcha() {
    get("captchaImage").src = "/captcha?t=" + Date.now();
    get("captcha").value = "";
  }

  get("refreshCaptcha").addEventListener("click", refreshCaptcha);

  get("togglePassword").addEventListener("click", () => {
    const input = get("password");
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    get("togglePassword").textContent = visible ? "Hide" : "Show";
  });

  form.addEventListener("submit", async event => {
    event.preventDefault();

    message.textContent = "";
    message.className = "form-message";

    const isRegistration = Boolean(registerForm);

    const payload = {
      universityId: get("universityId").value.trim(),
      password: get("password").value,
      captcha: get("captcha").value.trim()
    };

    if (isRegistration) {
      payload.fullName = get("fullName").value.trim();
      payload.email = get("email").value.trim();
      payload.confirmPassword = get("confirmPassword").value;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = isRegistration
      ? "Creating Account..."
      : "Verifying Account...";

    try {
      const response = await fetch(
        isRegistration ? "/register" : "/login",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(payload)
        }
      );

      const result = await response.json();

      message.textContent = result.message || "Request completed.";
      message.className = result.success
        ? "form-message success"
        : "form-message error";

      if (result.success) {
        if (isRegistration) {
          form.reset();
          setTimeout(() => {
            window.location.href = result.redirect || "/";
          }, 1000);
        } else {
          window.location.href =
            result.redirect || "/student/dashboard";
        }
      } else {
        refreshCaptcha();
      }

    } catch (error) {
      message.textContent =
        "Unable to connect to the server. Please try again.";
      message.className = "form-message error";
      refreshCaptcha();

    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = isRegistration
        ? "Create Account"
        : "Secure Login";
    }
  });
});
