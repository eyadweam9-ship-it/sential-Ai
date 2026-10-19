document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('adminLoginForm');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const togglePasswordBtn = document.getElementById('togglePasswordBtn');
  const eyeIcon = document.getElementById('eyeIcon');
  const submitBtn = document.getElementById('submitBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  const alertBox = document.getElementById('alertBox');
  const alertText = document.getElementById('alertText');

  // Helper to resolve API endpoint in any environment (root or subfolder)
  function resolveApi(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const clean = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
    const match = window.location.pathname.match(/^(.*\/Sential(?:%20|\s)AI)/i);
    if (match) {
      return match[1] + '/' + clean;
    }
    return '/' + clean;
  }

  // Toggle password visibility
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      if (eyeIcon) {
        eyeIcon.innerHTML = isPassword
          ? `<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>`
          : `<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>`;
      }
    });
  }

  // Show Alert Box
  function showAlert(message, type = 'danger') {
    if (!alertBox || !alertText) return;
    alertBox.className = `alert-box alert-${type}`;
    alertBox.style.display = 'flex';
    alertText.innerHTML = message;
  }

  function hideAlert() {
    if (!alertBox) return;
    alertBox.style.display = 'none';
  }

  // Handle Form Submission
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideAlert();

      const email = emailInput.value.trim();
      const password = passwordInput.value.trim();

      if (!email || !password) {
        showAlert('Please enter both email and password.', 'danger');
        return;
      }

      // Set Loading State
      if (submitBtn) submitBtn.disabled = true;
      if (btnText) btnText.textContent = 'Verifying administrator privileges...';
      if (btnSpinner) btnSpinner.style.display = 'inline-block';

      try {
        const url = resolveApi('api/admin/login');
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email, password }),
        });

        const data = await response.json().catch(() => ({}));

        if (response.ok && data.success) {
          // Successful login with role = ADMIN
          showAlert(`<strong>Authentication successful!</strong> Welcome Admin ${data.user.name}. Redirecting to dashboard...`, 'success');

          // Store JWT token and admin info in localStorage
          localStorage.setItem('adminToken', data.token);
          localStorage.setItem('adminUser', JSON.stringify(data.user));

          setTimeout(() => {
            window.location.href = 'dashboard.html';
          }, 600);
        } else {
          // Role check failed (403) or Invalid credentials (401)
          const errorMsg = data.error || data.message || 'Authentication failed. Please verify your credentials.';
          showAlert(`⛔ ${errorMsg}`, 'danger');
        }
      } catch (err) {
        console.error('Login error:', err);
        showAlert('⚠️ Server connection error. Please make sure the backend server is running (npm run dev).', 'danger');
      } finally {
        if (submitBtn) submitBtn.disabled = false;
        if (btnText) btnText.textContent = 'Log in to Admin Portal';
        if (btnSpinner) btnSpinner.style.display = 'none';
      }
    });
  }
});
