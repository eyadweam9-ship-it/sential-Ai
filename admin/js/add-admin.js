document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('addAdminForm');
  const message = document.getElementById('addAdminMessage');

  if (!form || !message) {
    console.error('Add Admin form was not found.');
    return;
  }

  function resolveApi(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const clean = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
    const match = window.location.pathname.match(/^(.*\/Sential(?:%20|\s)AI)/i);
    if (match) {
      return match[1] + '/' + clean;
    }
    return '/' + clean;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const name = document.getElementById('adminFullName').value.trim();
    const email = document.getElementById('adminEmail').value.trim();
    const password = document.getElementById('adminPassword').value;
    const confirmPassword = document.getElementById('adminConfirmPassword').value;

    message.textContent = '';
    message.style.color = '';
    message.style.fontWeight = '600';
    message.style.marginTop = '12px';

    if (password !== confirmPassword) {
      message.textContent = '❌ Passwords do not match.';
      message.style.color = '#dc2626';
      return;
    }

    if (password.length < 8) {
      message.textContent = '❌ Password must be at least 8 characters.';
      message.style.color = '#dc2626';
      return;
    }

    const token = localStorage.getItem('adminToken');

    if (!token) {
      message.textContent = 'Session expired. Please log in again as an administrator.';
      message.style.color = '#dc2626';
      setTimeout(() => {
        window.location.href = 'login.html';
      }, 1000);
      return;
    }

    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = 'Creating administrator...';
    }

    try {
      const url = resolveApi('api/admin/create-admin');
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({
          name: name,
          email: email,
          password: password
        })
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok && data.success) {
        message.textContent = '✅ ' + (data.message || 'Administrator account created successfully!');
        message.style.color = '#16a34a';
        form.reset();
      } else {
        message.textContent = '❌ ' + (data.error || data.message || 'Failed to create administrator account.');
        message.style.color = '#dc2626';
      }
    } catch (error) {
      console.error('Create admin error:', error);
      message.textContent = '⚠️ Network or server error. Please verify backend is running.';
      message.style.color = '#dc2626';
    } finally {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = 'Create Admin';
      }
    }
  });
});
