document.addEventListener('DOMContentLoaded', async () => {
  const token = localStorage.getItem('adminToken');

  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  const $ = (id) => document.getElementById(id);
  const navAdminName = $('navAdminName');
  const logoutBtn = $('logoutBtn');

  // Smart URL resolver for local development subfolder or root domain
  function resolveApi(endpoint) {
    if (endpoint.startsWith('http')) return endpoint;
    const clean = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
    const match = window.location.pathname.match(/^(.*\/Sential(?:%20|\s)AI)/i);
    if (match) {
      return match[1] + '/' + clean;
    }
    return '/' + clean;
  }

  async function apiFetch(url, options = {}) {
    const fullUrl = resolveApi(url);
    const response = await fetch(fullUrl, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status === 401) {
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminUser');
      window.location.href = 'login.html';
      throw new Error('Session expired. Please log in again.');
    }

    const data = await response.json().catch(() => ({}));

    if (!response.ok || data.success === false) {
      throw new Error(data.error || data.message || 'Request failed.');
    }

    return data;
  }

  function showError(tbodyId, columns, message) {
    const tbody = $(tbodyId);
    if (!tbody) return;
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = columns;
    cell.className = 'dashboard-empty';
    cell.textContent = message;
    row.appendChild(cell);
    tbody.replaceChildren(row);
  }

  function addCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = value ?? '—';
    row.appendChild(cell);
    return cell;
  }

  function formatDate(value) {
    if (!value) return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
  }

  // Verify the current administrator profile
  try {
    const data = await apiFetch('api/admin/me');
    if (navAdminName && data.user) {
      navAdminName.textContent = data.user.name;
    }

    await Promise.all([
      loadStats(),
      loadAuditLogs(),
    ]);
  } catch (error) {
    console.error('Dashboard initialization error:', error);
  }

  // Load dashboard statistics
  async function loadStats() {
    try {
      const data = await apiFetch('api/admin/stats');
      const stats = data.stats || {};

      if ($('totalAdmin')) {
        $('totalAdmin').textContent = stats.totalAdmin ?? stats.total_admins ?? 0;
      }
      if ($('totalTargets')) {
        $('totalTargets').textContent = stats.totalTargets ?? stats.total_targets ?? 0;
      }
      if ($('totalScans')) {
        $('totalScans').textContent = stats.totalScans ?? stats.total_scans ?? 0;
      }

      // Load users to count total admins
      const usersData = await apiFetch('api/admin/users');
      const admins = (usersData.users || []).filter(
        (user) => String(user.role).toUpperCase() === 'ADMIN'
      );

      if ($('totalAdmins')) {
        $('totalAdmins').textContent = admins.length;
      }
    } catch (error) {
      console.error('Stats loading error:', error);
    }
  }

  // Load recent audit activity
  async function loadAuditLogs() {
    const tbody = $('auditLogsTableBody');
    if (!tbody) return;

    try {
      tbody.textContent = '';
      const data = await apiFetch('api/admin/audit-logs');
      const logs = data.logs || [];

      if (logs.length === 0) {
        showError('auditLogsTableBody', 4, 'No audit logs found.');
        return;
      }

      logs.forEach((log) => {
        const row = document.createElement('tr');
        addCell(row, log.action);
        addCell(row, log.user?.name || log.user?.email || 'System');
        addCell(row, formatDate(log.createdAt || log.created_at));
        addCell(row, log.details || '—');
        tbody.appendChild(row);
      });
    } catch (error) {
      console.error('Audit logs loading error:', error);
      showError('auditLogsTableBody', 4, 'Unable to load audit logs.');
    }
  }

  // Refresh button
  $('refreshLogsBtn')?.addEventListener('click', loadAuditLogs);

  // Sign out
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      logoutBtn.disabled = true;
      try {
        await apiFetch('api/admin/logout', { method: 'POST' });
      } catch (error) {
        console.error('Logout error:', error);
      } finally {
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminUser');
        window.location.href = 'login.html';
      }
    });
  }
});
