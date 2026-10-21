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
      loadAuthRequests('ALL'),
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

      // Count pending written authorizations
      try {
        const pendingAuthData = await apiFetch('api/authorization/admin/list?status=PENDING');
        if ($('totalAuthPending')) {
          $('totalAuthPending').textContent = (pendingAuthData.requests || []).length;
        }
      } catch (e) {
        if ($('totalAuthPending')) $('totalAuthPending').textContent = '0';
      }
    } catch (error) {
      console.error('Stats loading error:', error);
    }
  }

  // Current active authorization requests filter
  let currentAuthFilter = 'ALL';

  // Load Target Authorization Requests
  async function loadAuthRequests(filter = 'ALL') {
    currentAuthFilter = filter;
    const tbody = $('authRequestsTableBody');
    if (!tbody) return;

    // Update filter buttons styling
    const filterBtns = document.querySelectorAll('.auth-filter-btn');
    filterBtns.forEach(btn => {
      if (btn.dataset.filter === filter) {
        btn.style.background = '#2563eb';
        btn.style.color = '#ffffff';
      } else {
        btn.style.background = 'transparent';
        btn.style.color = '#64748b';
      }
    });

    try {
      tbody.textContent = '';
      const endpoint = filter === 'ALL' ? 'api/authorization/admin/list' : `api/authorization/admin/list?status=${filter}`;
      const data = await apiFetch(endpoint);
      const requests = data.requests || [];

      if ($('totalAuthPending') && filter === 'ALL') {
        const pendingCount = requests.filter(r => r.status === 'PENDING').length;
        $('totalAuthPending').textContent = pendingCount;
      }

      if (requests.length === 0) {
        showError('authRequestsTableBody', 7, `No authorization requests found (${filter.toLowerCase()}).`);
        return;
      }

      requests.forEach((req) => {
        const row = document.createElement('tr');

        // 1. Target & Environment
        const targetCell = document.createElement('td');
        targetCell.innerHTML = `
          <div style="font-weight:700; color:#0f172a; font-size:13px;">${escapeHtml(req.targetUrl)}</div>
          <span style="display:inline-block; margin-top:3px; padding:2px 6px; border-radius:4px; font-size:10px; font-weight:700; background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe;">
            ${escapeHtml(req.environment || 'PRODUCTION')}
          </span>
        `;
        row.appendChild(targetCell);

        // 2. Submitter User Details
        const userCell = document.createElement('td');
        userCell.innerHTML = `
          <div style="font-weight:600; color:#1e293b; font-size:13px;">${escapeHtml(req.submitterName || 'User #' + req.targetId)}</div>
          <div style="color:#64748b; font-size:11px;">${escapeHtml(req.submitterEmail || 'user@scanner.local')}</div>
        `;
        row.appendChild(userCell);

        // 3. Signatory & Role
        const sigCell = document.createElement('td');
        sigCell.innerHTML = `
          <div style="font-weight:600; color:#1e293b; font-size:13px;">${escapeHtml(req.ownerName || 'System Owner')}</div>
          <div style="color:#64748b; font-size:11px;">${escapeHtml(req.ownerTitle || 'Authorized Representative')}</div>
        `;
        row.appendChild(sigCell);

        // 4. Timestamp
        const timeCell = document.createElement('td');
        timeCell.style.fontSize = '12px';
        timeCell.style.color = '#64748b';
        timeCell.textContent = formatDate(req.submittedAt);
        row.appendChild(timeCell);

        // 5. Document Link
        const docCell = document.createElement('td');
        if (req.letterFileUrl) {
          docCell.innerHTML = `
            <a href="${escapeHtml(req.letterFileUrl)}" target="_blank" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:6px; font-size:12px; font-weight:600; background:#f8fafc; border:1px solid #cbd5e1; color:#0f172a; text-decoration:none;">
              📄 View Document
            </a>
          `;
        } else {
          docCell.textContent = '—';
        }
        row.appendChild(docCell);

        // 6. Status Badge
        const statusCell = document.createElement('td');
        let statusStyle = 'background:#fef3c7; color:#92400e; border:1px solid #fde68a;';
        if (req.status === 'APPROVED') statusStyle = 'background:#ecfdf5; color:#065f46; border:1px solid #a7f3d0;';
        else if (req.status === 'REJECTED') statusStyle = 'background:#fef2f2; color:#991b1b; border:1px solid #fecaca;';
        else if (req.status === 'NEEDS_CHANGES') statusStyle = 'background:#fff7ed; color:#c2410c; border:1px solid #fed7aa;';

        statusCell.innerHTML = `
          <span style="display:inline-block; padding:3px 8px; border-radius:9999px; font-size:11px; font-weight:700; letter-spacing:0.03em; ${statusStyle}">
            ${escapeHtml(req.status)}
          </span>
          ${req.reviewNotes ? `<div style="font-size:10px; color:#64748b; margin-top:4px; max-width:160px;">Note: ${escapeHtml(req.reviewNotes)}</div>` : ''}
        `;
        row.appendChild(statusCell);

        // 7. Actions Cell
        const actionsCell = document.createElement('td');
        actionsCell.style.textAlign = 'right';

        if (req.status === 'PENDING' || req.status === 'NEEDS_CHANGES') {
          actionsCell.innerHTML = `
            <div style="display:inline-flex; align-items:center; gap:6px;">
              <button type="button" class="dashboard-btn" style="padding:4px 9px; font-size:11px; height:auto; background:#059669; color:#fff;" onclick="window.handleAuthAction(${req.id}, 'APPROVED')">
                Approve
              </button>
              <button type="button" class="dashboard-btn" style="padding:4px 9px; font-size:11px; height:auto; background:#ea580c; color:#fff;" onclick="window.handleAuthAction(${req.id}, 'NEEDS_CHANGES')">
                Request Changes
              </button>
              <button type="button" class="dashboard-btn" style="padding:4px 9px; font-size:11px; height:auto; background:#dc2626; color:#fff;" onclick="window.handleAuthAction(${req.id}, 'REJECTED')">
                Reject
              </button>
            </div>
          `;
        } else {
          actionsCell.innerHTML = `
            <span style="font-size:11px; color:#64748b;">
              Reviewed by ${escapeHtml(req.reviewedBy || 'Admin')}
            </span>
          `;
        }
        row.appendChild(actionsCell);

        tbody.appendChild(row);
      });
    } catch (error) {
      console.error('Auth requests loading error:', error);
      showError('authRequestsTableBody', 7, 'Unable to load authorization requests.');
    }
  }

  // Expose review action handler globally
  window.handleAuthAction = async function (requestId, decision) {
    let reason = '';
    if (decision !== 'APPROVED') {
      reason = prompt(`Enter reason / mandatory feedback for ${decision}:`, decision === 'NEEDS_CHANGES' ? 'Please ensure stamp and signature are clear on Page 2.' : 'Corporate authorization could not be verified.');
      if (reason === null) return; // user cancelled
      if (!reason.trim()) {
        alert('A reason is mandatory when requesting changes or rejecting a request.');
        return;
      }
    }

    try {
      const adminName = (navAdminName && navAdminName.textContent) || 'Security Administrator';
      await apiFetch(`api/authorization/admin/${requestId}/review`, {
        method: 'PATCH',
        body: JSON.stringify({ decision, reason, adminName }),
      });
      alert(`Request #${requestId} has been marked as ${decision}.`);
      await Promise.all([
        loadAuthRequests(currentAuthFilter),
        loadStats(),
        loadAuditLogs(),
      ]);
    } catch (err) {
      alert(err.message || 'Action failed.');
    }
  };

  // Filter and refresh button listeners
  $('refreshAuthRequestsBtn')?.addEventListener('click', () => loadAuthRequests(currentAuthFilter));
  $('filterAuthAll')?.addEventListener('click', () => loadAuthRequests('ALL'));
  $('filterAuthPending')?.addEventListener('click', () => loadAuthRequests('PENDING'));
  $('filterAuthApproved')?.addEventListener('click', () => loadAuthRequests('APPROVED'));

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
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
