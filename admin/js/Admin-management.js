document.addEventListener('DOMContentLoaded', async function () {
    const token = localStorage.getItem('adminToken');

    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    const tbody = document.getElementById('usersTableBody');
    const refreshBtn = document.getElementById('refreshUsersBtn');
    const message = document.getElementById('usersMessage');

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
                Authorization: 'Bearer ' + token
            }
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

    function showMessage(text, isError) {
        if (!message) return;
        message.textContent = text;
        message.style.color = isError ? '#dc2626' : '#16a34a';
        message.style.fontWeight = '600';
        message.style.marginTop = '12px';
    }

    function addCell(row, value) {
        const cell = document.createElement('td');
        cell.textContent = value == null ? '—' : String(value);
        row.appendChild(cell);
        return cell;
    }

    function formatDate(value) {
        if (!value) return 'Never';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return '—';
        }
        return date.toLocaleString();
    }

    async function changeUserStatus(user, button) {
        const isCurrentlyActive = Boolean(user.isActive !== undefined ? user.isActive : user.is_active);
        const nextStatus = !isCurrentlyActive;
        const action = nextStatus ? 'activate' : 'deactivate';

        const confirmed = window.confirm(
            'Are you sure you want to ' + action + ' ' +
            user.name + ' (' + user.email + ')?'
        );

        if (!confirmed) return;

        button.disabled = true;
        button.textContent = 'Updating...';

        try {
            // Send PATCH to user status endpoint
            const result = await apiFetch('api/admin/users/' + encodeURIComponent(user.id) + '/status', {
                method: 'PATCH',
                body: JSON.stringify({
                    isActive: nextStatus,
                    is_active: nextStatus
                })
            });

            showMessage(
                result.message || 'Administrator status updated successfully.',
                false
            );

            await loadUsers();
        } catch (error) {
            console.error('Update user status error:', error);
            showMessage(
                error.message || 'Unable to update administrator status.',
                true
            );
            button.disabled = false;
            button.textContent = isCurrentlyActive ? 'Deactivate' : 'Activate';
        }
    }

    async function loadUsers() {
        if (!tbody) {
            console.error('usersTableBody was not found in the HTML.');
            return;
        }

        tbody.replaceChildren();

        const loadingRow = document.createElement('tr');
        const loadingCell = document.createElement('td');
        loadingCell.colSpan = 6;
        loadingCell.className = 'dashboard-empty';
        loadingCell.textContent = 'Loading administrators...';
        loadingRow.appendChild(loadingCell);
        tbody.appendChild(loadingRow);

        try {
            const data = await apiFetch('api/admin/users');
            const users = (data.users || []).filter(
                user => String(user.role).toUpperCase() === 'ADMIN'
            );

            tbody.replaceChildren();

            if (users.length === 0) {
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.className = 'dashboard-empty';
                cell.textContent = 'No administrator accounts found.';
                row.appendChild(cell);
                tbody.appendChild(row);
                return;
            }

            users.forEach(function (user) {
                const isUserActive = Boolean(user.isActive !== undefined ? user.isActive : user.is_active);
                const row = document.createElement('tr');

                addCell(row, user.name);
                addCell(row, user.email);

                // Role badge
                const roleCell = document.createElement('td');
                const roleBadge = document.createElement('span');
                roleBadge.className = 'tag-admin';
                roleBadge.textContent = 'ADMIN';
                roleCell.appendChild(roleBadge);
                row.appendChild(roleCell);

                // Status pill
                const statusCell = document.createElement('td');
                const statusBadge = document.createElement('span');
                statusBadge.className = isUserActive ? 'pill-active' : 'tag-user';
                statusBadge.textContent = isUserActive ? '● Active' : 'Inactive';
                statusCell.appendChild(statusBadge);
                row.appendChild(statusCell);

                addCell(row, formatDate(user.lastLoginAt || user.last_login_at));

                // Actions cell
                const actionCell = document.createElement('td');
                const actionButton = document.createElement('button');
                actionButton.type = 'button';
                actionButton.className = 'dashboard-btn' + (isUserActive ? '' : ' primary');
                actionButton.style.padding = '6px 12px';
                actionButton.style.fontSize = '12px';
                actionButton.textContent = isUserActive ? 'Deactivate' : 'Activate';

                actionButton.addEventListener('click', function () {
                    changeUserStatus(user, actionButton);
                });

                actionCell.appendChild(actionButton);
                row.appendChild(actionCell);

                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Failed to load administrators:', error);
            tbody.replaceChildren();
            const errRow = document.createElement('tr');
            const errCell = document.createElement('td');
            errCell.colSpan = 6;
            errCell.className = 'dashboard-empty';
            errCell.textContent = 'Failed to load administrator accounts.';
            errRow.appendChild(errCell);
            tbody.appendChild(errRow);
        }
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadUsers);
    }

    loadUsers();
});
