// =========================================================
// Sential AI - API Client & Session Manager (Node.js & SQLite)
// =========================================================

const API = {
    BASE_URL: '/api',

    getToken() {
        return localStorage.getItem('sentinel_token');
    },

    setToken(token) {
        localStorage.setItem('sentinel_token', token);
    },

    removeToken() {
        localStorage.removeItem('sentinel_token');
        localStorage.removeItem('sentinel_user');
    },

    getUser() {
        try {
            return JSON.parse(localStorage.getItem('sentinel_user'));
        } catch (e) {
            return null;
        }
    },

    setUser(user) {
        localStorage.setItem('sentinel_user', JSON.stringify(user));
    },

    async request(endpoint, options = {}) {
        const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
        const url = `${this.BASE_URL}/${cleanEndpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        const token = this.getToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            const res = await fetch(url, {
                ...options,
                headers
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                if (res.status === 401) {
                    this.removeToken();
                }
                throw new Error(data.error || data.message || `Request failed with status ${res.status}`);
            }

            return data;
        } catch (err) {
            console.error(`API Error [${endpoint}]:`, err);
            throw err;
        }
    },

    // Auth
    async login(email, password, adminOnly = false) {
        const endpoint = adminOnly ? 'admin/login' : 'auth/login';
        const res = await this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
        if (res.token) this.setToken(res.token);
        if (res.user) this.setUser(res.user);
        return res;
    },

    async register(name, email, password) {
        const res = await this.request('auth/signup', {
            method: 'POST',
            body: JSON.stringify({ name, email, password, confirm: password })
        });
        if (res.token) this.setToken(res.token);
        if (res.user) this.setUser(res.user);
        return res;
    },

    async me() {
        const res = await this.request('auth/me');
        if (res.user) this.setUser(res.user);
        return res.user;
    },

    async logout() {
        try {
            await this.request('auth/logout', { method: 'POST' });
        } catch (e) {}
        this.removeToken();
    },

    // Scans
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        const token = this.getToken();
        const headers = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`${this.BASE_URL}/scans/upload`, {
            method: 'POST',
            headers,
            body: formData
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || data.message || 'File upload failed');
        }
        return data;
    },

    async uploadFolder(formData) {
        const token = this.getToken();
        const headers = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        try {
            const res = await fetch(`${this.BASE_URL}/scans/upload-folder`, {
                method: 'POST',
                headers,
                body: formData
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(data.error || data.message || `Upload failed with status ${res.status}`);
            }
            return data;
        } catch (err) {
            if (err.name === 'TypeError' && (err.message || '').includes('Failed to fetch')) {
                const isAr = window.I18n && window.I18n.currentLang === 'ar';
                throw new Error(isAr 
                    ? 'تعذر الاتصال بالسيرفر أثناء رفع المجلد (الحجم كبير أو انقطع الاتصال). يرجى ضغط الفولدر كملف ZIP ورفعه.' 
                    : 'Server connection dropped during folder upload (folder is too large or connection timed out). Please upload as a ZIP file.');
            }
            throw err;
        }
    },

    // Target Authorization & Scope Gate
    async getDnsChallenge(targetUrl) {
        return await this.request('authorization/dns/challenge', {
            method: 'POST',
            body: JSON.stringify({ targetUrl })
        });
    },

    async verifyDns(targetUrl, targetId) {
        return await this.request('authorization/dns/verify', {
            method: 'POST',
            body: JSON.stringify({ targetUrl, targetId })
        });
    },

    async getFileChallenge(targetUrl) {
        return await this.request('authorization/file/challenge', {
            method: 'POST',
            body: JSON.stringify({ targetUrl })
        });
    },

    async verifyFile(targetUrl, targetId) {
        return await this.request('authorization/file/verify', {
            method: 'POST',
            body: JSON.stringify({ targetUrl, targetId })
        });
    },

    async submitWrittenLetter(formData) {
        const token = this.getToken();
        const user = this.getUser();
        if (user && user.id && !formData.has('userId')) {
            formData.append('userId', String(user.id));
        }
        const headers = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`${this.BASE_URL}/authorization/letter/submit`, {
            method: 'POST',
            headers,
            body: formData
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || data.message || 'Failed to submit authorization letter');
        }
        return data;
    },

    async checkAuthorizationGate(targetUrl, environment = 'production') {
        return await this.request('authorization/check-gate', {
            method: 'POST',
            body: JSON.stringify({ targetUrl, environment })
        });
    },

    async getAdminAuthorizations(status = 'ALL') {
        return await this.request(`authorization/admin/list?status=${encodeURIComponent(status)}`);
    },

    async reviewAuthorization(id, decision, reason = '', adminName = 'Security Administrator') {
        return await this.request(`authorization/admin/${id}/review`, {
            method: 'PATCH',
            body: JSON.stringify({ decision, reason, adminName })
        });
    },

    async validateUrl(url, assessmentName = '', environment = 'production') {
        return await this.request('scans/validate-url', {
            method: 'POST',
            body: JSON.stringify({ url, assessmentName, environment })
        });
    },

    async discoverTarget(url, environment = 'production', options = {}) {
        return await this.request('scans/discover', {
            method: 'POST',
            body: JSON.stringify({ url, environment, options })
        });
    },

    async viewResourceContent(url) {
        return await this.request('scans/view-resource', {
            method: 'POST',
            body: JSON.stringify({ url })
        });
    },

    async createScan(data) {
        return await this.request('scans/create', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    async getScanProgress(scanId) {
        return await this.request(`scans/progress?scan_id=${scanId || ''}`);
    },

    async getScanTasks(scanId) {
        return await this.request(`scans/tasks?scanId=${scanId || ''}`);
    },

    async getScanFindings(scanId) {
        return await this.request(`scans/${scanId}/findings`);
    },

    async rescanTarget(targetId) {
        return await this.request(`scans/rescan/${targetId}`, { method: 'POST' });
    },

    async getScanReport(scanId) {
        return await this.request(`reports/scan/${scanId}`);
    },

    async exportScanReport(scanId) {
        return await this.request(`reports/export/${scanId}`, { method: 'POST' });
    },

    async getScanHistory() {
        return await this.request('scans/history');
    },

    async deleteScan(scanId) {
        return await this.request(`scans/${scanId}`, { method: 'DELETE' });
    },

    async cancelScan(scanId) {
        return await this.request(`scans/${scanId}/cancel`, { method: 'POST' });
    },

    async clearAllScans() {
        return await this.request('scans/history/all', { method: 'DELETE' });
    },

    // Findings
    async getFindings(params = {}) {
        const qs = new URLSearchParams(params).toString();
        return await this.request(`findings/list?${qs}`);
    },

    async getFindingDetail(id) {
        return await this.request(`findings/detail?id=${id}`);
    },

    async updateFindingStatus(findingId, status) {
        return await this.request('findings/update-status', {
            method: 'POST',
            body: JSON.stringify({ finding_id: findingId, status })
        });
    },

    // Reports
    async getReport() {
        return await this.request('reports/assessment');
    },

    // Admin
    async getAdminStats() {
        return await this.request('admin/stats');
    },

    async getAdminUsers(params = {}) {
        const qs = new URLSearchParams(params).toString();
        return await this.request(`admin/users?${qs}`);
    },

    async createAdmin(data) {
        return await this.request('admin/create-admin', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    async toggleUserStatus(userId, isActive) {
        return await this.request('admin/toggle-status', {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, is_active: isActive })
        });
    }
};

window.API = API;
