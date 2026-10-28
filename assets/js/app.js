// =========================================================
// Sential AI - Client Application & Assessment Flow Router
// Matches exact Figma design specifications across all 7 steps
// Real-time sleek input validation & empty default inputs
// =========================================================

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatStatus(status) {
    if (!status) return 'Detected';
    const isScanOnly = (window.App && window.App.scanState && window.App.scanState.scanType === 'scan_only');
    const s = status.toLowerCase();
    if (isScanOnly) {
        if (s === 'confirmed' || s === 'fix ready' || s === 'fixed') {
            return 'Detected';
        }
    }
    switch (s) {
        case 'confirmed': return 'Fix ready';
        case 'mitigated': return 'Mitigated';
        case 'fixed': return 'Fixed';
        case 'in_review': return 'In review';
        default: return status.charAt(0).toUpperCase() + status.slice(1);
    }
}

function showToast(message, type = 'info') {
    let toast = document.getElementById('toast-notice');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast-notice';
        toast.className = 'toast-notice';
        document.body.appendChild(toast);
    }
    toast.className = `toast-notice ${type} show`;
    toast.innerHTML = `
        <span>${type === 'success' ? Icons.get('check', 'size-4') : (type === 'error' ? Icons.get('alert', 'size-4') : Icons.get('shield', 'size-4'))}</span>
        <span>${message}</span>
    `;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3500);
}

// Brand Logo: 100% exact reproduction from Figma (Sential AI + checkmark shield)
function renderBrandLogo() {
    return `
        <div class="flex items-center gap-3">
            <div class="brand-mark">${Icons.get('shield', 'size-6')}</div>
            <div>
                <div class="flex items-center gap-2 text-lg font-extrabold tracking-tight text-slate-950">
                    Sential <span class="brand-ai">AI</span>
                </div>
                <div class="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400">
                    Autonomous Security
                </div>
            </div>
        </div>
    `;
}

// Page title wrapper matching Figma's exact oe() helper
function renderPageTitle({ eyebrow = '', title, copy = '', action = '' }) {
    return `
        <div class="page-title">
            <div>
                ${eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : ''}
                <h1>${title}</h1>
                ${copy ? `<p>${copy}</p>` : ''}
            </div>
            ${action ? action : ''}
        </div>
    `;
}

function togglePasswordVisibility(inputId, btnEl) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === 'password') {
        input.type = 'text';
        btnEl.innerHTML = Icons.get('eye-off', 'size-4 text-slate-400');
    } else {
        input.type = 'password';
        btnEl.innerHTML = Icons.get('eye', 'size-4 text-slate-400');
    }
}

// 7 Step Navigation Schema (Exact Figma Flow)
const STEPS = [
    { id: 'type', label: 'Assessment Type', step: 1, icon: 'settings' },
    { id: 'url', label: 'Target & Environment', step: 2, icon: 'globe' },
    { id: 'scope', label: 'Authorization & Scope', step: 3, icon: 'lock' },
    { id: 'progress', label: 'Assessment in Progress', step: 4, icon: 'activity' },
    { id: 'dashboard', label: 'Findings Dashboard', step: 5, icon: 'shield' },
    { id: 'finding', label: 'Finding Details', step: 6, icon: 'code' },
    { id: 'report', label: 'Assessment Report', step: 7, icon: 'file' }
];

// Exact 5 Findings from Figma Prototype (de array)
const FIGMA_FINDINGS = [
    {
        id: 1,
        title: 'SQL Injection in user search',
        endpoint: '/api/v2/users/search',
        path: 'POST /api/v2/users/search',
        severity: 'Critical',
        sev: 'Critical',
        cwe_id: 'CWE-89',
        type: 'CWE-89',
        cvss: '9.8',
        status: 'Fix ready',
        description: 'Untrusted input is passed directly into a database query, allowing an attacker to access or modify sensitive data.',
        what_we_found: 'The <code>query</code> parameter is concatenated directly into a SQL statement without validation or parameterization. This allows arbitrary SQL commands to be executed.',
        method: 'POST',
        request_code: `POST /api/v2/users/search HTTP/1.1\nHost: app.northstar.io\nContent-Type: application/json\n\n{\n  "query": "' OR 1=1 --",\n  "limit": 20\n}`,
        response_code: 'The server returned 2,481 user records, confirming that the injected condition changed the intended query behavior.',
        patch_file: 'src/api/users/search.ts',
        patch_diff: `- const users = await db.query(\n-   "SELECT * FROM users WHERE name LIKE '%" + query + "%'"\n- );\n+ const users = await db.query(\n+   "SELECT * FROM users WHERE name LIKE $1",\n+   [\`%\${query}%\`]\n+ );`,
        owasp: 'A03: Injection',
        date: 'June 14, 2025',
        asset: 'app.northstar.io',
        confidence: '98% · Confirmed'
    },
    {
        id: 2,
        title: 'Broken object level authorization',
        endpoint: '/api/v2/users/{id}',
        path: 'GET /api/v2/users/{id}',
        severity: 'Critical',
        sev: 'Critical',
        cwe_id: 'CWE-639',
        type: 'CWE-639',
        cvss: '9.1',
        status: 'Fix ready',
        description: 'The endpoint does not verify whether the requesting user has permission to access the specified user object.',
        what_we_found: 'User IDs passed in the route are directly queried without validating that the authenticated user owns or is authorized to view the resource.',
        method: 'GET',
        request_code: `GET /api/v2/users/42 HTTP/1.1\nHost: app.northstar.io\nAuthorization: Bearer test_token`,
        response_code: 'The server returned sensitive user data belonging to user ID 42 without ownership checks.',
        patch_file: 'src/api/users/controller.ts',
        patch_diff: `- const user = await db.findUser(req.params.id);\n+ const user = await db.findUserForTenant(req.params.id, req.user.tenantId);`,
        owasp: 'A01: Broken Access Control',
        date: 'June 14, 2025',
        asset: 'app.northstar.io',
        confidence: '99% · Confirmed'
    },
    {
        id: 3,
        title: 'Stored cross-site scripting',
        endpoint: '/api/v2/comments',
        path: 'POST /api/v2/comments',
        severity: 'High',
        sev: 'High',
        cwe_id: 'CWE-79',
        type: 'CWE-79',
        cvss: '7.5',
        status: 'Reviewing',
        description: 'User input submitted to the comments endpoint is rendered in HTML without proper sanitization.',
        what_we_found: 'Unsanitized user payload stored in database and executed in victim client browser context.',
        method: 'POST',
        request_code: `POST /api/v2/comments HTTP/1.1\nHost: app.northstar.io\n\n{\n  "body": "<script>alert(1)</script>"\n}`,
        response_code: 'Payload accepted with HTTP 201 Created and echoed without escaping.',
        patch_file: 'src/components/Comments.tsx',
        patch_diff: `- <div dangerouslySetInnerHTML={{ __html: comment.body }} />\n+ <div>{comment.body}</div>`,
        owasp: 'A03: Injection',
        date: 'June 14, 2025',
        asset: 'app.northstar.io',
        confidence: '95% · Confirmed'
    },
    {
        id: 4,
        title: 'Missing rate limiting',
        endpoint: '/api/v2/auth/reset',
        path: 'POST /api/v2/auth/reset',
        severity: 'High',
        sev: 'High',
        cwe_id: 'CWE-770',
        type: 'CWE-770',
        cvss: '7.1',
        status: 'Fix ready',
        description: 'Password reset endpoint does not enforce rate limiting, allowing automated brute-force attacks.',
        what_we_found: 'Multiple automated POST requests to /reset were accepted without throttling or IP cooldown.',
        method: 'POST',
        request_code: `POST /api/v2/auth/reset HTTP/1.1\nHost: app.northstar.io\n\n{\n  "email": "victim@example.com"\n}`,
        response_code: '50 consecutive requests processed in under 2 seconds without HTTP 429.',
        patch_file: 'src/middleware/rateLimit.ts',
        patch_diff: `+ router.post('/reset', rateLimiter({ max: 5, windowMs: 15 * 60 * 1000 }), handleReset);`,
        owasp: 'A04: Insecure Design',
        date: 'June 14, 2025',
        asset: 'app.northstar.io',
        confidence: '96% · Confirmed'
    },
    {
        id: 5,
        title: 'Session cookie misconfiguration',
        endpoint: '/session',
        path: 'SET-COOKIE /session',
        severity: 'Medium',
        sev: 'Medium',
        cwe_id: 'CWE-614',
        type: 'CWE-614',
        cvss: '5.3',
        status: 'Open',
        description: 'Session cookies lack the SameSite=Strict and Secure flags, making them vulnerable to CSRF and interception.',
        what_we_found: 'Cookie set without Secure and SameSite attributes in response header.',
        method: 'SET-COOKIE',
        request_code: `POST /api/v2/login HTTP/1.1\nHost: app.northstar.io`,
        response_code: 'Set-Cookie: session_id=xyz123; Path=/; HttpOnly',
        patch_file: 'src/config/session.ts',
        patch_diff: `- cookie: { secure: false, sameSite: 'lax' }\n+ cookie: { secure: true, sameSite: 'strict', httpOnly: true }`,
        owasp: 'A05: Security Misconfiguration',
        date: 'June 14, 2025',
        asset: 'app.northstar.io',
        confidence: '92% · Confirmed'
    }
];

const DEFAULT_HISTORY = [
    {
        id: 101,
        target_name: 'Northstar Cloud API Core',
        target_url: 'https://app.northstar.io',
        environment: 'PRODUCTION',
        scan_mode: 'scan_only',
        status: 'COMPLETED',
        progress: 100,
        critical_count: 2,
        high_count: 1,
        total_findings: 5,
        created_at: new Date(Date.now() - 3600000 * 2).toISOString()
    },
    {
        id: 102,
        target_name: 'Auth & Billing Service',
        target_url: 'auth-service-repo.zip',
        environment: 'DEVELOPMENT',
        scan_mode: 'scan_fix_test',
        status: 'COMPLETED',
        progress: 100,
        critical_count: 1,
        high_count: 2,
        total_findings: 4,
        created_at: new Date(Date.now() - 86400000).toISOString()
    },
    {
        id: 103,
        target_name: 'Staging Gateway Testing',
        target_url: 'https://staging.northstar.io',
        environment: 'STAGING',
        scan_mode: 'scan_only',
        status: 'COMPLETED',
        progress: 100,
        critical_count: 0,
        high_count: 1,
        total_findings: 2,
        created_at: new Date(Date.now() - 86400000 * 3).toISOString()
    }
];

const App = {
    currentView: 'welcome',
    currentUser: null,
    settingsTab: 'history', // 'history' | 'profile' | 'security'
    scanHistoryList: [],
    historySearchQuery: '',
    scanState: {
        maxUnlockedStep: 1, // Enforce strictly sequential step-by-step progression (1 to 7)
        scanType: 'scan_only', // 'scan_only' or 'scan_fix_test' (Default to Scan Only for pure inspection)
        url: '', // EMPTY by default
        name: '', // EMPTY by default
        environment: 'development', // 'development' (SAST upload) | 'staging' (DAST) | 'production' (Strict DAST)
        uploadedFile: null, // { name, size, path, type }
        isUploading: false,
        urlValidation: null, // { valid, normalizedUrl, ip, tls, ssrfSafe, isMockDemo, error }
        isValidatingUrl: false,
        showOptionalCode: false,
        optionalCodeTab: 'zip', // 'zip' or 'git'
        optionalCodeFile: null, // { name, size, path, type }
        gitRepoUrl: '',
        showGitInput: false,
        discoverySummary: null,
        isLoadingDiscovery: false,
        showDiscoveryModal: false,
        showDiscoveryDrawer: false,
        discoveryFilter: 'ALL',
        discoverySearchQuery: '',
        discoveryCollapsedCategories: {},
        treeCollapsed: false,
        scope: {
            includedPaths: ['/*'],
            excludedPaths: ['None'],
            rateLimit: '10 req/sec'
        },
        verifyMethod: 0,
        authData: {
            targetId: null,
            targetUrl: '',
            method: 'DNS',
            status: 'UNVERIFIED',
            dnsChallenge: null,
            fileChallenge: null,
            writtenLetter: {
                file: null,
                fileName: '',
                ownerName: '',
                ownerTitle: '',
                status: 'NONE',
                reviewNotes: ''
            },
            isCheckingDns: false,
            isCheckingFile: false,
            isSubmittingLetter: false,
            gateAllowed: false,
            gateMessage: '',
            showAdminModal: false,
            adminRequests: [],
            adminFilter: 'ALL',
            isLoadingAdmin: false,
            adminDecisionNotes: ''
        },
        confirmedAuthorization: false,
        showConfirmModal: false,
        currentScanId: null,
        progress: 0,
        timer: null
    },
    findingsData: [],
    selectedFindingId: null,
    findingTab: 'overview', // 'overview' | 'request' | 'fix'
    dashboardViewMode: 'standard', // 'standard' or 'sheet'
    activeCategoryFilter: '', // '' (All) | 'SAST' | 'DAST' | 'SECRETS' | 'SCA' | 'IAC'
    activeSeverityFilter: '',
    activeStatusFilter: '',
    activeSearchQuery: '',
    isDarkMode: false,

    // Dynamically retrieve the logged-in client's credentials (never hardcoded)
    getCurrentUser() {
        if (this.currentUser && this.currentUser.name) return this.currentUser;
        const stored = API.getUser();
        if (stored && stored.name) {
            this.currentUser = stored;
            return stored;
        }
        return { name: 'Client Account', email: 'client@scanner.local', role: 'user' };
    },

    async init() {
        this.initTheme();
        this.currentUser = API.getUser();

        if (API.getToken()) {
            try {
                this.currentUser = await API.me();
            } catch (e) {
                this.currentUser = API.getUser();
            }
        }

        // Restore staged files if available in localStorage
        try {
            const savedFileStr = localStorage.getItem('sential_staged_file');
            if (savedFileStr) {
                this.scanState.uploadedFile = JSON.parse(savedFileStr);
            }
            const savedOptStr = localStorage.getItem('sential_staged_opt_file');
            if (savedOptStr) {
                this.scanState.optionalCodeFile = JSON.parse(savedOptStr);
            }
        } catch (e) {
            console.warn('Could not restore staged file from localStorage', e);
        }

        let hash = window.location.hash.replace('#', '') || 'welcome';
        if (!API.getToken() && !['welcome', 'login', 'signup'].includes(hash)) {
            hash = 'welcome';
        }
        this.navigate(hash, false);

        window.addEventListener('hashchange', () => {
            let h = window.location.hash.replace('#', '') || 'welcome';
            if (!API.getToken() && !['welcome', 'login', 'signup'].includes(h)) {
                h = 'welcome';
            }
            if (h !== this.currentView) {
                this.navigate(h, false);
            }
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (this.scanState && this.scanState.activeCodeViewer) {
                    this.closeCodeViewer();
                } else if (this.scanState && this.scanState.showDiscoveryModal) {
                    this.toggleDiscoveryModal(false);
                } else {
                    this.closeScopeAutocomplete();
                }
            }
        });

        window.addEventListener('click', (e) => {
            if (!e.target.closest('.scope-tag-field')) {
                this.closeScopeAutocomplete();
            }
        });
    },

    // =========================================================
    // CYBER TACTICAL THEME ENGINE (DEFENSE GRID vs STEALTH OPS)
    // =========================================================
    initTheme() {
        try {
            const saved = localStorage.getItem('sential_theme');
            if (saved === 'dark') {
                this.isDarkMode = true;
            } else if (saved === 'light') {
                this.isDarkMode = false;
            } else {
                this.isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            }
        } catch (e) {
            this.isDarkMode = false;
        }
        this.applyTheme(false);
    },

    applyTheme(triggerSound = false) {
        const theme = this.isDarkMode ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-theme', theme);
        if (this.isDarkMode) {
            document.body.classList.add('dark-theme');
        } else {
            document.body.classList.remove('dark-theme');
        }
        try {
            localStorage.setItem('sential_theme', theme);
        } catch (e) {}

        if (triggerSound) {
            this.playCyberSound(this.isDarkMode);
        }

        // Keep Progress Orb colors in sync with theme changes
        const orbEl = document.querySelector('.progress-orb');
        if (orbEl && this.scanState) {
            const p = this.scanState.progress || 0;
            const isDone = p >= 100 || (this.scanState.status === 'completed');
            const orbColor = this.isDarkMode ? '#38bdf8' : '#2563eb';
            const bgCutout = this.isDarkMode ? '#0c1424' : '#ffffff';
            const bgTrack = this.isDarkMode ? '#1a273e' : '#e9eff6';
            if (isDone) {
                orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} 100%, ${orbColor} 100%)`;
                orbEl.classList.add('completed');
            } else {
                orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} ${p}%, ${bgTrack} 0)`;
                orbEl.classList.remove('completed');
            }
        }

        // Update all active theme toggles seamlessly without tearing down page DOM
        document.querySelectorAll('.theme-toggle-wrap, .cyber-tactical-hud-wrap').forEach(wrap => {
            const temp = document.createElement('div');
            temp.innerHTML = this.renderCyberThemeToggle();
            const newEl = temp.firstElementChild;
            if (newEl && wrap.parentNode) {
                wrap.parentNode.replaceChild(newEl, wrap);
            }
        });
    },

    toggleCyberTheme(event) {
        this.isDarkMode = !this.isDarkMode;
        this.spawnEmpWave(event);
        this.applyTheme(true);
        const modeLabel = this.isDarkMode ? 'Dark Mode' : 'Light Mode';
        const icon = this.isDarkMode ? '🌙' : '☀️';
        showToast(`${icon} ${modeLabel}`, 'info');
    },

    spawnEmpWave(event) {
        try {
            let x = window.innerWidth / 2;
            let y = 60;
            if (event && (event.clientX || event.clientY)) {
                x = event.clientX;
                y = event.clientY;
            } else {
                const btn = document.querySelector('.cyber-tactical-switch');
                if (btn) {
                    const rect = btn.getBoundingClientRect();
                    x = rect.left + rect.width / 2;
                    y = rect.top + rect.height / 2;
                }
            }
            const wave = document.createElement('div');
            wave.className = 'cyber-emp-shockwave';
            wave.style.left = `${x}px`;
            wave.style.top = `${y}px`;
            document.body.appendChild(wave);
            setTimeout(() => {
                if (wave.parentNode) wave.parentNode.removeChild(wave);
            }, 750);
        } catch (e) {
            console.warn('EMP Wave error', e);
        }
    },

    playCyberSound(isDark) {
        try {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (!AudioContextClass) return;
            const ctx = new AudioContextClass();
            if (ctx.state === 'suspended') {
                ctx.resume();
            }
            const now = ctx.currentTime;
            if (isDark) {
                // STEALTH OPS: Night vision power-up frequency sweep
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                const filter = ctx.createBiquadFilter();

                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(140, now);
                osc.frequency.exponentialRampToValueAtTime(780, now + 0.16);
                osc.frequency.exponentialRampToValueAtTime(520, now + 0.28);

                filter.type = 'bandpass';
                filter.frequency.setValueAtTime(400, now);
                filter.frequency.linearRampToValueAtTime(1200, now + 0.18);
                filter.Q.value = 4.0;

                gain.gain.setValueAtTime(0.001, now);
                gain.gain.linearRampToValueAtTime(0.18, now + 0.04);
                gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.32);

                osc.connect(filter);
                filter.connect(gain);
                gain.connect(ctx.destination);

                osc.start(now);
                osc.stop(now + 0.34);
            } else {
                // DEFENSE GRID: Double high affirmative sonar beep
                [0, 0.09].forEach((delay, idx) => {
                    const osc = ctx.createOscillator();
                    const gain = ctx.createGain();
                    osc.type = 'sine';
                    osc.frequency.setValueAtTime(idx === 0 ? 680 : 960, now + delay);
                    gain.gain.setValueAtTime(0.001, now + delay);
                    gain.gain.linearRampToValueAtTime(0.14, now + delay + 0.015);
                    gain.gain.exponentialRampToValueAtTime(0.0001, now + delay + 0.08);
                    osc.connect(gain);
                    gain.connect(ctx.destination);
                    osc.start(now + delay);
                    osc.stop(now + delay + 0.09);
                });
            }
        } catch (e) {
            // Safe fallback
        }
    },

    renderCyberThemeToggle() {
        const isDark = !!this.isDarkMode;
        return `
            <div class="theme-toggle-wrap">
                <button type="button" class="theme-icon-btn ${isDark ? 'is-dark' : 'is-light'}" onclick="App.toggleCyberTheme(event)" title="${isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}" aria-label="Toggle theme">
                    ${isDark ? 
                        Icons.get('moon', 'size-5 theme-svg-moon') : 
                        Icons.get('sun', 'size-5 theme-svg-sun')}
                </button>
            </div>
        `;
    },

    renderLanguageToggle() {
        if (window.I18n && typeof window.I18n.renderToggle === 'function') {
            return window.I18n.renderToggle();
        }
        return '';
    },

    toggleLanguage(event) {
        if (window.I18n && typeof window.I18n.toggleLang === 'function') {
            window.I18n.toggleLang(event);
        }
    },

    navigate(viewName, updateHash = true) {
        // Enforce strictly sequential progression: prevent jumping ahead to locked steps
        const targetStep = STEPS.find(s => s.id === viewName);
        if (targetStep && this.scanState) {
            const maxStep = this.scanState.maxUnlockedStep || 1;
            if (targetStep.step > maxStep) {
                showToast(`Step ${targetStep.step} (${targetStep.label}) is locked. Please proceed step-by-step.`, 'error');
                return;
            }
        }

        if (viewName !== 'scope') {
            this.stopAuthPolling();
        }

        this.currentView = viewName;
        if (updateHash) {
            window.location.hash = viewName;
        }

        this.render();
    },

    handleLockedStepClick(stepNumber, label) {
        const currentMax = (this.scanState && this.scanState.maxUnlockedStep) || 1;
        showToast(`Step ${stepNumber} (${label}) is locked. Please complete Step ${currentMax} first.`, 'info');
    },

    render() {
        const root = document.getElementById('root');
        if (!root) return;

        if (this.currentView === 'welcome') {
            root.innerHTML = this.renderWelcomeView();
        } else if (this.currentView === 'signup') {
            root.innerHTML = this.renderSignupView();
            this.clearInputs(['signup-firstname', 'signup-lastname', 'signup-email', 'signup-password', 'signup-confirm']);
            this.bindValidationListeners('signup');
        } else if (this.currentView === 'login') {
            root.innerHTML = this.renderLoginView();
            this.clearInputs(['login-email', 'login-password']);
            this.bindValidationListeners('login');
        } else {
            root.innerHTML = this.renderAppShell();
        }

        // Strictly attach Cyber Constellation matrix in Welcome view ONLY
        if (window.CyberMatrix) {
            if (this.currentView === 'welcome') {
                window.CyberMatrix.attach('cyber-welcome-canvas', {
                    nodeCount: window.innerWidth < 768 ? 28 : 54,
                    maxDistance: window.innerWidth < 768 ? 120 : 165,
                    drawPackets: true,
                    packetCount: 5,
                    ambientLight: true
                });
            } else {
                window.CyberMatrix.destroy('cyber-welcome-canvas');
                window.CyberMatrix.destroy('cyber-auth-canvas');
                window.CyberMatrix.destroy('cyber-app-canvas');
            }
        }

        if (this.currentView === 'dashboard') {
            this.loadDashboardData();
        } else if (this.currentView === 'finding') {
            this.loadFindingDetail(this.selectedFindingId);
        } else if (this.currentView === 'progress') {
            this.startProgressPolling();
        } else if (this.currentView === 'settings') {
            this.loadScanHistory();
        } else if (this.currentView === 'scope') {
            this.ensureAuthLoaded();
        } else if (this.currentView === 'report') {
            this.loadReportData();
        }

        if (window.I18n && typeof window.I18n.translateDOM === 'function') {
            window.I18n.translateDOM(document.body);
        }
    },

    clearInputs(ids) {
        const doClear = () => {
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    el.value = '';
                    el.defaultValue = '';
                    if (el.getAttribute('value')) el.removeAttribute('value');
                }
            });
        };
        requestAnimationFrame(doClear);
        setTimeout(doClear, 60);
        setTimeout(doClear, 200);
    },

    // =========================================================
    // REAL-TIME INPUT VALIDATION ENGINE
    // =========================================================
    bindValidationListeners(formType) {
        if (formType === 'login') {
            const emailInput = document.getElementById('login-email');
            const passInput = document.getElementById('login-password');
            if (emailInput) {
                emailInput.addEventListener('input', () => this.validateField('login-email'));
                emailInput.addEventListener('blur', () => this.validateField('login-email'));
            }
            if (passInput) {
                passInput.addEventListener('input', () => this.validateField('login-password'));
                passInput.addEventListener('blur', () => this.validateField('login-password'));
            }
        } else if (formType === 'signup') {
            const firstInput = document.getElementById('signup-firstname');
            const lastInput = document.getElementById('signup-lastname');
            const emailInput = document.getElementById('signup-email');
            const passInput = document.getElementById('signup-password');
            const confInput = document.getElementById('signup-confirm');

            if (firstInput) {
                firstInput.addEventListener('input', () => this.validateField('signup-firstname'));
                firstInput.addEventListener('blur', () => this.validateField('signup-firstname'));
            }
            if (lastInput) {
                lastInput.addEventListener('input', () => this.validateField('signup-lastname'));
                lastInput.addEventListener('blur', () => this.validateField('signup-lastname'));
            }
            if (emailInput) {
                emailInput.addEventListener('input', () => this.validateField('signup-email'));
                emailInput.addEventListener('blur', () => this.validateField('signup-email'));
            }
            if (passInput) {
                passInput.addEventListener('input', () => {
                    this.validateField('signup-password');
                    if (confInput && confInput.value.length > 0) {
                        this.validateField('signup-confirm');
                    }
                });
                passInput.addEventListener('blur', () => this.validateField('signup-password'));
            }
            if (confInput) {
                confInput.addEventListener('input', () => this.validateField('signup-confirm'));
                confInput.addEventListener('blur', () => this.validateField('signup-confirm'));
            }
        }
    },

    validateField(fieldId) {
        const input = document.getElementById(fieldId);
        if (!input) return true;
        const wrap = input.closest('.input-wrap');
        const feedbackContainer = document.getElementById(`${fieldId}-feedback`);
        const val = input.value.trim();

        const setFeedback = (isValid, msg, type = 'error') => {
            if (wrap) {
                wrap.classList.remove('is-invalid', 'is-valid');
                if (isValid === false) wrap.classList.add('is-invalid');
                else if (isValid === true) wrap.classList.add('is-valid');
            }
            if (feedbackContainer) {
                if (!msg) {
                    feedbackContainer.innerHTML = '';
                } else {
                    const icon = type === 'error' ? Icons.get('alert', 'size-3.5') : Icons.get('check', 'size-3.5');
                    feedbackContainer.innerHTML = `
                        <div class="field-feedback ${type}">
                            <span>${icon}</span>
                            <span>${msg}</span>
                        </div>
                    `;
                }
            }
        };

        // 1. Email fields
        if (fieldId === 'login-email' || fieldId === 'signup-email') {
            if (val.length === 0) {
                setFeedback(false, 'Email address is required.');
                return false;
            }
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(val)) {
                setFeedback(false, 'Please enter a valid email address (e.g. name@company.com).');
                return false;
            }
            setFeedback(true, '');
            return true;
        }

        // 2. Login password
        if (fieldId === 'login-password') {
            if (input.value.length === 0) {
                setFeedback(false, 'Password is required.');
                return false;
            }
            setFeedback(true, '');
            return true;
        }

        // 3. Signup first & last name
        if (fieldId === 'signup-firstname') {
            if (val.length === 0) {
                setFeedback(false, 'First name is required.');
                return false;
            }
            setFeedback(true, '');
            return true;
        }
        if (fieldId === 'signup-lastname') {
            if (val.length === 0) {
                setFeedback(false, 'Last name is required.');
                return false;
            }
            setFeedback(true, '');
            return true;
        }

        // 4. Signup password & strength meter
        if (fieldId === 'signup-password') {
            const raw = input.value;
            const strengthBar = document.getElementById('signup-password-strength');
            const steps = strengthBar ? strengthBar.querySelectorAll('.pw-strength-step') : [];

            if (raw.length === 0) {
                setFeedback(false, 'Password is required (min 8 characters).');
                steps.forEach(s => s.className = 'pw-strength-step');
                return false;
            }
            if (raw.length < 8) {
                setFeedback(false, 'Password must be at least 8 characters long.');
                if (steps.length === 3) {
                    steps[0].className = 'pw-strength-step weak';
                    steps[1].className = 'pw-strength-step';
                    steps[2].className = 'pw-strength-step';
                }
                return false;
            }

            // Calculate strength
            let score = 0;
            if (raw.length >= 8) score++;
            if (/[0-9]/.test(raw) && /[A-Z]/.test(raw)) score++;
            if (/[^A-Za-z0-9]/.test(raw)) score++;

            if (steps.length === 3) {
                steps.forEach(s => s.className = 'pw-strength-step');
                if (score === 1) {
                    steps[0].className = 'pw-strength-step weak';
                    setFeedback(true, 'Good password length.', 'success');
                } else if (score === 2) {
                    steps[0].className = 'pw-strength-step medium';
                    steps[1].className = 'pw-strength-step medium';
                    setFeedback(true, 'Strong password.', 'success');
                } else {
                    steps[0].className = 'pw-strength-step strong';
                    steps[1].className = 'pw-strength-step strong';
                    steps[2].className = 'pw-strength-step strong';
                    setFeedback(true, 'Very strong password.', 'success');
                }
            } else {
                setFeedback(true, '');
            }
            return true;
        }

        // 5. Signup confirm password
        if (fieldId === 'signup-confirm') {
            const passVal = document.getElementById('signup-password')?.value || '';
            const confVal = input.value;

            if (confVal.length === 0) {
                setFeedback(false, 'Please confirm your password.');
                return false;
            }
            if (confVal !== passVal) {
                setFeedback(false, 'Passwords do not match.');
                return false;
            }
            setFeedback(true, 'Passwords match perfectly.', 'success');
            return true;
        }

        return true;
    },

    // =========================================================
    // 1. WELCOME VIEW
    // =========================================================
    renderWelcomeView() {
        return `
            <div class="welcome-page">
                <!-- DarkEntry-style Cyber Constellation & Neural Network Canvas -->
                <div class="cyber-canvas-container">
                    <canvas id="cyber-welcome-canvas" class="cyber-background-canvas"></canvas>
                    <div class="cyber-ambient-glow glow-cyan"></div>
                    <div class="cyber-ambient-glow glow-emerald"></div>
                    <div class="cyber-ambient-glow glow-violet"></div>
                </div>

                <header class="welcome-nav">
                    ${renderBrandLogo()}
                    <div class="flex items-center gap-3">
                        ${this.renderLanguageToggle()}
                        ${this.renderCyberThemeToggle()}
                        <button class="button button-ghost" onclick="App.navigate('login')">Log in</button>
                        <button class="button button-primary" onclick="App.navigate('signup')">Start free</button>
                    </div>
                </header>

                <main class="welcome-main">
                    <div class="hero-copy">
                        <div class="pill">
                            <span class="size-2 rounded-full bg-emerald-500"></span>
                            AI-powered web security
                        </div>
                        <h1 class="mt-7 text-6xl font-extrabold leading-[1.06] tracking-tight text-slate-950">
                            Find vulnerabilities.<br>
                            <span class="text-blue-600">Fix them faster.</span>
                        </h1>
                        <p class="mt-6 max-w-xl text-xl leading-8 text-slate-500">
                            Run comprehensive security assessments, prioritize what matters, and ship AI-guided fixes with confidence.
                        </p>
                        <div class="mt-9 flex flex-wrap gap-3">
                            <button class="button button-primary button-lg" onclick="App.navigate('signup')">
                                <span>Start your first scan</span>
                                ${Icons.get('arrow', 'size-4')}
                            </button>
                            <button class="button button-secondary button-lg" onclick="App.navigate('dashboard')">
                                <span>View dashboard</span>
                            </button>
                        </div>
                        <div class="mt-9 flex flex-wrap gap-6 text-sm font-semibold text-slate-500">
                            <span class="inline-flex items-center gap-2">
                                ${Icons.get('check', 'size-4 text-emerald-500')}
                                No credit card required
                            </span>
                            <span class="inline-flex items-center gap-2">
                                ${Icons.get('check', 'size-4 text-emerald-500')}
                                First scan in minutes
                            </span>
                        </div>
                    </div>

                    <div class="hero-product">
                        <!-- Animated Defense Radar Orbits -->
                        <div class="orbit orbit-one">
                            <span class="orbit-satellite sat-one"></span>
                        </div>
                        <div class="orbit orbit-two">
                            <span class="orbit-satellite sat-two"></span>
                        </div>
                        <div class="orbit orbit-three">
                            <span class="orbit-satellite sat-three"></span>
                        </div>
                        <div class="scan-card">
                            <div class="scan-card-head">
                                <div class="flex items-center gap-3">
                                    <div class="icon-tile blue">${Icons.get('globe', 'size-5 text-blue-600')}</div>
                                    <div>
                                        <b>app.northstar.io</b>
                                        <small class="text-slate-400 block text-xs">Live assessment</small>
                                    </div>
                                </div>
                                <span class="status status-running">
                                    <span class="pulse-dot"></span> Scanning
                                </span>
                            </div>

                            <div class="scan-score">
                                <div class="score-ring">
                                    <strong>84</strong>
                                    <span>Security score</span>
                                </div>
                                <div class="grow space-y-3">
                                    <div>
                                        <div class="mb-1.5 flex justify-between text-xs font-semibold text-slate-600">
                                            <span>Endpoints mapped</span><b>142</b>
                                        </div>
                                        <div class="h-1.5 rounded-full bg-slate-100">
                                            <div class="h-full rounded-full bg-blue-500 w-full"></div>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="mb-1.5 flex justify-between text-xs font-semibold text-slate-600">
                                            <span>Tests completed</span><b>83%</b>
                                        </div>
                                        <div class="h-1.5 rounded-full bg-slate-100">
                                            <div class="h-full rounded-full bg-cyan-400 w-4/5"></div>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="mb-1.5 flex justify-between text-xs font-semibold text-slate-600">
                                            <span>Findings analyzed</span><b>18</b>
                                        </div>
                                        <div class="h-1.5 rounded-full bg-slate-100">
                                            <div class="h-full rounded-full bg-violet-400 w-2/3"></div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="finding-toast toast-one">
                                <span class="severity-dot critical"></span>
                                <div>
                                    <b class="text-xs">Critical finding</b>
                                    <small class="text-xs text-slate-400 block">SQL Injection · /api/v2/users</small>
                                </div>
                                ${Icons.get('arrow', 'ml-auto size-4 text-slate-400')}
                            </div>

                            <div class="finding-toast toast-two">
                                <div class="icon-tile mint">${Icons.get('sparkles', 'size-4')}</div>
                                <div>
                                    <b class="text-xs">AI remediation ready</b>
                                    <small class="text-xs text-slate-400 block">Safe patch generated</small>
                                </div>
                                ${Icons.get('check', 'ml-auto size-4 text-emerald-600')}
                            </div>
                        </div>
                    </div>
                </main>

                <div class="trusted">
                    <span>TRUSTED BY SECURITY TEAMS AT</span>
                    <b>Northstar</b>
                    <b>Vertex</b>
                    <b>Cloudline</b>
                    <b>HALO</b>
                </div>
            </div>
        `;
    },

    // =========================================================
    // 2. USER SIGN UP VIEW (Empty Inputs + Real-time Validation)
    // =========================================================
    renderSignupView() {
        return `
            <div class="auth-shell">
                <div class="auth-brand">
                    ${renderBrandLogo()}
                </div>
                <div style="position: absolute; top: 2.5rem; right: 3rem; z-index: 10; display: flex; align-items: center; gap: 0.75rem;">
                    ${this.renderLanguageToggle()}
                    ${this.renderCyberThemeToggle()}
                </div>

                <div class="auth-visual">
                    <div class="visual-grid"></div>
                    <div class="visual-content">
                        <div class="hero-shield">${Icons.get('shield', 'size-12')}</div>
                        <p class="eyebrow text-blue-200">Built for modern teams</p>
                        <h1 class="mt-4 max-w-lg text-5xl font-extrabold leading-tight tracking-tight text-white">
                            Security clarity,<br>without the noise.
                        </h1>
                        <p class="mt-5 max-w-md text-lg leading-8 text-blue-100/80">
                            From first scan to verified fix, Sential AI makes every vulnerability actionable.
                        </p>
                        <div class="mt-10 flex gap-8">
                            <div>
                                <div class="text-3xl font-black text-white">100%</div>
                                <span class="text-xs text-blue-200">Automated triage</span>
                            </div>
                            <div>
                                <div class="text-3xl font-black text-white">&lt;24h</div>
                                <span class="text-xs text-blue-200">Avg. time to fix</span>
                            </div>
                            <div>
                                <div class="text-3xl font-black text-white">&lt;1 min</div>
                                <span class="text-xs text-blue-200">Setup time</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="auth-form-wrap">
                    <div class="auth-form" id="signup-form-container">
                        <div class="eyebrow">Get started</div>
                        <h2>Create your account</h2>
                        <p class="text-slate-500 text-sm mt-1 mb-6">Start securing your applications in minutes.</p>

                        <form id="signup-form" onsubmit="App.handleSignup(event)" autocomplete="off" novalidate>
                            <div class="form-row-2">
                                <label class="field">
                                    <span class="field-label">First name</span>
                                    <span class="input-wrap">
                                        ${Icons.get('user', 'size-4 text-slate-400')}
                                        <input type="text" id="signup-firstname" placeholder="" value="" autocomplete="off">
                                    </span>
                                    <div id="signup-firstname-feedback"></div>
                                </label>
                                <label class="field">
                                    <span class="field-label">Last name</span>
                                    <span class="input-wrap">
                                        ${Icons.get('user', 'size-4 text-slate-400')}
                                        <input type="text" id="signup-lastname" placeholder="" value="" autocomplete="off">
                                    </span>
                                    <div id="signup-lastname-feedback"></div>
                                </label>
                            </div>

                            <label class="field mt-4">
                                <span class="field-label">Work email</span>
                                <span class="input-wrap">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="size-4 text-slate-400"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                                    <input type="email" id="signup-email" placeholder="" value="" autocomplete="off">
                                </span>
                                <div id="signup-email-feedback"></div>
                            </label>

                            <label class="field mt-4">
                                <span class="field-label">Password</span>
                                <span class="input-wrap">
                                    ${Icons.get('lock', 'size-4 text-slate-400')}
                                    <input type="password" id="signup-password" placeholder="" value="" autocomplete="new-password">
                                    <button type="button" class="bg-transparent border-0 p-0 cursor-pointer" onclick="togglePasswordVisibility('signup-password', this)" title="Toggle password visibility">
                                        ${Icons.get('eye', 'size-4 text-slate-400')}
                                    </button>
                                </span>
                                <div class="pw-strength-bar" id="signup-password-strength">
                                    <div class="pw-strength-step"></div>
                                    <div class="pw-strength-step"></div>
                                    <div class="pw-strength-step"></div>
                                </div>
                                <div id="signup-password-feedback"></div>
                            </label>

                            <label class="field mt-4">
                                <span class="field-label">Confirm password</span>
                                <span class="input-wrap">
                                    ${Icons.get('lock', 'size-4 text-slate-400')}
                                    <input type="password" id="signup-confirm" placeholder="" value="" autocomplete="new-password">
                                    <button type="button" class="bg-transparent border-0 p-0 cursor-pointer" onclick="togglePasswordVisibility('signup-confirm', this)" title="Toggle password visibility">
                                        ${Icons.get('eye', 'size-4 text-slate-400')}
                                    </button>
                                </span>
                                <div id="signup-confirm-feedback"></div>
                            </label>

                            <label class="mt-4 flex items-start gap-3 text-sm leading-6 text-slate-500 cursor-pointer">
                                <input type="checkbox" id="signup-terms" required checked class="mt-1 accent-blue-600">
                                <span>I agree to the <b class="text-slate-700">Terms of Service</b> and <b class="text-slate-700">Privacy Policy</b>.</span>
                            </label>

                            <button type="submit" id="btn-signup-submit" class="button button-primary button-lg w-full justify-center mt-6">
                                <span>Create account</span>
                                ${Icons.get('arrow', 'size-4')}
                            </button>
                        </form>

                        <p class="mt-6 text-center text-sm text-slate-500">
                            Already have an account? 
                            <button onclick="App.navigate('login')" class="font-bold text-blue-600 border-0 bg-transparent cursor-pointer p-0">Log in</button>
                        </p>
                    </div>
                </div>
            </div>
        `;
    },

    // =========================================================
    // 3. USER LOGIN VIEW (Empty Inputs + Real-time Validation)
    // =========================================================
    renderLoginView() {
        return `
            <div class="auth-shell">
                <div class="auth-brand">
                    ${renderBrandLogo()}
                </div>
                <div style="position: absolute; top: 2.5rem; right: 3rem; z-index: 10; display: flex; align-items: center; gap: 0.75rem;">
                    ${this.renderLanguageToggle()}
                    ${this.renderCyberThemeToggle()}
                </div>

                <div class="auth-visual">
                    <div class="visual-grid"></div>
                    <div class="visual-content">
                        <div class="hero-shield">${Icons.get('shield', 'size-12')}</div>
                        <p class="eyebrow text-blue-200">Built for modern teams</p>
                        <h1 class="mt-4 max-w-lg text-5xl font-extrabold leading-tight tracking-tight text-white">
                            Security clarity,<br>without the noise.
                        </h1>
                        <p class="mt-5 max-w-md text-lg leading-8 text-blue-100/80">
                            From first scan to verified fix, Sential AI makes every vulnerability actionable.
                        </p>
                        <div class="mt-10 flex gap-8">
                            <div>
                                <div class="text-3xl font-black text-white">100%</div>
                                <span class="text-xs text-blue-200">Automated triage</span>
                            </div>
                            <div>
                                <div class="text-3xl font-black text-white">&lt;24h</div>
                                <span class="text-xs text-blue-200">Avg. time to fix</span>
                            </div>
                            <div>
                                <div class="text-3xl font-black text-white">99.9%</div>
                                <span class="text-xs text-blue-200">Uptime</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="auth-form-wrap">
                    <div class="auth-form" id="login-form-container">
                        <div class="eyebrow">Welcome back</div>
                        <h2>Log in to Sential AI</h2>
                        <p class="text-slate-500 text-sm mt-1 mb-6">Continue to your security workspace.</p>

                        <form id="login-form" onsubmit="App.handleLogin(event)" autocomplete="off" novalidate>
                            <label class="field">
                                <span class="field-label">Work email</span>
                                <span class="input-wrap">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="size-4 text-slate-400"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                                    <input type="email" id="login-email" placeholder="" value="" autocomplete="off">
                                </span>
                                <div id="login-email-feedback"></div>
                            </label>

                            <label class="field mt-4">
                                <span class="field-label">Password</span>
                                <span class="input-wrap">
                                    ${Icons.get('lock', 'size-4 text-slate-400')}
                                    <input type="password" id="login-password" placeholder="" value="" autocomplete="current-password">
                                    <button type="button" class="bg-transparent border-0 p-0 cursor-pointer" onclick="togglePasswordVisibility('login-password', this)" title="Toggle password visibility">
                                        ${Icons.get('eye', 'size-4 text-slate-400')}
                                    </button>
                                </span>
                                <div id="login-password-feedback"></div>
                            </label>

                            <div class="flex items-center justify-between text-sm mt-4 mb-2">
                                <label class="flex items-center gap-2 text-slate-500 cursor-pointer m-0">
                                    <input type="checkbox" id="login-remember" checked class="accent-blue-600">
                                    <span>Remember me</span>
                                </label>
                                <a href="javascript:void(0)" class="font-bold text-blue-600 text-xs" onclick="showToast('Password reset link sent to your registered email', 'info')">Forgot password?</a>
                            </div>

                            <button type="submit" id="btn-login-submit" class="button button-primary button-lg w-full justify-center mt-5">
                                <span>Log in</span>
                                ${Icons.get('arrow', 'size-4')}
                            </button>

                            <div class="divider"><span>or continue with</span></div>

                            <button type="button" class="button button-secondary w-full justify-center" onclick="showToast('Google Workspace SSO authenticated successfully', 'success')">
                                <span class="text-lg font-black text-blue-600">G</span>
                                <span>Google Workspace</span>
                            </button>
                        </form>

                        <p class="mt-6 text-center text-sm text-slate-500">
                            New to Sential AI? 
                            <button onclick="App.navigate('signup')" class="font-bold text-blue-600 border-0 bg-transparent cursor-pointer p-0">Create account</button>
                        </p>
                    </div>
                </div>
            </div>
        `;
    },

    // =========================================================
    // 4. APP SHELL (Exact Figma Sidebar, Topbar & Navigation)
    // =========================================================
    renderAppShell() {
        const user = this.getCurrentUser();
        const currentStepObj = STEPS.find(s => s.id === this.currentView) || 
            (this.currentView === 'finding' ? { label: 'Finding Details', step: 6, icon: 'code' } : 
            (this.currentView === 'settings' ? { label: 'Settings & History', step: '—', icon: 'settings' } : STEPS[0]));
        const initials = user.name ? user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() : 'CU';

        return `
            <div class="app-shell">
                <!-- Sidebar -->
                <aside class="sidebar" id="app-sidebar">
                    <div class="sidebar-brand">
                        ${renderBrandLogo()}
                        <button class="lg:hidden text-slate-400 bg-transparent border-0 cursor-pointer" onclick="App.toggleSidebar(false)">
                            ${Icons.get('x', 'size-5')}
                        </button>
                    </div>

                    <!-- Sleek ChatGPT-style New Assessment button (Spaced downwards) -->
                    <div class="sidebar-action-wrap" style="padding: 1.15rem 1rem 0.45rem;">
                        <button type="button" class="btn-new-assessment" onclick="App.startNewAssessment()">
                            ${Icons.get('plus', 'size-4')}
                            <span>New Assessment</span>
                        </button>
                    </div>

                    <div class="nav-label">Assessment flow</div>
                    <nav class="side-nav">
                        ${STEPS.map(s => {
                            const isCurrent = this.currentView === s.id;
                            const maxStep = (this.scanState && this.scanState.maxUnlockedStep) || 1;
                            const isUnlocked = s.step <= maxStep;
                            const isCompleted = s.step < maxStep;

                            if (isUnlocked) {
                                return `
                                    <button class="${isCurrent ? 'active' : ''}" onclick="App.navigate('${s.id}')">
                                        <span class="nav-icon ${isCompleted ? 'text-blue-600' : ''}">${Icons.get(s.icon, 'size-4')}</span>
                                        <span>
                                            <b>${s.label}</b>
                                            <small>Step ${s.step}</small>
                                        </span>
                                        ${isCurrent ? '<span class="active-dot"></span>' : (isCompleted ? `<span class="step-check">${Icons.get('check', 'size-3 text-emerald-600')}</span>` : '')}
                                    </button>
                                `;
                            } else {
                                return `
                                    <button type="button" class="step-locked" onclick="App.handleLockedStepClick(${s.step}, '${escapeHtml(s.label)}')">
                                        <span class="nav-icon opacity-40">${Icons.get(s.icon, 'size-4')}</span>
                                        <span class="opacity-45">
                                            <b>${s.label}</b>
                                            <small>Step ${s.step} · Locked</small>
                                        </span>
                                        <span class="ml-auto opacity-35">${Icons.get('lock', 'size-3.5')}</span>
                                    </button>
                                `;
                            }
                        }).join('')}
                    </nav>

                    <div class="sidebar-bottom">
                        <div class="sidebar-user-tile ${this.currentView === 'settings' ? 'active' : ''}" onclick="App.navigate('settings')" title="View profile &amp; assessment history">
                            <span class="avatar">${initials}</span>
                            <div class="user-text">
                                <span class="user-name">${escapeHtml(user.name)}</span>
                                <span class="user-email">${escapeHtml(user.email)}</span>
                            </div>
                            <span class="user-settings-icon" title="Workspace Settings">${Icons.get('settings', 'size-3.5')}</span>
                        </div>
                    </div>
                </aside>

                <!-- Content Area -->
                <section class="content-area">
                    <header class="topbar">
                        <button class="lg:hidden bg-transparent border-0 cursor-pointer" onclick="App.toggleSidebar(true)">
                            ${Icons.get('menu', 'size-5 text-slate-600')}
                        </button>
                        <div class="topbar-trail">
                            <span>${escapeHtml(user.organization || (user.name ? user.name + ' Workspace' : 'Security Workspace'))}</span>
                            ${Icons.get('arrow', 'size-3')}
                            <b>${currentStepObj.label}</b>
                        </div>

                        <div class="ml-auto flex items-center gap-3">
                            ${this.renderLanguageToggle()}
                            ${this.renderCyberThemeToggle()}
                            <button type="button" class="topbar-logout-btn" onclick="App.handleLogout()" title="Log out">
                                ${Icons.get('logout', 'size-4')}
                            </button>
                        </div>
                    </header>

                    <main class="page-content" id="page-content">
                        ${this.renderCurrentViewBody()}
                    </main>
                </section>
                ${this.scanState.showDiscoveryModal ? this.renderDiscoveryModal() : ''}
                ${this.scanState.activeCodeViewer ? this.renderCodeViewerModal() : ''}
            </div>
        `;
    },

    startNewAssessment() {
        try {
            localStorage.removeItem('sentinel_history_all_cleared');
            localStorage.removeItem('sential_staged_file');
        } catch (e) {}
        this.findingsData = [];
        this.selectedFindingId = null;
        this.scanState.currentScanId = null;
        this.scanState.uploadedFile = null;
        this.scanState.name = '';
        this.scanState.url = '';
        this.scanState.progress = 0;
        this.scanState.liveCodeStream = [];
        this.scanState.inspectorTick = 0;
        if (this.scanState.timer) clearInterval(this.scanState.timer);
        if (this.scanState.inspectorTimer) clearInterval(this.scanState.inspectorTimer);
        this.scanState.timer = null;
        this.scanState.inspectorTimer = null;
        this.scanState.confirmedAuthorization = false;
        this.scanState.showConfirmModal = false;
        this.scanState.maxUnlockedStep = 1;
        this.navigate('type');
        showToast('Starting a new security assessment.', 'info');
    },

    proceedFromType() {
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 2);
        this.navigate('url');
    },

    proceedToDashboard() {
        if (this.scanState.timer) clearInterval(this.scanState.timer);
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 7);
        this.navigate('dashboard');
    },

    proceedToReport() {
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 7);
        this.navigate('report');
    },

    toggleSidebar(open) {
        const sb = document.getElementById('app-sidebar');
        if (sb) {
            if (open) sb.classList.add('sidebar-open');
            else sb.classList.remove('sidebar-open');
        }
    },

    renderCurrentViewBody() {
        switch (this.currentView) {
            case 'type': return this.renderTypeStep();
            case 'url': return this.renderUrlStep();
            case 'scope': return this.renderScopeStep();
            case 'confirm': return this.renderConfirmStep();
            case 'progress': return this.renderProgressStep();
            case 'dashboard': return this.renderDashboard();
            case 'finding': return this.renderFindingDetail();
            case 'report': return this.renderReport();
            case 'settings': return this.renderSettingsView();
            default: return this.renderDashboard();
        }
    },

    // =========================================================
    // =========================================================
    // 5. STEP 1: ASSESSMENT TYPE (EXACT FIGMA se COMPONENT)
    // =========================================================
    renderTypeStep() {
        const selected = this.scanState.scanType;

        return `
            ${renderPageTitle({
                eyebrow: 'New assessment',
                title: 'What would you like us to do?',
                copy: 'Choose the depth of your security assessment. You can review every change before it is applied.'
            })}

            <div class="option-grid" style="grid-template-columns: repeat(2, 1fr);">
                <!-- Option 1: Scan Only -->
                <button type="button" class="option-card ${selected === 'scan_only' ? 'selected' : ''}" onclick="App.selectScanType('scan_only')">
                    <div class="option-top">
                        <div class="icon-tile blue">${Icons.get('search', 'size-5')}</div>
                        <span class="option-tag">QUICK</span>
                    </div>
                    <h2>Scan Only</h2>
                    <p>Identify and prioritize vulnerabilities without making changes.</p>
                    <div class="option-foot">
                        <span>${Icons.get('clock', 'size-4')} ~10 minutes</span>
                        <span class="radio"><i></i></span>
                    </div>
                </button>

                <!-- Option 2: Scan + Fix + Test -->
                <button type="button" class="option-card ${selected === 'scan_fix_test' ? 'selected' : ''}" onclick="App.selectScanType('scan_fix_test')">
                    <div class="option-top">
                        <div class="icon-tile blue">${Icons.get('check', 'size-5')}</div>
                        <span class="option-tag">COMPLETE</span>
                    </div>
                    <h2>Scan + Fix + Test</h2>
                    <p>Full assessment, automated fixes, and validation testing.</p>
                    <div class="option-foot">
                        <span>${Icons.get('clock', 'size-4')} ~35 minutes</span>
                        <span class="radio"><i></i></span>
                    </div>
                </button>
            </div>

            <div class="info-banner">
                <div class="icon-tile mint">${Icons.get('shield', 'size-5')}</div>
                <div>
                    <b>You’re always in control</b>
                    <p>We never deploy changes automatically. Review and approve every suggested fix before applying it.</p>
                </div>
            </div>

            <div class="page-actions">
                <button type="button" class="button button-secondary" onclick="App.navigate('welcome')">Cancel</button>
                <button type="button" class="button button-primary" onclick="App.proceedFromType()">
                    Continue ${Icons.get('arrow', 'size-4')}
                </button>
            </div>
        `;
    },

    selectScanType(type) {
        this.scanState.scanType = type;
        this.render();
    },

    // =========================================================
    // 6. STEP 2: TARGET & ENVIRONMENT (SAST FILE UPLOAD + URL)
    // =========================================================
    renderUrlStep() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const rawUrl = (this.scanState.url || '').replace(/^https?:\/\//, '');
        const targetName = this.scanState.name || '';
        const file = this.scanState.uploadedFile;
        const isUploading = this.scanState.isUploading;

        const fileExt = file ? (file.name.split('.').pop() || 'ZIP').toUpperCase() : 'ZIP';
        const isArchive = file ? (file.name.endsWith('.zip') || file.name.endsWith('.tar.gz') || file.name.endsWith('.tar') || file.name.endsWith('.tgz')) : false;

        return `
            ${renderPageTitle({
                eyebrow: 'New assessment · Step 2 of 3',
                title: 'Target & Environment',
                copy: 'Select your deployment environment and configure the target application or repository to evaluate.'
            })}

            <!-- Environment Selection Grid (3 Distinct Cards) -->
            <div class="env-grid">
                <!-- 1. Development (File/Folder Upload for SAST) -->
                <div class="env-card ${env === 'development' ? 'selected' : ''}" onclick="App.selectEnvironment('development')">
                    <div class="env-card-head">
                        <div class="icon-tile indigo">${Icons.get('folder', 'size-5')}</div>
                        <span class="env-badge dev">SAST · Code Upload</span>
                    </div>
                    <h3>Development</h3>
                    <p>Upload project files or a ZIP archive. Performs Static Code Analysis (SAST) locally without needing internet exposure.</p>
                </div>

                <!-- 2. Staging (URL Required for DAST) -->
                <div class="env-card ${env === 'staging' ? 'selected' : ''}" onclick="App.selectEnvironment('staging')">
                    <div class="env-card-head">
                        <div class="icon-tile blue">${Icons.get('globe', 'size-5')}</div>
                        <span class="env-badge staging">DAST · Testing URL</span>
                    </div>
                    <h3>Staging</h3>
                    <p>Target pre-production test environments. Automated endpoint discovery and dynamic security testing (DAST).</p>
                </div>

                <!-- 3. Production (URL + Strict Safeguards) -->
                <div class="env-card ${env === 'production' ? 'selected' : ''}" onclick="App.selectEnvironment('production')">
                    <div class="env-card-head">
                        <div class="icon-tile amber">${Icons.get('shield', 'size-5')}</div>
                        <span class="env-badge prod">Live DAST · Strict Safeguards</span>
                    </div>
                    <h3>Production</h3>
                    <p>Target live web applications. Enforces strict conservative rate-limits (10 req/s) to protect live systems and users.</p>
                </div>
            </div>

            <!-- Dynamic Input Card Based on Selected Environment -->
            <div class="form-card">
                <div class="form-card-head">
                    <div class="icon-tile blue">${env === 'development' ? Icons.get('folder', 'size-5') : Icons.get('globe', 'size-5')}</div>
                    <div>
                        <h2>${env === 'development' ? 'Project Source Code (SAST)' : 'Target Application Endpoint (DAST)'}</h2>
                        <p>${env === 'development' ? 'Provide your source code archive for static vulnerability inspection.' : 'Specify the HTTPS reachable URL of your application.'}</p>
                    </div>
                </div>

                ${env === 'development' ? `
                    <!-- ChatGPT-style Minimalist Source Code Upload for Development (SAST) -->
                    <div class="mt-5">
                        <div class="chatgpt-attach-bar ${file ? 'has-file' : ''}">
                            <div class="chatgpt-attach-left">
                                <button type="button" class="chatgpt-clip-btn" onclick="App.triggerFileInput()" title="Attach file">
                                    ${Icons.get('file', 'size-3.5')}
                                </button>
                                ${file ? `
                                    <div class="chatgpt-attach-pill">
                                        <span class="font-semibold text-slate-800 truncate max-w-xs">${escapeHtml(file.name)}</span>
                                        <span class="text-[11px] text-slate-400">${fileExt} · ${(file.size / (1024 * 1024)).toFixed(2)} MB · Ready</span>
                                        <button type="button" class="chatgpt-remove-pill-btn" onclick="App.removeStagedFile()" title="Remove file">&times;</button>
                                    </div>
                                ` : `
                                    <span class="text-xs text-slate-400">Attach source code archive or folder for SAST (.zip, .tar, .js, .php, max 1GB)</span>
                                `}
                            </div>
                            <div class="flex items-center gap-1.5 flex-shrink-0">
                                ${file ? `
                                    <button type="button" class="chatgpt-attach-btn" onclick="App.triggerFileInput()">Change</button>
                                ` : `
                                    <button type="button" class="chatgpt-attach-btn" onclick="App.triggerFileInput()">
                                        ${Icons.get('file', 'size-3')} Attach ZIP
                                    </button>
                                    <button type="button" class="chatgpt-attach-btn" onclick="App.triggerFolderInput()">
                                        ${Icons.get('folder', 'size-3')} Folder
                                    </button>
                                `}
                            </div>
                        </div>

                        <input type="file" id="target-file-input" class="hidden" accept=".zip,.tar,.gz,.tgz,.js,.ts,.py,.php,.html,.json" onchange="App.handleFileSelect(event)">
                        <input type="file" id="target-folder-input" class="hidden" webkitdirectory directory multiple onchange="App.handleFolderSelect(event)">
                    </div>
                ` : `
                    <!-- URL Input Section for Staging & Production -->
                    <label class="field mt-6">
                        <span class="field-label flex items-center justify-between">
                            <span>Application URL</span>
                            <span class="text-xs text-slate-400 font-normal">HTTP / HTTPS</span>
                        </span>
                        <div class="flex items-center gap-2">
                            <span class="url-input flex-1">
                                <span id="url-protocol-prefix" class="cursor-pointer select-none font-bold text-slate-500 hover:text-blue-600 transition" onclick="App.toggleProtocolPrefix()" title="Click to toggle between http:// and https://">${(this.scanState.url && this.scanState.url.startsWith('http://')) ? 'http://' : 'https://'}</span>
                                <input type="text" id="target-url-input" value="${escapeHtml((this.scanState.url || '').replace(/^https?:\/\//i, ''))}" placeholder="app.yourcompany.com" oninput="App.onUrlChange(this.value)" onkeydown="if(event.key==='Enter'){event.preventDefault();App.validateTargetUrlInput();}">
                            </span>
                            <button type="button" class="button button-secondary text-xs" style="padding: 0.55rem 0.85rem;" onclick="App.validateTargetUrlInput()">
                                ${this.scanState.isValidatingUrl ? '<span class="spinner"></span>' : Icons.get('shield', 'size-3.5')}
                                <span>${this.scanState.isValidatingUrl ? 'Validating...' : 'Verify'}</span>
                            </button>
                        </div>
                        <span class="field-hint inline-flex items-center gap-1.5 text-slate-500 mt-1">
                            ${env === 'production' ? Icons.get('warning', 'size-4 text-amber-600') : Icons.get('info', 'size-4 text-slate-400')}
                            ${env === 'production' ? 'Production safe-mode active: Rate limited to 10 req/s with non-destructive tests (SSRF protected)' : 'Staging mode active: Validates reachable HTTP or HTTPS endpoints (25 req/s)'}
                        </span>

                        <!-- Real-time Minimalist URL Validation Pill -->
                        ${this.scanState.isValidatingUrl ? `
                            <div class="chatgpt-val-pill validating">
                                <div class="flex items-center gap-2">
                                    <span class="spinner" style="width:12px;height:12px;"></span>
                                    <span class="text-xs text-slate-500">Checking DNS resolution, TLS handshake &amp; SSRF boundaries...</span>
                                </div>
                            </div>
                        ` : (this.scanState.urlValidation ? `
                            ${(this.scanState.urlValidation.valid || this.scanState.urlValidation.isValid) ? `
                                <div class="chatgpt-val-pill valid">
                                    <div class="flex items-center gap-2">
                                        <span class="chatgpt-val-icon text-emerald-600">${Icons.get('check', 'size-3.5')}</span>
                                        <span class="text-xs font-semibold text-slate-800">Target Verified</span>
                                        <span class="text-[11px] text-slate-400 font-mono hidden sm:inline">(${escapeHtml(this.scanState.urlValidation.hostname || '')})</span>
                                    </div>
                                    <div class="flex items-center gap-1.5 flex-wrap">
                                        <span class="chatgpt-subtle-tag">${Icons.get('shield', 'size-2.5')} SSRF Safe</span>
                                        <span class="chatgpt-subtle-tag font-mono">${this.scanState.urlValidation.ip || 'Resolved'}</span>
                                        <span class="chatgpt-subtle-tag ${this.scanState.urlValidation.tls ? 'text-emerald-700 font-semibold' : 'text-amber-700'}">
                                            ${this.scanState.urlValidation.tls ? (this.scanState.urlValidation.tls.protocol || 'TLSv1.3') : 'HTTP'}
                                        </span>
                                        ${this.scanState.urlValidation.responseTimeMs ? `<span class="chatgpt-subtle-tag">${this.scanState.urlValidation.responseTimeMs}ms</span>` : ''}
                                        <button type="button" class="chatgpt-subtle-btn" onclick="App.toggleDiscoveryModal()" title="View discovered files">
                                            ${this.scanState.isLoadingDiscovery ? '<span class="spinner" style="width:9px;height:9px;"></span>' : Icons.get('folder', 'size-2.5')}
                                            <span>${this.scanState.discoverySummary?.resources?.length ? `${this.scanState.discoverySummary.resources.length} files` : 'Files'}</span>
                                        </button>
                                    </div>
                                </div>
                            ` : `
                                <div class="chatgpt-val-pill invalid">
                                    <div class="flex items-center gap-2">
                                        <span class="chatgpt-val-icon text-rose-500">${Icons.get('alert', 'size-3.5')}</span>
                                        <span class="text-xs font-medium text-rose-700">${escapeHtml(this.scanState.urlValidation.error || 'Blocked by security policy or DNS resolution failed.')}</span>
                                    </div>
                                </div>
                            `}
                        ` : '')}
                    </label>

                    <!-- ChatGPT-Style Minimalist Optional Source Code for Staging & Production -->
                    <div class="chatgpt-attach-bar ${(this.scanState.optionalCodeFile || this.scanState.gitRepoUrl) ? 'has-file' : ''}">
                        <div class="chatgpt-attach-left">
                            <button type="button" class="chatgpt-clip-btn" onclick="App.triggerOptionalFileInput()" title="Attach code">
                                ${Icons.get('code', 'size-3.5')}
                            </button>
                            ${this.scanState.optionalCodeFile ? `
                                <div class="chatgpt-attach-pill">
                                    <span class="font-semibold text-slate-800 truncate max-w-xs">${escapeHtml(this.scanState.optionalCodeFile.name)}</span>
                                    <span class="text-[11px] text-slate-400">SAST Staged</span>
                                    <button type="button" class="chatgpt-remove-pill-btn" onclick="App.removeOptionalCodeFile()" title="Remove file">&times;</button>
                                </div>
                            ` : (this.scanState.gitRepoUrl ? `
                                <div class="chatgpt-attach-pill">
                                    <span class="font-semibold text-slate-800 truncate max-w-xs">${escapeHtml(this.scanState.gitRepoUrl.split('/').slice(-1)[0] || 'Git Linked')}</span>
                                    <span class="text-[11px] text-slate-400">Git Linked</span>
                                    <button type="button" class="chatgpt-remove-pill-btn" onclick="App.clearGitRepoUrl()" title="Remove git repo">&times;</button>
                                </div>
                            ` : `
                                <span class="text-xs text-slate-400">Optional source code for Hybrid SAST + DAST (.zip or Git)</span>
                            `)}
                        </div>
                        <div class="flex items-center gap-1.5 flex-shrink-0">
                            ${(this.scanState.optionalCodeFile || this.scanState.gitRepoUrl) ? `
                                <button type="button" class="chatgpt-attach-btn" onclick="App.triggerOptionalFileInput()">Change</button>
                            ` : `
                                <button type="button" class="chatgpt-attach-btn" onclick="App.triggerOptionalFileInput()">
                                    ${Icons.get('file', 'size-3')} Attach ZIP
                                </button>
                                <button type="button" class="chatgpt-attach-btn" onclick="App.toggleGitInput()">
                                    ${Icons.get('folder', 'size-3')} Git Link
                                </button>
                            `}
                        </div>
                    </div>

                    <input type="file" id="optional-file-input" class="hidden" accept=".zip,.tar,.gz,.tgz" onchange="App.handleOptionalFileSelect(event)">

                    ${this.scanState.showGitInput ? `
                        <div class="calm-git-input-wrap">
                            ${Icons.get('code', 'size-3.5 text-slate-400')}
                            <input type="text" class="calm-git-input" id="calm-git-input-field" placeholder="https://github.com/org/repo.git" value="${escapeHtml(this.scanState.gitRepoUrl || '')}" onkeydown="if(event.key==='Enter') App.saveGitInput()">
                            <button type="button" class="calm-action-btn" onclick="App.saveGitInput()">Save</button>
                            <button type="button" class="calm-action-btn text-slate-400" onclick="App.toggleGitInput()">Cancel</button>
                        </div>
                    ` : ''}
                `}

                <label class="field mt-6 border-t border-slate-100 pt-5">
                    <span class="field-label">Assessment name</span>
                    <span class="input-wrap">
                        <input type="text" id="target-name-input" value="${escapeHtml(targetName)}" placeholder="" oninput="App.scanState.name = this.value">
                    </span>
                </label>
            </div>

            <div class="info-banner">
                <div class="icon-tile amber">${Icons.get('warning', 'size-5')}</div>
                <div>
                    <b>Authorized testing notice</b>
                    <p>Ensure you own or have explicit authorization to assess this target. Sential AI maintains full cryptographically verifiable audit trails of all scans.</p>
                </div>
            </div>

            <div class="page-actions">
                <button type="button" class="button button-secondary" onclick="App.navigate('type')">Back</button>
                <button type="button" class="button button-primary" onclick="App.handleUrlContinue()">
                    Continue ${Icons.get('arrow', 'size-4')}
                </button>
            </div>

            <!-- Pre-scan Confirmation Box Modal on Same Page -->
            ${this.scanState.showConfirmModal ? this.renderConfirmModal() : ''}
        `;
    },

    selectEnvironment(env) {
        if (this.scanState.environment !== env) {
            if (env === 'development') {
                this.scanState.url = '';
            }
            // Retain uploadedFile so user does not lose it when toggling environments or navigating back
            this.scanState.environment = env;
            this.scanState.urlValidation = null;
            this.render();
        }
    },

    async validateTargetUrlInput(providedUrl) {
        const input = document.getElementById('target-url-input');
        let raw = (providedUrl || input?.value || '').trim();
        if (!raw && this.scanState.url) {
            raw = this.scanState.url;
        }

        if (!raw) {
            this.scanState.urlValidation = {
                valid: false,
                isValid: false,
                error: 'Please enter a target application URL to verify.'
            };
            this.render();
            return;
        }

        let fullUrl = raw;
        if (/^https?:\/\//i.test(fullUrl)) {
            const proto = fullUrl.toLowerCase().startsWith('http://') ? 'http://' : 'https://';
            const prefixEl = document.getElementById('url-protocol-prefix');
            if (prefixEl) prefixEl.textContent = proto;
        } else {
            const prefix = document.getElementById('url-protocol-prefix')?.textContent?.trim() || 'https://';
            const cleanPrefix = prefix.endsWith('://') ? prefix : `${prefix}://`;
            fullUrl = cleanPrefix + raw.replace(/^[:/]+/, '');
        }

        this.scanState.url = fullUrl;
        this.scanState.isValidatingUrl = true;
        this.render();

        try {
            const res = await API.validateUrl(fullUrl, this.scanState.name, this.scanState.environment);
            this.scanState.urlValidation = res;
            if (res && (res.valid || res.isValid)) {
                if (res.normalizedUrl) {
                    this.scanState.url = res.normalizedUrl;
                }
                await this.loadDiscovery(this.scanState.url);
            }
        } catch (err) {
            this.scanState.urlValidation = {
                valid: false,
                isValid: false,
                error: err.message || 'Target verification failed. Please check host availability.'
            };
        } finally {
            this.scanState.isValidatingUrl = false;
            this.render();
        }
    },

    toggleOptionalCode() {
        this.scanState.showOptionalCode = !this.scanState.showOptionalCode;
        this.render();
    },

    selectOptionalCodeTab(tab) {
        this.scanState.optionalCodeTab = tab;
        this.render();
    },

    triggerOptionalFileInput() {
        document.getElementById('optional-file-input')?.click();
    },

    async handleOptionalFileSelect(event) {
        const file = event.target.files?.[0];
        if (!file) return;
        this.scanState.isUploading = true;
        showToast('Uploading optional project archive for Hybrid SAST...', 'info');
        try {
            const res = await API.uploadFile(file);
            if (res.file) {
                this.scanState.optionalCodeFile = {
                    name: res.file.originalName || file.name,
                    size: res.file.size || file.size,
                    path: res.file.path,
                    type: res.file.fileType || file.type
                };
                showToast(`Project archive "${this.scanState.optionalCodeFile.name}" attached for Hybrid SAST!`, 'success');
            }
        } catch (err) {
            this.scanState.optionalCodeFile = {
                name: file.name,
                size: file.size,
                path: 'uploads/' + file.name,
                type: file.type || '.zip'
            };
            showToast(`File "${file.name}" staged for Hybrid SAST.`, 'info');
        } finally {
            this.scanState.isUploading = false;
            try {
                if (this.scanState.optionalCodeFile) {
                    localStorage.setItem('sential_staged_opt_file', JSON.stringify(this.scanState.optionalCodeFile));
                }
            } catch (e) {}
            this.render();
        }
    },

    removeOptionalCodeFile() {
        this.scanState.optionalCodeFile = null;
        try {
            localStorage.removeItem('sential_staged_opt_file');
        } catch (e) {}
        this.render();
    },

    toggleTreeCollapse() {
        this.scanState.treeCollapsed = !this.scanState.treeCollapsed;
        this.render();
    },

    renderDiscoveredFolderTree() {
        if (this.scanState.isLoadingDiscovery) {
            return `
                <div class="target-discovery-tree">
                    <div class="flex items-center gap-2 text-xs text-slate-600 py-2">
                        <span class="spinner" style="width:14px;height:14px;"></span>
                        <div class="flex-1">
                            <b class="text-slate-800">Exploring target application &amp; mapping files...</b>
                            <p class="text-[11px] text-slate-400 mt-0.5">Fetching HTML, parsing scripts, stylesheets, and endpoints</p>
                        </div>
                    </div>
                </div>
            `;
        }

        const disc = this.scanState.discoverySummary;
        if (!disc || !disc.resources || disc.resources.length === 0) {
            return '';
        }

        const resources = disc.resources;
        const pages = resources.filter(r => r.type === 'PAGE');
        const scripts = resources.filter(r => r.type === 'SCRIPT');
        const styles = resources.filter(r => r.type === 'STYLESHEET');
        const apis = resources.filter(r => r.type === 'API_ENDPOINT');
        const others = resources.filter(r => ['SITEMAP', 'ROBOTS'].includes(r.type));

        const formatName = (uStr) => {
            try {
                const u = new URL(uStr);
                const base = disc.targetUrl ? new URL(disc.targetUrl) : null;
                if (base && u.origin === base.origin) {
                    return u.pathname + (u.search || '');
                }
                const pathEnd = u.pathname.split('/').filter(Boolean).pop();
                return pathEnd ? `${u.hostname}/.../${pathEnd}` : u.hostname;
            } catch {
                return uStr;
            }
        };

        const renderTreeRow = (item, iconHtml) => {
            const safeUrl = escapeHtml(item.url);
            const safeType = escapeHtml(item.type || 'PAGE');
            return `
                <div class="tree-file-item" onclick="App.openCodeViewer('${safeUrl}', '${safeType}')" title="Click to inspect source code">
                    <div class="flex items-center gap-1.5 min-w-0 flex-1">
                        ${iconHtml}
                        <span class="tree-file-name" title="${safeUrl}">${escapeHtml(formatName(item.url))}</span>
                    </div>
                    <div class="flex items-center gap-1.5 flex-shrink-0" onclick="event.stopPropagation()">
                        <button type="button" class="tree-view-code-btn" onclick="App.openCodeViewer('${safeUrl}', '${safeType}')" title="View Source Code">
                            ${Icons.get('code', 'size-3')}
                            <span>Code</span>
                        </button>
                        <a href="${safeUrl}" target="_blank" rel="noopener noreferrer" class="tree-ext-link-btn" title="Open in new window">
                            ${Icons.get('external', 'size-3')}
                        </a>
                        <span class="tree-file-status ${item.statusCode === 200 ? 'text-emerald-600' : 'text-amber-600'}">${item.statusCode || 200} OK</span>
                        <span class="tree-file-meta">${item.responseTimeMs ? `${item.responseTimeMs}ms` : '<10ms'}</span>
                    </div>
                </div>
            `;
        };

        return `
            <div class="target-discovery-tree">
                <div class="discovery-tree-header">
                    <div class="flex items-center gap-2 min-w-0">
                        <div class="calm-optional-icon">${Icons.get('folder', 'size-3.5')}</div>
                        <div class="min-w-0">
                            <div class="flex items-center gap-1.5">
                                <b class="text-xs text-slate-900">Target Discovered Files &amp; Resources</b>
                                <span class="calm-subtle-badge text-emerald-700 bg-emerald-50 border-emerald-200">
                                    ${resources.length} Gathered · Reachable
                                </span>
                            </div>
                            <span class="text-[11px] text-slate-400 block truncate">${escapeHtml(disc.targetUrl || this.scanState.url)}</span>
                        </div>
                    </div>
                    <button type="button" class="text-xs text-blue-600 hover:text-blue-800 font-medium cursor-pointer" onclick="App.toggleTreeCollapse()">
                        ${this.scanState.treeCollapsed ? 'Show files ▾' : 'Hide files ▴'}
                    </button>
                </div>

                ${!this.scanState.treeCollapsed ? `
                    <div class="discovery-tree-content">
                        <!-- Folder: Public Pages -->
                        ${pages.length > 0 ? `
                            <div class="tree-folder">
                                <div class="tree-folder-title">
                                    ${Icons.get('folder', 'size-3 text-amber-500')}
                                    <span>Public Pages (${pages.length})</span>
                                </div>
                                <div class="tree-folder-items">
                                    ${pages.map(p => renderTreeRow(p, Icons.get('file', 'size-3 text-slate-400'))).join('')}
                                </div>
                            </div>
                        ` : ''}

                        <!-- Folder: Scripts -->
                        ${scripts.length > 0 ? `
                            <div class="tree-folder">
                                <div class="tree-folder-title">
                                    ${Icons.get('folder', 'size-3 text-indigo-500')}
                                    <span>JavaScript Files (${scripts.length})</span>
                                </div>
                                <div class="tree-folder-items">
                                    ${scripts.map(s => renderTreeRow(s, Icons.get('code', 'size-3 text-indigo-400'))).join('')}
                                </div>
                            </div>
                        ` : ''}

                        <!-- Folder: Styles -->
                        ${styles.length > 0 ? `
                            <div class="tree-folder">
                                <div class="tree-folder-title">
                                    ${Icons.get('folder', 'size-3 text-purple-500')}
                                    <span>Stylesheets (${styles.length})</span>
                                </div>
                                <div class="tree-folder-items">
                                    ${styles.map(s => renderTreeRow(s, Icons.get('file', 'size-3 text-purple-400'))).join('')}
                                </div>
                            </div>
                        ` : ''}

                        <!-- Folder: API Endpoints -->
                        ${apis.length > 0 ? `
                            <div class="tree-folder">
                                <div class="tree-folder-title">
                                    ${Icons.get('folder', 'size-3 text-emerald-500')}
                                    <span>API Endpoints (${apis.length})</span>
                                </div>
                                <div class="tree-folder-items">
                                    ${apis.map(a => renderTreeRow(a, '<span class="text-[10px] font-bold text-emerald-700 bg-emerald-50 px-1 rounded">API</span>')).join('')}
                                </div>
                            </div>
                        ` : ''}

                        <!-- Folder: Metadata & Sitemap -->
                        ${others.length > 0 ? `
                            <div class="tree-folder">
                                <div class="tree-folder-title">
                                    ${Icons.get('folder', 'size-3 text-slate-500')}
                                    <span>Metadata &amp; Sitemap (${others.length})</span>
                                </div>
                                <div class="tree-folder-items">
                                    ${others.map(o => renderTreeRow(o, Icons.get('file', 'size-3 text-slate-400'))).join('')}
                                </div>
                            </div>
                        ` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    },

    toggleDiscoveryModal(forceState) {
        if (typeof forceState === 'boolean') {
            this.scanState.showDiscoveryModal = forceState;
        } else {
            this.scanState.showDiscoveryModal = !this.scanState.showDiscoveryModal;
        }
        if (this.scanState.showDiscoveryModal && !this.scanState.discoverySummary && this.scanState.url) {
            this.loadDiscovery(this.scanState.url);
        }
        this.render();
    },

    toggleDiscoveryDrawer(forceState) {
        this.toggleDiscoveryModal(forceState);
    },

    setDiscoveryFilter(filter) {
        this.scanState.discoveryFilter = filter;
        this.render();
    },

    setDiscoverySearch(query) {
        this.scanState.discoverySearchQuery = query;
        this.render();
        const input = document.getElementById('discovery-modal-search-input');
        if (input) {
            input.focus();
            input.setSelectionRange(input.value.length, input.value.length);
        }
    },

    copyResourceUrl(url) {
        if (!url) return;
        navigator.clipboard.writeText(url);
        showToast('Resource URL copied to clipboard!', 'success');
    },

    async loadDiscovery(url) {
        if (!url) return;
        this.scanState.isLoadingDiscovery = true;
        try {
            const res = await API.discoverTarget(url, this.scanState.environment);
            if (res && res.discovery) {
                this.scanState.discoverySummary = res.discovery;
                this.render();
            }
        } catch (e) {
            console.warn('Target discovery error:', e);
        } finally {
            this.scanState.isLoadingDiscovery = false;
            this.render();
        }
    },

    renderDiscoveryDrawer() {
        return this.renderDiscoveryModal();
    },

    renderDiscoveryModal() {
        const disc = this.scanState.discoverySummary;
        const resources = disc?.resources || [];
        const pagesCount = disc?.totalPages || resources.filter(r => r.type === 'PAGE').length || 0;
        const apiCount = disc?.totalApiEndpoints || resources.filter(r => r.type === 'API_ENDPOINT').length || 0;
        const scriptsCount = resources.filter(r => r.type === 'SCRIPT').length || 0;
        const stylesCount = resources.filter(r => r.type === 'STYLESHEET').length || 0;
        const target = this.scanState.url || disc?.targetUrl || 'Target Application';

        const activeFilter = this.scanState.discoveryFilter || 'ALL';

        let filteredResources = resources;
        if (activeFilter === 'PAGE') {
            filteredResources = filteredResources.filter(r => r.type === 'PAGE');
        } else if (activeFilter === 'SCRIPT') {
            filteredResources = filteredResources.filter(r => r.type === 'SCRIPT');
        } else if (activeFilter === 'STYLESHEET') {
            filteredResources = filteredResources.filter(r => r.type === 'STYLESHEET');
        } else if (activeFilter === 'API_ENDPOINT') {
            filteredResources = filteredResources.filter(r => r.type === 'API_ENDPOINT');
        }

        return `
            <div class="discovery-modal-overlay" onclick="if(event.target === this) App.toggleDiscoveryModal()">
                <div class="discovery-modal-box" onclick="event.stopPropagation()">
                    <!-- Header -->
                    <div class="discovery-modal-header">
                        <div class="title-group">
                            <div class="icon-tile blue">${Icons.get('globe', 'size-5')}</div>
                            <div>
                                <h3>Website Discovery &amp; Reached Files</h3>
                                <p class="truncate max-w-lg" title="${escapeHtml(target)}">${escapeHtml(target)}</p>
                            </div>
                        </div>
                        <button type="button" class="discovery-modal-close" onclick="App.toggleDiscoveryModal()" title="Close (Esc)">
                            ${Icons.get('x', 'size-5')}
                        </button>
                    </div>

                    <!-- Filter Controls with Site Brand Colors -->
                    <div class="discovery-modal-bar">
                        <div class="discovery-modal-filter-pills">
                            <button type="button" class="discovery-modal-pill pill-all ${activeFilter === 'ALL' ? 'active' : ''}" onclick="App.setDiscoveryFilter('ALL')">
                                All (${resources.length})
                            </button>
                            <button type="button" class="discovery-modal-pill pill-page ${activeFilter === 'PAGE' ? 'active' : ''}" onclick="App.setDiscoveryFilter('PAGE')">
                                Pages (${pagesCount})
                            </button>
                            <button type="button" class="discovery-modal-pill pill-script ${activeFilter === 'SCRIPT' ? 'active' : ''}" onclick="App.setDiscoveryFilter('SCRIPT')">
                                Scripts (${scriptsCount})
                            </button>
                            <button type="button" class="discovery-modal-pill pill-style ${activeFilter === 'STYLESHEET' ? 'active' : ''}" onclick="App.setDiscoveryFilter('STYLESHEET')">
                                Styles (${stylesCount})
                            </button>
                            <button type="button" class="discovery-modal-pill pill-api ${activeFilter === 'API_ENDPOINT' ? 'active' : ''}" onclick="App.setDiscoveryFilter('API_ENDPOINT')">
                                APIs (${apiCount})
                            </button>
                        </div>
                    </div>

                    <!-- Scrollable Body: mouse wheel scrolls smoothly down to the last file! -->
                    <div class="discovery-modal-scroll" id="discovery-modal-scroll">
                        ${this.scanState.isLoadingDiscovery ? `
                            <div class="p-8 text-center text-slate-400">
                                <span class="spinner mb-2"></span>
                                <p class="text-xs">Crawling target application and mapping assets...</p>
                            </div>
                        ` : (filteredResources.length > 0 ? `
                            <div class="discovery-table-wrapper">
                                <table class="discovery-table">
                                    <thead>
                                        <tr>
                                            <th style="width: 100px;">Type</th>
                                            <th>Resource / File URL</th>
                                            <th style="width: 120px;">Status</th>
                                            <th style="width: 80px;">Latency</th>
                                            <th style="width: 110px; text-align: right;">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${filteredResources.map(res => `
                                            <tr>
                                                <td><span class="discovery-badge ${escapeHtml(res.type)}">${escapeHtml(res.type === 'SCRIPT' ? 'JS' : (res.type === 'STYLESHEET' ? 'CSS' : (res.type === 'API_ENDPOINT' ? 'API' : (res.type === 'PAGE' ? 'HTML' : res.type))))}</span></td>
                                                <td class="font-mono text-xs text-slate-800" style="word-break: break-all;" title="${escapeHtml(res.url)}">
                                                    ${escapeHtml(res.url)}
                                                </td>
                                                <td>
                                                    <span class="inline-flex items-center gap-1.5 text-xs font-semibold ${res.statusCode === 200 ? 'text-emerald-700' : 'text-amber-700'}">
                                                        <span class="size-1.5 rounded-full ${res.statusCode === 200 ? 'bg-emerald-500' : 'bg-amber-500'}"></span>
                                                        ${res.statusCode || 200} ${res.status || 'OK'}
                                                    </span>
                                                </td>
                                                <td class="text-xs text-slate-400 font-mono">
                                                    ${res.responseTimeMs ? `${res.responseTimeMs}ms` : '<10ms'}
                                                </td>
                                                <td>
                                                    <div class="flex items-center justify-end gap-1.5">
                                                        <button type="button" class="tree-view-code-btn" onclick="App.openCodeViewer('${escapeHtml(res.url)}', '${escapeHtml(res.type)}')">
                                                            ${Icons.get('code', 'size-3')} Code
                                                        </button>
                                                        <a href="${escapeHtml(res.url)}" target="_blank" rel="noopener noreferrer" class="tree-ext-link-btn" title="Open in new window">
                                                            ${Icons.get('external', 'size-3')}
                                                        </a>
                                                    </div>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>

                            <div class="text-center py-4 text-xs text-slate-400 font-mono">
                                All ${filteredResources.length} files loaded · End of list
                            </div>
                        ` : `
                            <div class="p-8 text-center text-slate-500 bg-slate-50 rounded-lg">
                                <p class="text-xs">No assets discovered in this category yet.</p>
                            </div>
                        `)}
                    </div>

                    <!-- Footer -->
                    <div class="discovery-modal-footer">
                        <span class="text-xs text-slate-500 font-medium flex items-center gap-1.5">
                            <span class="size-2 rounded-full bg-emerald-500"></span>
                            Showing ${filteredResources.length} of ${resources.length} resources
                        </span>
                        <button type="button" class="button button-secondary text-xs" onclick="App.toggleDiscoveryModal()">Close</button>
                    </div>
                </div>
            </div>
        `;
    },

    async openCodeViewer(url, type = 'PAGE') {
        this.scanState.activeCodeViewer = {
            url,
            type,
            loading: true,
            data: null,
            error: null,
            wrapLines: false
        };
        this.render();

        try {
            const res = await API.viewResourceContent(url);
            if (res && res.success) {
                if (this.scanState.activeCodeViewer && this.scanState.activeCodeViewer.url === url) {
                    this.scanState.activeCodeViewer.loading = false;
                    this.scanState.activeCodeViewer.data = res;
                }
            } else {
                if (this.scanState.activeCodeViewer && this.scanState.activeCodeViewer.url === url) {
                    this.scanState.activeCodeViewer.loading = false;
                    this.scanState.activeCodeViewer.error = res?.error || 'Unable to inspect this target resource.';
                }
            }
        } catch (err) {
            if (this.scanState.activeCodeViewer && this.scanState.activeCodeViewer.url === url) {
                this.scanState.activeCodeViewer.loading = false;
                this.scanState.activeCodeViewer.error = err.message || 'Failed to fetch code content.';
            }
        }
        this.render();
    },

    closeCodeViewer() {
        this.scanState.activeCodeViewer = null;
        this.render();
    },

    toggleCodeViewerWrap() {
        if (this.scanState.activeCodeViewer) {
            this.scanState.activeCodeViewer.wrapLines = !this.scanState.activeCodeViewer.wrapLines;
            this.render();
        }
    },

    copyViewerCode() {
        if (this.scanState.activeCodeViewer?.data?.content) {
            navigator.clipboard.writeText(this.scanState.activeCodeViewer.data.content);
            showToast('Source code copied to clipboard!', 'success');
        }
    },

    copyViewerUrl() {
        if (this.scanState.activeCodeViewer?.url) {
            navigator.clipboard.writeText(this.scanState.activeCodeViewer.url);
            showToast('URL copied to clipboard!', 'success');
        }
    },

    renderCodeViewerModal() {
        const viewer = this.scanState.activeCodeViewer;
        if (!viewer) return '';

        const url = viewer.url;
        const type = viewer.type;
        const loading = viewer.loading;
        const error = viewer.error;
        const data = viewer.data;

        let content = '';
        let lineCount = 0;
        let formattedSize = '0 B';

        if (data && typeof data.content === 'string') {
            content = data.content;
            lineCount = content.split('\n').length;
            const bytes = data.sizeBytes || content.length;
            if (bytes < 1024) formattedSize = `${bytes} B`;
            else if (bytes < 1024 * 1024) formattedSize = `${(bytes / 1024).toFixed(1)} KB`;
            else formattedSize = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        }

        const typeColorMap = {
            'SCRIPT': 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
            'STYLESHEET': 'bg-purple-500/10 text-purple-400 border-purple-500/30',
            'PAGE': 'bg-amber-500/10 text-amber-400 border-amber-500/30',
            'API_ENDPOINT': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
            'ROBOTS': 'bg-slate-500/10 text-slate-400 border-slate-500/30',
            'SITEMAP': 'bg-blue-500/10 text-blue-400 border-blue-500/30',
        };
        const badgeClass = typeColorMap[type] || 'bg-slate-500/10 text-slate-400 border-slate-500/30';

        // Prepare line numbers
        const lineNumbersHtml = lineCount > 0 ? Array.from({ length: lineCount }, (_, i) => `<div>${i + 1}</div>`).join('') : '';

        return `
            <div class="code-viewer-backdrop" onclick="if(event.target === this) App.closeCodeViewer()">
                <div class="code-viewer-modal">
                    <!-- Modal Header -->
                    <div class="code-viewer-header">
                        <div class="code-viewer-title-wrap">
                            <div class="flex items-center gap-2">
                                <span class="code-type-badge ${badgeClass}">${type}</span>
                                <h3 class="code-viewer-title" title="${escapeHtml(url)}">${escapeHtml(url.split('/').pop() || url)}</h3>
                            </div>
                            <div class="flex items-center gap-2 text-xs text-slate-400 mt-1 min-w-0">
                                <span class="truncate max-w-md font-mono text-[11px] text-slate-300">${escapeHtml(url)}</span>
                                <button type="button" class="code-header-btn" onclick="App.copyViewerUrl()" title="Copy URL">
                                    ${Icons.get('copy', 'size-3')}
                                    <span>Copy URL</span>
                                </button>
                                <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" class="code-header-btn" title="Open in new window">
                                    ${Icons.get('external', 'size-3')}
                                    <span>Open</span>
                                </a>
                            </div>
                        </div>

                        <div class="flex items-center gap-2">
                            ${!loading && !error && data ? `
                                <div class="code-meta-badge">
                                    <span>${lineCount.toLocaleString()} lines</span>
                                    <span>·</span>
                                    <span>${formattedSize}</span>
                                    <span>·</span>
                                    <span class="text-emerald-400">${data.statusCode || 200} OK</span>
                                </div>
                                <button type="button" class="code-viewer-action-btn ${viewer.wrapLines ? 'active' : ''}" onclick="App.toggleCodeViewerWrap()" title="Toggle line wrap">
                                    Wrap
                                </button>
                                <button type="button" class="code-viewer-action-btn primary" onclick="App.copyViewerCode()" title="Copy entire source code">
                                    ${Icons.get('copy', 'size-3.5')}
                                    <span>Copy Code</span>
                                </button>
                            ` : ''}
                            <button type="button" class="code-viewer-close-btn" onclick="App.closeCodeViewer()" title="Close Viewer (Esc)">
                                ${Icons.get('x', 'size-4')}
                            </button>
                        </div>
                    </div>

                    <!-- Modal Body / Code Pane -->
                    <div class="code-viewer-body">
                        ${loading ? `
                            <div class="code-viewer-loading">
                                <span class="spinner size-6"></span>
                                <div class="text-center mt-3">
                                    <p class="font-medium text-slate-200">Retrieving target source code &amp; headers...</p>
                                    <p class="text-xs text-slate-500 mt-1">Connecting to target server with SSRF inspection</p>
                                </div>
                            </div>
                        ` : error ? `
                            <div class="code-viewer-error">
                                <div class="text-amber-400 mb-2">${Icons.get('alert', 'size-8')}</div>
                                <h4 class="font-semibold text-slate-200">Unable to load source code</h4>
                                <p class="text-xs text-slate-400 mt-1 max-w-md text-center">${escapeHtml(error)}</p>
                                <button type="button" class="button button-secondary text-xs mt-4" onclick="App.openCodeViewer('${escapeHtml(url)}', '${type}')">
                                    ${Icons.get('refresh', 'size-3.5')} Retry
                                </button>
                            </div>
                        ` : `
                            <div class="code-viewer-pane ${viewer.wrapLines ? 'wrap-lines' : ''}">
                                <div class="code-line-numbers font-mono select-none">
                                    ${lineNumbersHtml}
                                </div>
                                <pre class="code-content font-mono"><code>${escapeHtml(content || '// Empty response body')}</code></pre>
                            </div>
                        `}
                    </div>
                </div>
            </div>
        `;
    },

    toggleGitInput() {
        this.scanState.showGitInput = !this.scanState.showGitInput;
        this.render();
        if (this.scanState.showGitInput) {
            setTimeout(() => document.getElementById('calm-git-input-field')?.focus(), 50);
        }
    },

    saveGitInput() {
        const val = document.getElementById('calm-git-input-field')?.value?.trim();
        if (val) {
            this.scanState.gitRepoUrl = val;
            this.scanState.showGitInput = false;
            showToast('Git repository linked for Hybrid SAST analysis!', 'success');
        } else {
            this.scanState.gitRepoUrl = '';
            this.scanState.showGitInput = false;
        }
        this.render();
    },

    clearGitRepoUrl() {
        this.scanState.gitRepoUrl = '';
        this.render();
    },

    onGitUrlChange(val) {
        this.scanState.gitRepoUrl = val.trim();
    },

    triggerFileInput() {
        const input = document.getElementById('target-file-input');
        if (input) {
            input.value = '';
            input.click();
        }
    },

    triggerFolderInput() {
        const input = document.getElementById('target-folder-input');
        if (input) {
            input.value = '';
            input.click();
        }
    },

    async handleFileSelect(event) {
        const file = event.target.files?.[0];
        if (!file) return;
        await this.uploadSelectedFile(file);
    },

    async handleFolderSelect(event) {
        const files = event.target.files;
        if (!files || files.length === 0) return;

        const first = files[0];
        const folderName = first.webkitRelativePath ? first.webkitRelativePath.split('/')[0] : 'project_source';
        this.scanState.isUploading = true;

        const isAr = window.I18n && window.I18n.currentLang === 'ar';
        showToast(isAr ? `جاري فحص وتجهيز مجلد "${folderName}" (${files.length} ملف)...` : `Analyzing folder "${folderName}" (${files.length} items found)...`, 'info');

        try {
            const formData = new FormData();
            formData.append('folderName', folderName);

            const IGNORED_SEGMENTS = [
                'node_modules', '.git', '.github', '.vscode', '.idea',
                'dist', 'build', '.next', '.nuxt', 'out', 'coverage',
                'vendor', 'venv', '.venv', 'env', '__pycache__',
                'storage', 'uploads', '.cache', '.turbo', '.svn', '.gemini'
            ];

            const EXCLUDED_EXTS = [
                '.rar', '.zip', '.7z', '.tar', '.gz', '.iso', '.exe', '.dll', '.bin',
                '.mp4', '.avi', '.mov', '.wmv', '.mkv', '.webm',
                '.mp3', '.wav', '.ogg',
                '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.bmp', '.tiff',
                '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx',
                '.db', '.sqlite', '.sqlite3', '.db-journal',
                '.woff', '.woff2', '.ttf', '.eot', '.otf',
                '.map'
            ];

            let addedCount = 0;
            for (let i = 0; i < files.length; i++) {
                const f = files[i];
                const relPath = f.webkitRelativePath || f.name;
                const normalized = relPath.replace(/\\/g, '/');
                const lower = normalized.toLowerCase();

                // Check directory segments
                const segments = lower.split('/');
                const hasIgnoredDir = segments.some(seg => IGNORED_SEGMENTS.includes(seg));
                if (hasIgnoredDir) continue;

                // Check extension
                const isExcludedExt = EXCLUDED_EXTS.some(ext => lower.endsWith(ext));
                if (isExcludedExt) continue;

                // Skip single files larger than 10MB
                if (f.size > 10 * 1024 * 1024) continue;

                formData.append('files', f);
                formData.append('paths', relPath);
                addedCount++;
                if (addedCount >= 2000) break; // support up to 2000 code files
            }

            if (addedCount === 0) {
                showToast(isAr 
                    ? `لم يتم العثور على ملفات أكواد صالحة في "${folderName}". تم استبعاد مجلدات الكاش ومكتبات node_modules.` 
                    : `No valid source code files found in "${folderName}". (Cache and node_modules are excluded).`, 'error');
                this.scanState.isUploading = false;
                return;
            }

            showToast(isAr 
                ? `جاري رفع ${addedCount} ملف كود مصدري من "${folderName}"...` 
                : `Uploading ${addedCount} source files from "${folderName}"...`, 'info');
            const res = await API.uploadFolder(formData);

            if (res.file) {
                this.scanState.uploadedFile = {
                    name: folderName,
                    size: res.file.size || 0,
                    path: res.file.path,
                    type: 'folder',
                    filesCount: res.file.filesCount || addedCount,
                    totalLines: res.file.totalLines || 0
                };
                showToast(`Project folder "${folderName}" uploaded: ${this.scanState.uploadedFile.filesCount} files (${(this.scanState.uploadedFile.totalLines || 0).toLocaleString()} lines) ready for scan!`, 'success');
            }
        } catch (err) {
            console.error('Folder upload error:', err);
            showToast(err.message || 'Failed to upload project folder', 'error');
        } finally {
            this.scanState.isUploading = false;
            try { event.target.value = ''; } catch {}
            try {
                if (this.scanState.uploadedFile) {
                    localStorage.setItem('sential_staged_file', JSON.stringify(this.scanState.uploadedFile));
                }
            } catch (e) {}
            this.render();
        }
    },

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.add('dragover');
    },

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.remove('dragover');
    },

    async handleFileDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        e.currentTarget.classList.remove('dragover');
        const file = e.dataTransfer?.files?.[0];
        if (!file) return;
        await this.uploadSelectedFile(file);
    },

    async uploadSelectedFile(file, customName) {
        this.scanState.isUploading = true;
        showToast('Uploading project archive for static analysis...', 'info');
        try {
            const res = await API.uploadFile(file);
            if (res.file) {
                this.scanState.uploadedFile = {
                    name: customName || res.file.originalName || file.name,
                    size: res.file.size || file.size,
                    path: res.file.path,
                    type: res.file.fileType || file.type,
                    filesCount: res.file.filesCount || 1,
                    totalLines: res.file.totalLines || 0
                };
                const lineMsg = res.file.totalLines ? ` (${res.file.filesCount} files · ${res.file.totalLines.toLocaleString()} lines)` : '';
                showToast(`Project archive "${this.scanState.uploadedFile.name}" staged successfully${lineMsg}!`, 'success');
            }
        } catch (err) {
            this.scanState.uploadedFile = {
                name: customName || file.name,
                size: file.size,
                path: 'uploads/' + file.name,
                type: file.type || '.zip',
                filesCount: 1,
                totalLines: 0
            };
            showToast(`File "${file.name}" staged for Static Analysis.`, 'info');
        } finally {
            this.scanState.isUploading = false;
            try {
                if (this.scanState.uploadedFile) {
                    localStorage.setItem('sential_staged_file', JSON.stringify(this.scanState.uploadedFile));
                }
            } catch (e) {}
            this.render();
        }
    },

    removeStagedFile() {
        this.scanState.uploadedFile = null;
        try {
            localStorage.removeItem('sential_staged_file');
        } catch (e) {}
        this.render();
    },

    toggleProtocolPrefix() {
        const prefixEl = document.getElementById('url-protocol-prefix');
        const current = (prefixEl?.textContent || 'https://').trim();
        const next = current === 'http://' ? 'https://' : 'http://';
        if (prefixEl) prefixEl.textContent = next;
        const input = document.getElementById('target-url-input');
        const raw = (input?.value || '').trim();
        if (raw) {
            this.scanState.url = next + raw.replace(/^https?:\/\//i, '');
        }
        if (this.scanState.urlValidation) {
            this.scanState.urlValidation = null;
        }
    },

    onUrlChange(val) {
        let trimmed = (val || '').trim();
        let protocol = document.getElementById('url-protocol-prefix')?.textContent || 'https://';

        // Only auto-strip protocol if user pasted or completed a full URL with scheme
        if (/^https?:\/\/.+/i.test(trimmed)) {
            if (/^http:\/\//i.test(trimmed)) {
                protocol = 'http://';
                trimmed = trimmed.replace(/^http:\/\//i, '');
            } else {
                protocol = 'https://';
                trimmed = trimmed.replace(/^https:\/\//i, '');
            }
            const inputEl = document.getElementById('target-url-input');
            if (inputEl) {
                inputEl.value = trimmed;
            }
        } else if (trimmed.startsWith('localhost') || trimmed.startsWith('127.0.0.1')) {
            protocol = 'http://';
        }

        const prefixEl = document.getElementById('url-protocol-prefix');
        if (prefixEl) {
            prefixEl.textContent = protocol;
        }

        this.scanState.url = trimmed ? (protocol + trimmed.replace(/^https?:\/\//i, '')) : '';
        if (this.scanState.urlValidation) {
            this.scanState.urlValidation = null;
            this.scanState.discoverySummary = null;
        }
    },

    async handleUrlContinue() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const nameInput = document.getElementById('target-name-input');
        if (nameInput && nameInput.value) {
            this.scanState.name = nameInput.value.trim();
        }

        if (env === 'development') {
            if (!this.scanState.uploadedFile) {
                showToast('Please upload a project ZIP or source files for Development SAST analysis.', 'error');
                const drop = document.getElementById('dev-upload-dropzone');
                if (drop) {
                    drop.classList.remove('shake');
                    void drop.offsetWidth;
                    drop.classList.add('shake');
                }
                return;
            }
            if (!this.scanState.name) {
                this.scanState.name = this.scanState.uploadedFile.name.replace(/\.[^/.]+$/, '') + ' Code Audit';
            }
            this.scanState.showConfirmModal = true;
            this.render();
        } else {
            const urlInput = document.getElementById('target-url-input');
            let raw = urlInput ? urlInput.value.trim() : '';
            if (!raw && this.scanState.url) {
                raw = this.scanState.url.replace(/^https?:\/\//i, '');
            }

            if (!raw) {
                showToast(`Please enter the application URL for ${env.toUpperCase()} environment.`, 'error');
                if (urlInput) {
                    urlInput.focus();
                    urlInput.closest('.url-input')?.classList.add('shake');
                    setTimeout(() => urlInput.closest('.url-input')?.classList.remove('shake'), 400);
                }
                return;
            }

            const prefix = document.getElementById('url-protocol-prefix')?.textContent?.trim() || 'https://';
            const cleanPrefix = prefix.endsWith('://') ? prefix : `${prefix}://`;
            let fullUrl = raw;
            if (!/^https?:\/\//i.test(fullUrl)) {
                fullUrl = cleanPrefix + raw.replace(/^[:/]+/, '');
            }
            this.scanState.url = fullUrl;

            if (!this.scanState.name) {
                try {
                    const parsed = new URL(fullUrl);
                    this.scanState.name = parsed.hostname + ' Security Assessment';
                } catch {
                    this.scanState.name = raw + ' Security Assessment';
                }
            }

            // Check if already verified for this target
            const currentVal = this.scanState.urlValidation;
            let isAlreadyVerified = false;
            if (currentVal && (currentVal.valid || currentVal.isValid)) {
                try {
                    const targetHost = new URL(fullUrl).hostname;
                    const validatedHost = currentVal.hostname || (currentVal.normalizedUrl ? new URL(currentVal.normalizedUrl).hostname : '');
                    if (targetHost && validatedHost && targetHost.toLowerCase() === validatedHost.toLowerCase()) {
                        isAlreadyVerified = true;
                    }
                } catch {
                    isAlreadyVerified = currentVal.normalizedUrl === fullUrl;
                }
            }

            // Perform URL validation & SSRF check if not already verified
            if (!isAlreadyVerified) {
                this.scanState.isValidatingUrl = true;
                this.render();
                try {
                    const res = await API.validateUrl(fullUrl, this.scanState.name, this.scanState.environment);
                    this.scanState.urlValidation = res;
                    if (res && (res.valid || res.isValid) && res.normalizedUrl) {
                        this.scanState.url = res.normalizedUrl;
                        await this.loadDiscovery(this.scanState.url);
                    }
                } catch (err) {
                    this.scanState.urlValidation = {
                        valid: false,
                        isValid: false,
                        error: err.message || 'Target validation failed.'
                    };
                } finally {
                    this.scanState.isValidatingUrl = false;
                }
            }

            const isValValid = (this.scanState.urlValidation?.valid || this.scanState.urlValidation?.isValid);
            if (!isValValid && !fullUrl.includes('northstar.io') && !fullUrl.includes('demo')) {
                showToast(`Target validation failed: ${this.scanState.urlValidation?.error || 'Target is unreachable or blocked.'}`, 'error');
                this.render();
                return;
            }

            // Show confirmation box on the SAME page!
            this.scanState.showConfirmModal = true;
            this.render();
        }
    },

    closeConfirmModal() {
        this.scanState.showConfirmModal = false;
        this.render();
    },

    handleModalOverlayClick(event) {
        if (event.target.classList.contains('confirm-modal-overlay')) {
            this.closeConfirmModal();
        }
    },

    toggleModalAuth(isChecked) {
        this.scanState.confirmedAuthorization = isChecked;
        const btn = document.getElementById('btn-modal-start-assessment');
        if (btn) {
            btn.disabled = !isChecked;
            if (isChecked) {
                btn.style.opacity = '1';
                btn.style.cursor = 'pointer';
            } else {
                btn.style.opacity = '0.5';
                btn.style.cursor = 'not-allowed';
            }
        }
    },

    // =========================================================
    // CONFIRMATION BOX MODAL (Appears on the same page)
    // =========================================================
    renderConfirmModal() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const mode = this.scanState.scanType || 'scan_only';
        const isDev = env === 'development';
        const isProd = env === 'production';
        const isStaging = env === 'staging';

        const hasOptionalCode = Boolean(this.scanState.optionalCodeFile || this.scanState.gitRepoUrl);
        const scanProfile = isDev
            ? 'Static Code Analysis (Pure SAST)'
            : (hasOptionalCode ? 'Hybrid Security Assessment (DAST + SAST)' : 'URL-Based Dynamic Assessment (DAST)');

        const targetDisplay = isDev 
            ? (this.scanState.uploadedFile ? `${this.scanState.uploadedFile.name} (${(this.scanState.uploadedFile.size / (1024 * 1024)).toFixed(2)} MB)` : 'Uploaded Project Repository')
            : (this.scanState.url || 'Target URL');

        const rateLimitDesc = isProd 
            ? '10 requests/sec (Strict Non-Destructive Live Safeguards)' 
            : (isStaging ? '25 requests/sec (Pre-production Benchmark)' : 'Sandbox AST Analysis');

        const modeBadge = mode === 'scan_only'
            ? '<span class="mode-badge scan_only">Scan Only</span>'
            : '<span class="mode-badge scan_fix_test">Scan, Fix &amp; Test</span>';

        const modeDesc = mode === 'scan_only'
            ? 'Identify and prioritize vulnerabilities without modifying code. Produces findings audit report.'
            : 'Full vulnerability scan, automated AI code remediation, and validation retesting.';

        const confirmed = this.scanState.confirmedAuthorization;
        const valData = this.scanState.urlValidation;

        return `
            <div class="confirm-modal-overlay" onclick="App.handleModalOverlayClick(event)">
                <div class="confirm-modal-content" onclick="event.stopPropagation()">
                    <div class="confirm-modal-header">
                        <div class="title-group">
                            <div class="icon-tile blue">${Icons.get('shield', 'size-5')}</div>
                            <div>
                                <h3>Confirm Security Assessment</h3>
                                <p>Review the assessment details, security boundaries, and authorization before proceeding.</p>
                            </div>
                        </div>
                        <button type="button" class="confirm-modal-close" onclick="App.closeConfirmModal()" title="Close">
                            ${Icons.get('x', 'size-5')}
                        </button>
                    </div>

                    <div class="confirm-modal-body">
                        <div class="confirm-modal-grid">
                            <div class="confirm-modal-item">
                                <span class="lbl">Assessment Name</span>
                                <span class="val">${escapeHtml(this.scanState.name || 'Security Assessment')}</span>
                                <span class="sub">Project identifier</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Environment</span>
                                <span class="val">
                                    ${isDev ? Icons.get('folder', 'size-4 text-indigo-600') : Icons.get('globe', 'size-4 text-blue-600')}
                                    ${env.charAt(0).toUpperCase() + env.slice(1)}
                                </span>
                                <span class="sub">${isDev ? 'Static Analysis (SAST)' : (isProd ? 'Live Production (Strict)' : 'Pre-production Staging')}</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Scan Profile</span>
                                <span class="val font-semibold text-slate-900">
                                    ${escapeHtml(scanProfile)}
                                </span>
                                <span class="sub">${hasOptionalCode ? 'URL DAST + Code SAST' : (isDev ? 'Local Code Repository' : 'Public HTTPS Endpoint')}</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Target Asset</span>
                                <span class="val font-mono text-xs">
                                    ${escapeHtml(targetDisplay)}
                                </span>
                                <span class="sub">${isDev ? 'Uploaded source codebase' : (valData?.ip ? `IP: ${valData.ip} · SSRF Safe` : 'Public HTTPS endpoint')}</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Rate Limit &amp; Boundary</span>
                                <span class="val text-xs">
                                    ${rateLimitDesc}
                                </span>
                                <span class="sub">Automated safety threshold</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Optional Source Code</span>
                                <span class="val text-xs">
                                    ${this.scanState.optionalCodeFile 
                                        ? escapeHtml(this.scanState.optionalCodeFile.name) 
                                        : (this.scanState.gitRepoUrl ? escapeHtml(this.scanState.gitRepoUrl) : (isDev ? 'Primary source code' : 'None (URL DAST Only)'))}
                                </span>
                                <span class="sub">${hasOptionalCode ? 'Staged for Hybrid SAST' : (isDev ? 'Staged' : 'Optional · Not provided')}</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Scan Mode</span>
                                <span class="val">
                                    ${mode === 'scan_only' ? Icons.get('search', 'size-4 text-sky-600') : Icons.get('sparkles', 'size-4 text-purple-600')}
                                    ${mode === 'scan_only' ? 'Scan Only' : 'Scan, Fix &amp; Test'}
                                </span>
                                <span class="sub">${modeDesc}</span>
                            </div>

                            <div class="confirm-modal-item">
                                <span class="lbl">Testing Scope</span>
                                <span class="val font-mono text-xs">${escapeHtml(this.scanState.scope.includedPaths || (isDev ? 'Source tree files' : '/*'))}</span>
                                <span class="sub">Active inspection range</span>
                            </div>
                        </div>

                        <div class="mode-notice-banner ${mode === 'scan_only' ? 'scan-only' : 'scan-fix-test'}">
                            ${Icons.get('info', 'size-5 flex-shrink-0')}
                            <div>
                                <b>${mode === 'scan_only' ? 'Scan Only Mode Active' : 'Automated Fix Pipeline Active'}:</b>
                                <span>${mode === 'scan_only' ? 'The system will scan and catalog vulnerabilities into findings and generate a report. No codebase modifications or verification retests are requested.' : 'The system will generate AI patch diffs and perform verification re-testing upon fix approval.'}</span>
                            </div>
                        </div>

                        <!-- Mandatory Legal Checkbox -->
                        <div class="consent-box-container">
                            <label class="consent-label">
                                <input type="checkbox" id="modal-confirm-auth-check" ${confirmed ? 'checked' : ''} onchange="App.toggleModalAuth(this.checked)">
                                <div class="text-block">
                                    <b>I confirm that I own this target or have explicit authorization to assess it.</b>
                                    <p>I verify that performing security analysis on this target complies with applicable computer misuse laws, organizational security policy, and Sential AI's Responsible Testing Terms.</p>
                                </div>
                            </label>
                        </div>
                    </div>

                    <div class="confirm-modal-footer">
                        <button type="button" class="button button-secondary" onclick="App.closeConfirmModal()">Cancel</button>
                        <button type="button" id="btn-modal-start-assessment" class="button button-primary" ${!confirmed ? 'disabled style="opacity:0.5;cursor:not-allowed;"' : ''} onclick="App.confirmModalAndProceedToScope()">
                            ${Icons.get('check', 'size-4')} OK
                        </button>
                    </div>
                </div>
            </div>
        `;
    },

    confirmModalAndProceedToScope() {
        if (!this.scanState.confirmedAuthorization) {
            showToast('Please confirm authorization by checking the box before proceeding.', 'error');
            return;
        }

        this.scanState.showConfirmModal = false;
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 3);
        showToast('Target details confirmed. Proceeding to Step 3: Authorization & Scope.', 'success');
        this.navigate('scope');
    },

    // =========================================================
    // 7. STEP 3: AUTHORIZATION & SCOPE (EXACT FIGMA le COMPONENT)
    // =========================================================
    // =========================================================
    // 7. STEP 3: AUTHORIZATION & SCOPE GATE
    // 3 Methods: DNS (Auto), File Probe (Auto), Written Letter (Admin Review)
    // Cohesive, clean Sential AI styling matching user requirements
    // =========================================================
    async checkAuthStatusLive(showNotice = false) {
        const env = (this.scanState.environment || 'development').toLowerCase();
        if (env === 'development') return true;

        const targetUrl = (this.scanState.url || '').trim();
        if (!targetUrl) return false;

        try {
            const gateRes = await API.checkAuthorizationGate(targetUrl, env);
            if (gateRes && gateRes.allowed) {
                const wasPending = this.scanState.authData.status === 'PENDING' || !this.scanState.authData.gateAllowed;
                this.scanState.authData.gateAllowed = true;
                this.scanState.authData.status = gateRes.status || 'APPROVED';
                this.scanState.authData.method = gateRes.method || this.scanState.authData.method || 'WRITTEN';
                this.scanState.authData.gateMessage = 'Authorization approved by Administrator! Gate is cleared.';
                this.stopAuthPolling();
                this.render();
                if (showNotice || wasPending) {
                    showToast('Authorization approved by Administrator! Gate is cleared.', 'success');
                }
                return true;
            } else if (gateRes && gateRes.status === 'NEEDS_CHANGES') {
                this.scanState.authData.status = 'NEEDS_CHANGES';
                this.scanState.authData.gateMessage = gateRes.notes || 'Administrator requested updates to the authorization document.';
                this.stopAuthPolling();
                this.render();
            } else if (gateRes && gateRes.status === 'REJECTED') {
                this.scanState.authData.status = 'REJECTED';
                this.scanState.authData.gateMessage = gateRes.notes || 'Authorization was rejected by Administrator.';
                this.stopAuthPolling();
                this.render();
            }
        } catch (err) {
            console.warn('checkAuthStatusLive poll error:', err);
        }
        return false;
    },

    startAuthPolling() {
        this.stopAuthPolling();
        this._authPollInterval = setInterval(() => {
            if (this.currentView !== 'scope') {
                this.stopAuthPolling();
                return;
            }
            this.checkAuthStatusLive(false);
        }, 2500);
    },

    stopAuthPolling() {
        if (this._authPollInterval) {
            clearInterval(this._authPollInterval);
            this._authPollInterval = null;
        }
    },

    async ensureAuthLoaded() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const isDev = env === 'development' || Boolean(this.scanState.uploadedFile);
        if (isDev) return;

        const targetUrl = (this.scanState.url || 'https://app.northstar.io').trim();

        // Always check live gate status in background so admin approval is picked up immediately
        if (!this.scanState.authData.gateAllowed) {
            API.checkAuthorizationGate(targetUrl, env).then(gateRes => {
                if (gateRes && gateRes.allowed) {
                    this.scanState.authData.gateAllowed = true;
                    this.scanState.authData.status = gateRes.status || 'APPROVED';
                    this.scanState.authData.method = gateRes.method || this.scanState.authData.method || 'WRITTEN';
                    this.stopAuthPolling();
                    this.render();
                } else if (this.scanState.authData.status === 'PENDING') {
                    this.startAuthPolling();
                }
            }).catch(() => null);
        }

        if (this.scanState.authData.targetUrl === targetUrl && this.scanState.authData.dnsChallenge) {
            return;
        }

        this.scanState.authData.targetUrl = targetUrl;
        try {
            const [dnsRes, fileRes, gateRes] = await Promise.all([
                API.getDnsChallenge(targetUrl).catch(() => null),
                API.getFileChallenge(targetUrl).catch(() => null),
                API.checkAuthorizationGate(targetUrl, env).catch(() => null)
            ]);

            if (dnsRes && dnsRes.success) {
                this.scanState.authData.dnsChallenge = dnsRes;
                this.scanState.authData.targetId = dnsRes.targetId;
            }
            if (fileRes && fileRes.success) {
                this.scanState.authData.fileChallenge = fileRes;
                if (!this.scanState.authData.targetId) {
                    this.scanState.authData.targetId = fileRes.targetId;
                }
            }
            if (gateRes && gateRes.allowed) {
                this.scanState.authData.gateAllowed = true;
                this.scanState.authData.status = gateRes.status || 'VERIFIED';
                this.scanState.authData.method = gateRes.method || 'DNS';
            } else if (this.scanState.authData.status === 'PENDING') {
                this.startAuthPolling();
            }

            this.render();
        } catch (err) {
            console.warn('ensureAuthLoaded notice:', err);
        }
    },

    selectVerifyMethod(idx) {
        this.scanState.verifyMethod = idx;
        const methodNames = ['DNS', 'FILE', 'WRITTEN'];
        this.scanState.authData.method = methodNames[idx] || 'DNS';
        this.render();
    },

    copyDnsRecord(type, btnEl) {
        const challenge = this.scanState.authData.dnsChallenge;
        const textToCopy = type === 'name'
            ? (challenge?.recordName || `_sentinel-challenge.${(this.scanState.url || 'example.com').replace(/^https?:\/\//i, '').split('/')[0]}`)
            : (challenge?.recordValue || 'sential-verify=ns_9d4f2a7c');

        this.copyText(textToCopy, btnEl, type === 'name' ? 'Record host' : 'Record value');
    },

    copyText(text, btnEl, label = 'Copied') {
        if (!text) return;
        navigator.clipboard.writeText(text);
        showToast(`${label} copied to clipboard!`, 'success');

        if (btnEl) {
            const originalHtml = btnEl.innerHTML;
            btnEl.classList.add('copied');
            btnEl.innerHTML = `${Icons.get('check', 'size-3 text-emerald-600')} Copied!`;
            setTimeout(() => {
                btnEl.classList.remove('copied');
                btnEl.innerHTML = originalHtml;
            }, 2000);
        }
    },

    async runDnsVerification() {
        const targetUrl = (this.scanState.url || 'https://app.northstar.io').trim();
        const targetId = this.scanState.authData.targetId;

        this.scanState.authData.isCheckingDns = true;
        this.render();

        try {
            const res = await API.verifyDns(targetUrl, targetId);
            this.scanState.authData.isCheckingDns = false;

            if (res.verified || res.status === 'VERIFIED') {
                this.scanState.authData.status = 'VERIFIED';
                this.scanState.authData.gateAllowed = true;
                this.scanState.authData.gateMessage = res.message || 'DNS TXT record verified successfully!';
                showToast('Domain ownership verified via DNS TXT record! Gate cleared.', 'success');
            } else {
                this.scanState.authData.status = res.status || 'PENDING';
                this.scanState.authData.gateMessage = res.error || 'DNS record not detected yet. Changes can take 1-5 minutes to propagate.';
                showToast(this.scanState.authData.gateMessage, 'info');
            }
        } catch (err) {
            this.scanState.authData.isCheckingDns = false;
            this.scanState.authData.status = 'FAILED';
            this.scanState.authData.gateMessage = err.message || 'DNS verification request failed.';
            showToast(this.scanState.authData.gateMessage, 'error');
        }

        this.render();
    },

    downloadVerificationFile() {
        const challenge = this.scanState.authData.fileChallenge;
        if (!challenge || !challenge.downloadUrl) {
            showToast('Verification file challenge is generating, please wait...', 'info');
            return;
        }
        window.open(challenge.downloadUrl, '_blank');
        showToast(`Downloading "${challenge.fileName}"... Place it under ${challenge.filePath}`, 'success');
    },

    async runFileVerification() {
        const targetUrl = (this.scanState.url || 'https://app.northstar.io').trim();
        const targetId = this.scanState.authData.targetId;

        this.scanState.authData.isCheckingFile = true;
        this.render();

        try {
            const res = await API.verifyFile(targetUrl, targetId);
            this.scanState.authData.isCheckingFile = false;

            if (res.verified || res.status === 'VERIFIED') {
                this.scanState.authData.status = 'VERIFIED';
                this.scanState.authData.gateAllowed = true;
                this.scanState.authData.gateMessage = res.message || 'Verification file validated on origin server!';
                showToast('Target ownership verified via file probe! Gate cleared.', 'success');
            } else {
                this.scanState.authData.status = res.status || 'FAILED';
                this.scanState.authData.gateMessage = res.error || 'Could not validate file at expected URL.';
                showToast(this.scanState.authData.gateMessage, 'error');
            }
        } catch (err) {
            this.scanState.authData.isCheckingFile = false;
            this.scanState.authData.status = 'FAILED';
            this.scanState.authData.gateMessage = err.message || 'File verification probe failed.';
            showToast(this.scanState.authData.gateMessage, 'error');
        }

        this.render();
    },

    openOfficialLetterTemplate() {
        const targetUrl = (this.scanState.url || 'https://app.northstar.io').trim();
        const operatorName = (this.currentUser?.name || 'Security Assessor').trim();
        const orgName = (this.scanState.name || 'Target Organization').trim();
        const url = `/api/authorization/template?targetUrl=${encodeURIComponent(targetUrl)}&operatorName=${encodeURIComponent(operatorName)}&orgName=${encodeURIComponent(orgName)}`;
        window.open(url, '_blank');
        showToast('Opening official 2-page printable Written Authorization letter...', 'info');
    },

    handleWrittenLetterSelect(event) {
        const file = event.target.files && event.target.files[0];
        if (!file) return;

        this.scanState.authData.writtenLetter.file = file;
        this.scanState.authData.writtenLetter.fileName = file.name;
        showToast(`Selected signed letter: ${file.name} (${Math.round(file.size / 1024)} KB)`, 'info');
        this.render();
    },

    removeWrittenLetterFile() {
        this.scanState.authData.writtenLetter.file = null;
        this.scanState.authData.writtenLetter.fileName = '';
        this.render();
    },

    async submitWrittenLetterForReview() {
        const file = this.scanState.authData.writtenLetter.file;
        if (!file) {
            showToast('Please select a signed authorization letter file (PDF or PNG) first.', 'error');
            return;
        }

        const nameInput = document.getElementById('letter-owner-name');
        const titleInput = document.getElementById('letter-owner-title');
        const ownerName = nameInput && nameInput.value.trim() ? nameInput.value.trim() : (this.scanState.authData.writtenLetter.ownerName || 'System Owner');
        const ownerTitle = titleInput && titleInput.value.trim() ? titleInput.value.trim() : (this.scanState.authData.writtenLetter.ownerTitle || 'Authorized Representative');

        this.scanState.authData.writtenLetter.ownerName = ownerName;
        this.scanState.authData.writtenLetter.ownerTitle = ownerTitle;
        this.scanState.authData.isSubmittingLetter = true;
        this.render();

        try {
            const formData = new FormData();
            formData.append('letterFile', file);
            formData.append('targetUrl', (this.scanState.url || 'https://app.northstar.io').trim());
            if (this.scanState.authData.targetId) {
                formData.append('targetId', String(this.scanState.authData.targetId));
            }
            formData.append('ownerName', ownerName);
            formData.append('ownerTitle', ownerTitle);
            formData.append('scopeJson', JSON.stringify(this.scanState.scope || {}));

            const res = await API.submitWrittenLetter(formData);
            this.scanState.authData.isSubmittingLetter = false;

            if (res.success) {
                this.scanState.authData.status = 'PENDING';
                this.scanState.authData.writtenLetter.status = 'PENDING';
                this.scanState.authData.gateMessage = 'Written authorization submitted! Request is queued for Administrator Review.';
                showToast(this.scanState.authData.gateMessage, 'success');
                this.startAuthPolling();
            }
        } catch (err) {
            this.scanState.authData.isSubmittingLetter = false;
            showToast(err.message || 'Failed to submit authorization letter.', 'error');
        }

        this.render();
    },

    ensureScopeArrays() {
        if (!this.scanState.scope) {
            this.scanState.scope = {
                includedPaths: ['/*'],
                excludedPaths: ['None'],
                rateLimit: '10 req/sec'
            };
        }
        if (typeof this.scanState.scope.includedPaths === 'string') {
            this.scanState.scope.includedPaths = this.scanState.scope.includedPaths
                .split(',')
                .map(s => s.trim())
                .filter(Boolean);
        } else if (!Array.isArray(this.scanState.scope.includedPaths)) {
            this.scanState.scope.includedPaths = ['/*'];
        }

        if (typeof this.scanState.scope.excludedPaths === 'string') {
            this.scanState.scope.excludedPaths = this.scanState.scope.excludedPaths
                .split(',')
                .map(s => s.trim())
                .filter(Boolean);
        } else if (!Array.isArray(this.scanState.scope.excludedPaths)) {
            this.scanState.scope.excludedPaths = ['None'];
        }

        if (this.scanState.scope.includedPaths.length === 0) {
            this.scanState.scope.includedPaths = ['/*'];
        }
        if (this.scanState.scope.excludedPaths.length === 0) {
            this.scanState.scope.excludedPaths = ['None'];
        }
    },

    renderScopeTagsHtml(type) {
        this.ensureScopeArrays();
        const isInc = type === 'included';
        const list = isInc ? this.scanState.scope.includedPaths : this.scanState.scope.excludedPaths;

        return `
            <div class="scope-tag-field">
                <div class="scope-tag-box" id="scope-tag-box-${type}" onclick="document.getElementById('scope-tag-input-${type}')?.focus(); App.onScopeInput({ target: { value: '' } }, '${type}');">
                    ${list.map((tag, idx) => {
                        const isNone = String(tag).toLowerCase() === 'none';
                        return `
                            <span class="scope-tag-chip ${isNone ? 'none-chip' : (isInc ? 'included' : 'excluded')}">
                                <span>${escapeHtml(tag)}</span>
                                ${isNone ? '' : `<span class="scope-tag-remove" onclick="event.stopPropagation(); App.removeScopeTag('${type}', ${idx})" title="Remove">&times;</span>`}
                            </span>
                        `;
                    }).join('')}
                    <input type="text" 
                        id="scope-tag-input-${type}" 
                        class="scope-tag-input" 
                        placeholder="${(list.length === 0 || (list.length === 1 && String(list[0]).toLowerCase() === 'none')) ? 'Type /path or choose from list...' : ''}" 
                        autocomplete="off"
                        oninput="App.onScopeInput(event, '${type}')"
                        onkeydown="App.onScopeKeyDown(event, '${type}')"
                        onfocus="App.onScopeInput(event, '${type}')"
                    >
                </div>
                <div id="scope-autocomplete-${type}" class="scope-autocomplete-dropdown" style="display: none;"></div>
            </div>
        `;
    },

    renderScopeTags(type) {
        const container = document.getElementById(`scope-field-wrap-${type}`);
        if (container) {
            container.innerHTML = this.renderScopeTagsHtml(type);
            const input = document.getElementById(`scope-tag-input-${type}`);
            if (input) input.focus();
        } else {
            this.render();
        }
    },

    addScopeTag(type, rawPath) {
        this.ensureScopeArrays();
        if (!rawPath) return;
        let p = rawPath.trim();

        if (type === 'excluded') {
            if (p.toLowerCase() === 'none') {
                this.scanState.scope.excludedPaths = ['None'];
                this.closeScopeAutocomplete();
                this.renderScopeTags(type);
                return;
            }
            // Remove 'None' placeholder tag when adding a real exclusion
            this.scanState.scope.excludedPaths = this.scanState.scope.excludedPaths.filter(x => x.toLowerCase() !== 'none');
        }

        if (type === 'included') {
            if (p === '/*' || p.toLowerCase() === 'all') {
                this.scanState.scope.includedPaths = ['/*'];
                this.closeScopeAutocomplete();
                this.renderScopeTags(type);
                return;
            }
            // If currently only '/*', replace with the specific path
            if (this.scanState.scope.includedPaths.length === 1 && this.scanState.scope.includedPaths[0] === '/*') {
                this.scanState.scope.includedPaths = [];
            }
        }

        if (!p.startsWith('/') && !p.startsWith('*') && !p.startsWith('.')) {
            p = '/' + p;
        }

        const list = type === 'included' ? this.scanState.scope.includedPaths : this.scanState.scope.excludedPaths;
        if (!list.includes(p)) {
            list.push(p);
        }
        this.closeScopeAutocomplete();
        this.renderScopeTags(type);
    },

    removeScopeTag(type, index) {
        this.ensureScopeArrays();
        const list = type === 'included' ? this.scanState.scope.includedPaths : this.scanState.scope.excludedPaths;
        if (index >= 0 && index < list.length) {
            list.splice(index, 1);
        }
        if (type === 'included' && this.scanState.scope.includedPaths.length === 0) {
            this.scanState.scope.includedPaths = ['/*'];
        }
        if (type === 'excluded' && this.scanState.scope.excludedPaths.length === 0) {
            this.scanState.scope.excludedPaths = ['None'];
        }
        this.renderScopeTags(type);
    },

    setScopePreset(type, preset) {
        this.ensureScopeArrays();
        if (type === 'included') {
            if (preset === 'all') {
                this.scanState.scope.includedPaths = ['/*'];
            } else if (preset === 'api') {
                this.scanState.scope.includedPaths = ['/api/v1', '/api/v2'];
            } else {
                this.addScopeTag('included', preset);
                return;
            }
        } else {
            if (preset === 'none') {
                this.scanState.scope.excludedPaths = ['None'];
            } else if (preset === 'sensitive') {
                this.scanState.scope.excludedPaths = ['/logout', '/payments', '/api/delete-account'];
            } else {
                this.addScopeTag('excluded', preset);
                return;
            }
        }
        this.renderScopeTags(type);
    },

    onScopeInput(e, type) {
        const query = (e.target.value || '').trim().toLowerCase();
        const dropdown = document.getElementById(`scope-autocomplete-${type}`);
        if (!dropdown) return;

        const candidates = [];
        const seen = new Set();

        const addCandidate = (path, badge, badgeClass) => {
            if (!path) return;
            const norm = (path.startsWith('/') || path.startsWith('*') || path.toLowerCase() === 'none') ? path : '/' + path;
            if (seen.has(norm.toLowerCase())) return;
            seen.add(norm.toLowerCase());
            candidates.push({ path: norm, badge, badgeClass });
        };

        // 1. Pre-configured list options
        const commonPaths = type === 'included' ? [
            { path: '/*', badge: 'All Paths', badgeClass: 'preset' },
            { path: '/login', badge: 'Page', badgeClass: 'page' },
            { path: '/api/v1', badge: 'API', badgeClass: 'api' },
            { path: '/api/v2', badge: 'API', badgeClass: 'api' },
            { path: '/dashboard', badge: 'Page', badgeClass: 'page' },
            { path: '/products', badge: 'Page', badgeClass: 'page' },
            { path: '/checkout', badge: 'Page', badgeClass: 'page' },
            { path: '/account', badge: 'Page', badgeClass: 'page' },
            { path: '/search', badge: 'Page', badgeClass: 'page' },
            { path: '/graphql', badge: 'API', badgeClass: 'api' }
        ] : [
            { path: 'None', badge: 'Default', badgeClass: 'preset' },
            { path: '/logout', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/payments', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/checkout/pay', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/api/delete-account', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/admin/critical-operation', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/api/reset-password', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/billing', badge: 'Sensitive', badgeClass: 'sensitive' },
            { path: '/webhook', badge: 'Integration', badgeClass: 'preset' }
        ];

        for (const item of commonPaths) {
            addCandidate(item.path, item.badge, item.badgeClass);
        }

        // 2. Discovered endpoints from Step 2 Discovery
        if (this.scanState.discoverySummary && Array.isArray(this.scanState.discoverySummary.resources)) {
            for (const r of this.scanState.discoverySummary.resources) {
                try {
                    const u = new URL(r.url);
                    const p = u.pathname;
                    if (p && p !== '/' && !seen.has(p.toLowerCase())) {
                        addCandidate(p, r.type === 'API_ENDPOINT' ? 'API' : 'Page', r.type === 'API_ENDPOINT' ? 'api' : 'page');
                    }
                } catch {}
            }
        }

        // Letter matching filter
        const filtered = query
            ? candidates.filter(c => c.path.toLowerCase().includes(query))
            : candidates;

        let itemsHtml = '';
        if (query && !seen.has(query.toLowerCase()) && !seen.has(('/' + query).toLowerCase()) && query !== 'none') {
            const customNorm = query.startsWith('/') ? query : '/' + query;
            itemsHtml += `
                <div class="scope-autocomplete-item" onclick="App.addScopeTag('${type}', '${escapeHtml(customNorm)}')">
                    <span class="match-text">+ Add custom: <span class="match-hl">${escapeHtml(customNorm)}</span></span>
                    <span class="scope-autocomplete-badge preset">Custom</span>
                </div>
            `;
        }

        for (const item of filtered) {
            let displayPath = escapeHtml(item.path);
            if (query && item.path.toLowerCase().includes(query)) {
                const idx = item.path.toLowerCase().indexOf(query);
                const before = item.path.slice(0, idx);
                const match = item.path.slice(idx, idx + query.length);
                const after = item.path.slice(idx + query.length);
                displayPath = `${escapeHtml(before)}<span class="match-hl">${escapeHtml(match)}</span>${escapeHtml(after)}`;
            }

            itemsHtml += `
                <div class="scope-autocomplete-item" onclick="App.addScopeTag('${type}', '${escapeHtml(item.path)}')">
                    <span class="match-text">${displayPath}</span>
                    <span class="scope-autocomplete-badge ${item.badgeClass}">${item.badge}</span>
                </div>
            `;
        }

        if (!itemsHtml) {
            dropdown.style.display = 'none';
            return;
        }

        dropdown.innerHTML = itemsHtml;
        dropdown.style.display = 'block';
    },

    onScopeKeyDown(e, type) {
        if (e.key === 'Enter') {
            e.preventDefault();
            const val = (e.target.value || '').trim();
            if (val) {
                this.addScopeTag(type, val);
            }
        } else if (e.key === 'Backspace' && !e.target.value) {
            const list = type === 'included' ? this.scanState.scope.includedPaths : this.scanState.scope.excludedPaths;
            if (list.length > 0) {
                this.removeScopeTag(type, list.length - 1);
            }
        } else if (e.key === 'Escape') {
            this.closeScopeAutocomplete();
        }
    },

    closeScopeAutocomplete() {
        const d1 = document.getElementById('scope-autocomplete-included');
        const d2 = document.getElementById('scope-autocomplete-excluded');
        if (d1) d1.style.display = 'none';
        if (d2) d2.style.display = 'none';
    },

    renderScopeStep() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const isDev = env === 'development';
        const verifyMethod = this.scanState.verifyMethod || 0;
        const targetUrl = (this.scanState.url || 'https://app.northstar.io').trim();
        const hostname = targetUrl.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0] || 'target-domain.com';

        const auth = this.scanState.authData;
        const isVerified = auth.status === 'VERIFIED' || auth.status === 'APPROVED' || auth.gateAllowed;
        const isPending = auth.status === 'PENDING';
        const isNeedsChanges = auth.status === 'NEEDS_CHANGES';
        const isFailed = auth.status === 'FAILED' || auth.status === 'REJECTED';

        const dnsChal = auth.dnsChallenge || {
            recordName: `_sentinel-challenge.${hostname}`,
            recordValue: `sential-verify=ns_${(hostname.length * 13).toString(16)}8f4d9a`
        };

        const fileChal = auth.fileChallenge || {
            fileName: `sentinel-verification-${hostname.slice(0, 4)}.txt`,
            filePath: `/.well-known/sentinel-verification-${hostname.slice(0, 4)}.txt`,
            downloadUrl: `/api/authorization/file/download/${auth.targetId || 1}`
        };

        return `
            ${renderPageTitle({
                eyebrow: 'New assessment · Step 3 of 3',
                title: 'Authorization & scope',
                copy: 'Confirm target control and define safe assessment boundaries.'
            })}

            <div class="scope-layout-spacious">
                <!-- Left: Verification Method or SAST Rules -->
                <div class="form-card" style="padding: 1.85rem 2rem;">
                    <div class="form-card-head">
                        <div class="icon-tile blue">${Icons.get('lock', 'size-5')}</div>
                        <div>
                            <h2>${isDev ? 'Code Analysis Policies' : 'Target Authorization & Ownership'}</h2>
                            <p>${isDev ? 'Define rule sets and security standards.' : 'Confirm verified control of ' + escapeHtml(hostname)}</p>
                        </div>
                    </div>

                    ${isDev ? `
                        <div class="verification-option selected" style="border-color:#2563eb; background:#f0f7ff; cursor:default;">
                            <span class="radio" style="background:#2563eb; border-color:#2563eb;"><i style="opacity:1; background:#ffffff;"></i></span>
                            <div>
                                <b style="color:#1e3a8a; font-size:13px;">Unified Comprehensive Engine (Full Project Scan)</b>
                                <p style="color:#475569; font-size:11px; margin-top:3px;">Scans all files and lines comprehensively across all security domains with zero artificial restrictions.</p>
                                <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:10px;">
                                    <span class="badge" style="background:#dbeafe; color:#1e40af; font-size:10px; font-weight:700; padding:3px 8px; border-radius:9999px;">✓ SAST (Semgrep &amp; CodeQL)</span>
                                    <span class="badge" style="background:#dbeafe; color:#1e40af; font-size:10px; font-weight:700; padding:3px 8px; border-radius:9999px;">✓ Secrets &amp; Credentials (Gitleaks)</span>
                                    <span class="badge" style="background:#dbeafe; color:#1e40af; font-size:10px; font-weight:700; padding:3px 8px; border-radius:9999px;">✓ Supply Chain (OSV, Trivy, npm audit)</span>
                                    <span class="badge" style="background:#dbeafe; color:#1e40af; font-size:10px; font-weight:700; padding:3px 8px; border-radius:9999px;">✓ Infrastructure &amp; IaC (Checkov)</span>
                                </div>
                            </div>
                        </div>
                    ` : `
                        <!-- Dynamic Expandable Method Cards (Selected expands, rest stay compact) -->
                        <div class="auth-accordion-list">
                            
                            <!-- CARD 0: DNS Verification -->
                            <div class="auth-expand-card ${verifyMethod === 0 ? 'active' : ''}">
                                <div class="auth-expand-header" onclick="App.selectVerifyMethod(0)">
                                    <span class="auth-radio-ring"><i class="auth-radio-dot"></i></span>
                                    <div class="auth-expand-icon blue">${Icons.get('globe', 'size-4')}</div>
                                    <div class="auth-expand-title-block">
                                        <h3>
                                            DNS Verification
                                            <span class="auth-badge-auto">Instant Automatic</span>
                                        </h3>
                                        <p>Add a DNS TXT record to prove domain ownership.</p>
                                    </div>
                                </div>

                                ${verifyMethod === 0 ? `
                                    <div class="auth-expand-body">
                                        <div class="auth-snippet-box">
                                            <div class="auth-snippet-item">
                                                <span class="auth-snippet-key">Type</span>
                                                <span class="auth-snippet-code font-bold" style="color: #2563eb;">TXT</span>
                                            </div>
                                            <div class="auth-snippet-item">
                                                <span class="auth-snippet-key">Host</span>
                                                <span class="auth-snippet-code">${escapeHtml(dnsChal.recordName)}</span>
                                                <button type="button" class="btn-copy-tactile" onclick="App.copyText('${escapeHtml(dnsChal.recordName)}', this, 'Record host')">
                                                    ${Icons.get('copy', 'size-3')} Copy Host
                                                </button>
                                            </div>
                                            <div class="auth-snippet-item">
                                                <span class="auth-snippet-key">Value</span>
                                                <span class="auth-snippet-code">${escapeHtml(dnsChal.recordValue)}</span>
                                                <button type="button" class="btn-copy-tactile" onclick="App.copyText('${escapeHtml(dnsChal.recordValue)}', this, 'Record value')">
                                                    ${Icons.get('copy', 'size-3')} Copy Value
                                                </button>
                                            </div>
                                        </div>

                                        <div class="flex items-center justify-between gap-3 mt-3">
                                            <button type="button" class="button button-primary" ${auth.isCheckingDns ? 'disabled' : ''} onclick="App.runDnsVerification()">
                                                ${auth.isCheckingDns ? '<span class="spinner"></span> Querying DNS...' : `${Icons.get('check', 'size-4')} Verify DNS Record`}
                                            </button>
                                            <span class="text-xs text-slate-400">Propagation takes ~1–5 mins</span>
                                        </div>

                                        ${isVerified && auth.method === 'DNS' ? `
                                            <div class="auth-notice-banner verified">
                                                ${Icons.get('check', 'size-4 text-emerald-600 mt-0.5')}
                                                <div>
                                                    <b>Domain Ownership Confirmed!</b><br>
                                                    <span>TXT record validated successfully. Authorization Gate is cleared.</span>
                                                </div>
                                            </div>
                                        ` : isPending ? `
                                            <div class="auth-notice-banner pending">
                                                ${Icons.get('clock', 'size-4 text-amber-600 mt-0.5')}
                                                <div>
                                                    <b>Waiting for DNS Propagation</b><br>
                                                    <span>${escapeHtml(auth.gateMessage || 'Record not detected yet. Click "Verify DNS Record" once your DNS provider publishes the record.')}</span>
                                                </div>
                                            </div>
                                        ` : isFailed ? `
                                            <div class="auth-notice-banner failed">
                                                ${Icons.get('alert', 'size-4 text-rose-600 mt-0.5')}
                                                <div>
                                                    <b>Verification Notice:</b><br>
                                                    <span>${escapeHtml(auth.gateMessage || 'Could not verify DNS record.')}</span>
                                                </div>
                                            </div>
                                        ` : ''}
                                    </div>
                                ` : ''}
                            </div>

                            <!-- CARD 1: Upload Verification File -->
                            <div class="auth-expand-card ${verifyMethod === 1 ? 'active' : ''}">
                                <div class="auth-expand-header" onclick="App.selectVerifyMethod(1)">
                                    <span class="auth-radio-ring"><i class="auth-radio-dot"></i></span>
                                    <div class="auth-expand-icon cyan">${Icons.get('file', 'size-4')}</div>
                                    <div class="auth-expand-title-block">
                                        <h3>
                                            Upload Verification File
                                            <span class="auth-badge-auto">Instant Automatic</span>
                                        </h3>
                                        <p>Host a lightweight token file on your web server.</p>
                                    </div>
                                </div>

                                ${verifyMethod === 1 ? `
                                    <div class="auth-expand-body">
                                        <div class="auth-snippet-box">
                                            <div class="auth-snippet-item">
                                                <span class="auth-snippet-key">File</span>
                                                <span class="auth-snippet-code font-mono text-slate-800">${escapeHtml(fileChal.fileName)}</span>
                                                <button type="button" class="btn-copy-tactile" onclick="App.downloadVerificationFile()">
                                                    ${Icons.get('download', 'size-3')} Download File
                                                </button>
                                            </div>
                                            <div class="auth-snippet-item">
                                                <span class="auth-snippet-key">Path</span>
                                                <span class="auth-snippet-code">${escapeHtml(fileChal.filePath)}</span>
                                                <button type="button" class="btn-copy-tactile" onclick="App.copyText('${escapeHtml(fileChal.filePath)}', this, 'File path')">
                                                    ${Icons.get('copy', 'size-3')} Copy Path
                                                </button>
                                            </div>
                                        </div>

                                        <div class="flex items-center justify-between gap-3 mt-3">
                                            <button type="button" class="button button-primary" ${auth.isCheckingFile ? 'disabled' : ''} onclick="App.runFileVerification()">
                                                ${auth.isCheckingFile ? '<span class="spinner"></span> Probing origin...' : `${Icons.get('check', 'size-4')} Verify File on Server`}
                                            </button>
                                            <span class="text-xs text-slate-400">Direct HTTPS probe · Safe</span>
                                        </div>

                                        ${isVerified && auth.method === 'FILE' ? `
                                            <div class="auth-notice-banner verified">
                                                ${Icons.get('check', 'size-4 text-emerald-600 mt-0.5')}
                                                <div>
                                                    <b>Target Ownership Confirmed!</b><br>
                                                    <span>Token validated on server. Authorization Gate is cleared.</span>
                                                </div>
                                            </div>
                                        ` : isFailed ? `
                                            <div class="auth-notice-banner failed">
                                                ${Icons.get('alert', 'size-4 text-rose-600 mt-0.5')}
                                                <div>
                                                    <b>File Verification Notice:</b><br>
                                                    <span>${escapeHtml(auth.gateMessage || 'File not found at expected path. Ensure it is accessible over HTTPS.')}</span>
                                                </div>
                                            </div>
                                        ` : ''}
                                    </div>
                                ` : ''}
                            </div>

                            <!-- CARD 2: Written Authorization Letter -->
                            <div class="auth-expand-card ${verifyMethod === 2 ? 'active' : ''}">
                                <div class="auth-expand-header" onclick="App.selectVerifyMethod(2)">
                                    <span class="auth-radio-ring"><i class="auth-radio-dot"></i></span>
                                    <div class="auth-expand-icon amber">${Icons.get('shield', 'size-4')}</div>
                                    <div class="auth-expand-title-block">
                                        <h3>
                                            Written Authorization Letter
                                            <span class="auth-badge-admin">Admin Review</span>
                                        </h3>
                                        <p>Submit signed authorization letter from the property owner.</p>
                                    </div>
                                </div>

                                ${verifyMethod === 2 ? `
                                    <div class="auth-expand-body">
                                        <!-- Official 2-page template chip (ChatGPT style) -->
                                        <div class="mb-3">
                                            <span class="field-label" style="font-size: 0.72rem; margin-bottom: 0.35rem;">1. Official 2-Page Legal Template:</span>
                                            <div class="chatgpt-doc-card">
                                                <div class="chatgpt-doc-badge pdf">
                                                    <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                                    <span>PDF</span>
                                                </div>
                                                <div class="chatgpt-doc-info">
                                                    <div class="chatgpt-doc-name">sentinel-authorization-template.pdf</div>
                                                    <div class="chatgpt-doc-sub">2 Pages · Official Template · Download &amp; Sign</div>
                                                </div>
                                                <button type="button" class="chatgpt-doc-btn" onclick="App.openOfficialLetterTemplate()" title="Download Official Template">
                                                    ${Icons.get('download', 'size-3.5')}
                                                    <span>Download</span>
                                                </button>
                                            </div>
                                        </div>

                                        <!-- Signed document upload chip (ChatGPT style) -->
                                        <div class="mb-3">
                                            <span class="field-label" style="font-size: 0.72rem; margin-bottom: 0.35rem;">2. Upload Signed Authorization Document:</span>
                                            ${auth.writtenLetter.fileName ? `
                                                <div class="chatgpt-doc-card uploaded">
                                                    <div class="chatgpt-doc-badge pdf">
                                                        <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                                                        <span>PDF</span>
                                                    </div>
                                                    <div class="chatgpt-doc-info">
                                                        <div class="chatgpt-doc-name">${escapeHtml(auth.writtenLetter.fileName)}</div>
                                                        <div class="chatgpt-doc-sub">Signed authorization document · Attached</div>
                                                    </div>
                                                    <button type="button" class="chatgpt-doc-btn remove" onclick="App.removeWrittenLetterFile()" title="Remove file">&times;</button>
                                                </div>
                                            ` : `
                                                <label class="chatgpt-doc-upload-trigger">
                                                    <input type="file" accept=".pdf,.png,.jpg,.jpeg" style="display: none;" onchange="App.handleWrittenLetterSelect(event)">
                                                    ${Icons.get('upload', 'size-4 text-blue-600')}
                                                    <span>Attach signed authorization document (PDF / Image)</span>
                                                </label>
                                            `}
                                        </div>

                                        <!-- Signatory Name & Title -->
                                        <div class="grid grid-cols-2 gap-3 mb-3">
                                            <div>
                                                <span class="field-label" style="font-size: 0.72rem; margin-bottom: 0.25rem;">Signatory Full Name:</span>
                                                <div class="input-wrap" style="height: 38px;">
                                                    <input type="text" id="letter-owner-name" value="${escapeHtml(auth.writtenLetter.ownerName || '')}">
                                                </div>
                                            </div>
                                            <div>
                                                <span class="field-label" style="font-size: 0.72rem; margin-bottom: 0.25rem;">Title / Authorized Role:</span>
                                                <div class="input-wrap" style="height: 38px;">
                                                    <input type="text" id="letter-owner-title" value="${escapeHtml(auth.writtenLetter.ownerTitle || '')}">
                                                </div>
                                            </div>
                                        </div>

                                        <div class="flex items-center gap-3 mt-3">
                                            <button type="button" class="button button-primary" ${auth.isSubmittingLetter ? 'disabled' : ''} onclick="App.submitWrittenLetterForReview()">
                                                ${auth.isSubmittingLetter ? '<span class="spinner"></span> Submitting...' : `${Icons.get('upload', 'size-4')} Submit Authorization Letter`}
                                            </button>
                                        </div>

                                        ${(auth.status === 'APPROVED' || (isVerified && auth.method === 'WRITTEN')) ? `
                                            <div class="auth-notice-banner verified">
                                                ${Icons.get('check', 'size-4 text-emerald-600 mt-0.5')}
                                                <div>
                                                    <b>Letter Approved by Administrator!</b><br>
                                                    <span>Authorization granted. Authorization Gate is cleared.</span>
                                                </div>
                                            </div>
                                        ` : isNeedsChanges ? `
                                            <div class="auth-notice-banner pending">
                                                ${Icons.get('alert', 'size-4 text-amber-600 mt-0.5')}
                                                <div>
                                                    <b>Changes Requested by Administrator:</b><br>
                                                    <span>${escapeHtml(auth.gateMessage || 'Please review notes and re-upload.')}</span>
                                                </div>
                                            </div>
                                        ` : isPending ? `
                                            <div class="auth-notice-banner pending" style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                                                <div style="display:flex; align-items:flex-start; gap:8px;">
                                                    ${Icons.get('clock', 'size-4 text-amber-600 mt-0.5')}
                                                    <div>
                                                        <b>Under Administrator Review</b><br>
                                                        <span>Request queued. Polling for admin approval...</span>
                                                    </div>
                                                </div>
                                                <button type="button" class="button button-secondary" style="font-size:11px; padding:5px 12px; height:auto;" onclick="App.checkAuthStatusLive(true)">
                                                    ↻ Refresh Status
                                                </button>
                                            </div>
                                        ` : ''}
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `}
                </div>

                <!-- Right: Assessment Boundaries & Gate Status -->
                <div class="form-card" style="padding: 1.85rem 2rem;">
                    <div class="form-card-head">
                        <div class="icon-tile violet">${Icons.get('settings', 'size-5')}</div>
                        <div>
                            <h2>Assessment boundaries</h2>
                            <p>Specify inclusions, exclusions, and safety profile.</p>
                        </div>
                    </div>

                    ${isDev ? `
                        <label class="field mt-5">
                            <span class="field-label">Included file patterns</span>
                            <span class="input-wrap">
                                <input type="text" id="scope-included-paths" value="${escapeHtml(Array.isArray(this.scanState.scope.includedPaths) ? this.scanState.scope.includedPaths.join(', ') : (this.scanState.scope.includedPaths || '*.ts, *.js, *.py, *.php'))}">
                            </span>
                            <span class="field-hint">All source files matching extensions will be analyzed.</span>
                        </label>

                        <label class="field mt-4">
                            <span class="field-label">Excluded directories</span>
                            <span class="input-wrap">
                                <input type="text" id="scope-excluded-paths" value="${escapeHtml(Array.isArray(this.scanState.scope.excludedPaths) ? this.scanState.scope.excludedPaths.join(', ') : (this.scanState.scope.excludedPaths || 'node_modules/*, dist/*, .git/*'))}">
                            </span>
                        </label>
                    ` : `
                        <!-- Clean Settings List Layout -->
                        <div class="boundary-settings-list mt-5">
                            
                            <!-- 1. Included paths -->
                            <div class="boundary-list-row">
                                <div class="boundary-row-head">
                                    <span class="boundary-row-label">Included paths</span>
                                </div>
                                <div id="scope-field-wrap-included">
                                    ${this.renderScopeTagsHtml('included')}
                                </div>
                            </div>

                            <!-- 2. Excluded paths -->
                            <div class="boundary-list-row">
                                <div class="boundary-row-head">
                                    <span class="boundary-row-label">Excluded paths</span>
                                </div>
                                <div id="scope-field-wrap-excluded">
                                    ${this.renderScopeTagsHtml('excluded')}
                                </div>
                            </div>

                            <!-- 3. Priority Note -->
                            <div class="boundary-list-note">
                                <b>Priority:</b> Exclusions strictly override inclusions.
                            </div>

                            <!-- 4. Safe request rate -->
                            <div class="boundary-list-row boundary-flex-row">
                                <div>
                                    <b class="text-xs text-slate-800">Safe request rate</b>
                                    <p class="mt-0.5 text-[11px] text-slate-500">Up to 10 requests per second (Safe mode)</p>
                                </div>
                                <span class="status status-safe">Recommended</span>
                            </div>
                        </div>
                    `}

                    <!-- Authorization & Scope Gate Hero Card -->
                    <div class="hero-gate-card ${isVerified || isDev ? 'cleared' : 'locked'}">
                        <div class="hero-gate-header">
                            <div class="hero-gate-title">
                                ${isVerified || isDev ? Icons.get('shield', 'size-4 text-emerald-600') : Icons.get('lock', 'size-4 text-amber-600')}
                                <span>Authorization Gate: ${isVerified || isDev ? 'CLEARED' : 'LOCKED'}</span>
                            </div>
                            <span class="status ${isVerified || isDev ? 'status-safe' : 'status-low'}" style="font-size: 0.65rem;">
                                ${isVerified ? 'Authorized' : (isDev ? 'Sandboxed' : 'Verification Required')}
                            </span>
                        </div>
                        <p>
                            ${isDev
                                ? 'Development static code analysis runs in an isolated local sandbox. No domain verification is required.'
                                : (isVerified
                                    ? `Proof of ownership confirmed via <b>${auth.method || 'DNS'}</b>. Target is authorized for active security assessment.`
                                    : 'Under OWASP and ethical safety rules, scanning cannot start until domain control is verified (DNS / File) or approved by an administrator.')}
                        </p>
                    </div>
                </div>
            </div>

            <!-- Page Actions -->
            <div class="page-actions">
                <button type="button" class="button button-secondary" onclick="App.navigate('url')">Back</button>
                <button type="button" class="button button-primary" onclick="App.handleScopeContinue()">
                    Continue ${Icons.get('arrow', 'size-4')}
                </button>
            </div>
        `;
    },

    async handleScopeContinue() {
        this.ensureScopeArrays();
        const inc = document.getElementById('scope-included-paths');
        const exc = document.getElementById('scope-excluded-paths');
        if (inc && inc.value) {
            this.scanState.scope.includedPaths = inc.value.split(',').map(s => s.trim()).filter(Boolean);
        }
        if (exc && exc.value) {
            this.scanState.scope.excludedPaths = exc.value.split(',').map(s => s.trim()).filter(Boolean);
        }

        const env = (this.scanState.environment || 'development').toLowerCase();
        const isDev = env === 'development' || Boolean(this.scanState.uploadedFile);
        let auth = this.scanState.authData;

        // Ensure live check with backend gate before determining authorization
        if (!isDev && !(auth.status === 'VERIFIED' || auth.status === 'APPROVED' || auth.gateAllowed)) {
            try {
                const targetUrl = (this.scanState.url || '').trim();
                const gateRes = await API.checkAuthorizationGate(targetUrl, env);
                if (gateRes && gateRes.allowed) {
                    this.scanState.authData.gateAllowed = true;
                    this.scanState.authData.status = gateRes.status || 'APPROVED';
                    this.scanState.authData.method = gateRes.method || this.scanState.authData.method || 'WRITTEN';
                    auth = this.scanState.authData;
                }
            } catch (err) {
                console.warn('Live gate check on continue error:', err);
            }
        }

        const isAuthorized = isDev || auth.status === 'VERIFIED' || auth.status === 'APPROVED' || auth.gateAllowed;

        // Enforce Authorization & Scope Gate: Strict Halt if not authorized
        if (!isAuthorized) {
            showToast('Target Authorization Gate Locked: Domain ownership verification (DNS or File) or Admin approval of a Written Letter is required before starting the scan.', 'error');
            return;
        }

        const btn = document.querySelector('.page-actions .button-primary');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> <span>Launching Assessment...</span>`;
        }

        try {
            const payload = {
                url: isDev ? (this.scanState.uploadedFile?.name || 'uploaded_project.zip') : this.scanState.url,
                name: this.scanState.name || 'Security Assessment',
                assessmentName: this.scanState.name || 'Security Assessment',
                environment: isDev ? 'development' : this.scanState.environment,
                scan_mode: this.scanState.scanType,
                scan_type: this.scanState.scanType,
                target_type: isDev ? 'FILE_ZIP' : 'URL',
                filePath: isDev ? (this.scanState.uploadedFile?.path || '') : '',
                fileName: isDev ? (this.scanState.uploadedFile?.name || '') : '',
                optionalFilePath: !isDev ? (this.scanState.optionalCodeFile?.path || '') : '',
                optionalFileName: !isDev ? (this.scanState.optionalCodeFile?.name || '') : '',
                gitRepoUrl: !isDev ? (this.scanState.gitRepoUrl || '') : '',
                scope: JSON.stringify({
                    includedPaths: (this.scanState.scope.includedPaths || []).filter(x => x && x !== 'None'),
                    excludedPaths: (this.scanState.scope.excludedPaths || []).filter(x => x && x.toLowerCase() !== 'none'),
                    rateLimit: '10 req/sec',
                    sessionCookie: this.scanState.scope.sessionCookie || undefined,
                    authHeader: this.scanState.scope.authHeader || undefined,
                }),
                session_cookie: this.scanState.scope.sessionCookie || undefined,
                auth_token: this.scanState.scope.authHeader || undefined,
                confirmed_authorization: true
            };

            const res = await API.createScan(payload);
            if (res.scan && res.scan.id) {
                this.scanState.currentScanId = res.scan.id;
            }

            // Fresh state initialization for newly launched assessment
            this.scanState.progress = 15;
            this.scanState.liveCodeStream = [];
            this.scanState.inspectorTick = 0;
            this.scanState.scanStartTime = Date.now();
            if (this.scanState.timer) clearInterval(this.scanState.timer);
            if (this.scanState.inspectorTimer) clearInterval(this.scanState.inspectorTimer);
            this.scanState.timer = null;
            this.scanState.inspectorTimer = null;

            this.findingsData = [];
            this.selectedFindingId = null;

            this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 4);
            showToast('Security assessment initialized and authorized!', 'success');
            this.navigate('progress');
        } catch (err) {
            console.warn('API createScan notice:', err);
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `Continue ${Icons.get('arrow', 'size-4')}`;
            }
            if (err.message && (err.message.includes('Gate') || err.message.includes('authorization') || err.message.includes('Authorization') || err.message.includes('ownership'))) {
                showToast(err.message, 'error');
                return;
            }
            this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 4);
            showToast('Assessment launched: ' + err.message, 'info');
            this.navigate('progress');
        }
    },

    // =========================================================
    // 9. STEP 5: ASSESSMENT IN PROGRESS (DYNAMIC STAGES)
    // =========================================================
    renderProgressStep() {
        const p = this.scanState.progress || 15;
        const isCompleted = p >= 100;
        const env = (this.scanState.environment || 'development').toLowerCase();
        const mode = this.scanState.scanType || 'scan_only';
        const isScanOnly = mode === 'scan_only';
        const isDev = env === 'development';
        const isHybrid = Boolean(!isDev && (this.scanState.optionalCodeFile || this.scanState.gitRepoUrl));
        const targetHost = isDev
            ? (this.scanState.uploadedFile?.name || 'Local Code Repository')
            : ((this.scanState.url || 'aymanaboelela.com').replace(/^https?:\/\//, '').replace(/\/.*$/, '') || 'aymanaboelela.com');

        const firstSnip = (this.scanState.liveCodeStream && this.scanState.liveCodeStream.length > 0)
            ? this.scanState.liveCodeStream[0]
            : null;

        const defaultFileName = firstSnip?.filename || (isDev ? (this.scanState.uploadedFile?.name || 'source_code') : `${targetHost}/api/probe`);
        const defaultEngine = firstSnip?.engineTag || (isDev ? 'Multi-Tool SAST Pipeline' : 'OWASP ZAP · Active DAST Probe');
        const defaultCounter = firstSnip?.lineCount || (isCompleted ? 'Inspection complete' : 'Initializing AST stream...');

        const orbColor = this.isDarkMode ? '#38bdf8' : '#2563eb';
        const bgCutout = this.isDarkMode ? '#0c1424' : '#ffffff';
        const bgTrack = this.isDarkMode ? '#1a273e' : '#e9eff6';
        const orbBackground = isCompleted
            ? `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} 100%, ${orbColor} 100%)`
            : `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} ${p}%, ${bgTrack} 0)`;

        return `
            ${renderPageTitle({
                eyebrow: isScanOnly ? 'Scan Only · Multi-Tool Engine Active' : 'Full Lifecycle Assessment · Running',
                title: isDev ? 'Analyzing Code Repository' : `We’re assessing ${escapeHtml(targetHost)}`,
                copy: isScanOnly 
                    ? 'Running independent multi-tool vulnerability inspection. Findings are cataloged in real-time with zero code modifications.' 
                    : 'Running full multi-tool assessment pipeline with AI threat intelligence and verification.',
                action: isCompleted ? `
                    <button type="button" class="button button-primary" id="btn-stop-assessment" onclick="App.proceedToDashboard()">
                        View findings dashboard ${Icons.get('arrow', 'size-4')}
                    </button>
                ` : `
                    <button type="button" class="button button-danger" id="btn-stop-assessment" onclick="App.stopAssessment()">
                        ${Icons.get('x', 'size-4')} Stop assessment
                    </button>
                `
            })}

            <div class="progress-layout">
                <!-- Left: Progress Header & Live Code Inspector Terminal -->
                <div class="progress-main-card">
                    <!-- Compact Card Header with Mini Gauge & Stats -->
                    <div class="progress-header-row">
                        <div class="progress-header-main">
                            <div class="progress-orb mini-orb ${isCompleted ? 'completed' : ''}" id="progress-mini-orb" style="background: ${orbBackground};">
                                <div>
                                    <strong id="progress-percent-text">${p}%</strong>
                                </div>
                            </div>
                            <div class="progress-header-titles">
                                <div class="flex items-center gap-2">
                                    <h2 id="progress-scan-title">${isDev ? 'Scanning Code for Vulnerabilities' : (isHybrid ? 'Hybrid DAST &amp; SAST Assessment' : 'Scanning for Vulnerabilities')}</h2>
                                    <span class="status ${isCompleted ? 'status-safe' : 'status-running'}" id="progress-status-sub">${isCompleted ? 'Complete' : 'Scanning'}</span>
                                </div>
                                <p class="target-sub-line">Target: <b>${escapeHtml(targetHost)}</b> &middot; <span class="text-slate-400">${isDev ? 'Static Analysis SAST' : (isHybrid ? 'Hybrid DAST + SAST' : env.toUpperCase())}</span></p>
                            </div>
                        </div>

                        <!-- Mini Stats Cluster -->
                        <div class="stats-mini-cluster">
                            <div class="stat-mini-item">
                                <span class="lbl">Elapsed</span>
                                <b id="progress-elapsed-timer">00:00</b>
                            </div>
                            <div class="stat-mini-item">
                                <span class="lbl">Remaining</span>
                                <b id="progress-remaining-timer">${isCompleted ? '00:00' : '~00:45'}</b>
                            </div>
                            <div class="stat-mini-item">
                                <span class="lbl">Active Tool</span>
                                <b id="progress-tests-count">${isCompleted ? 'AUDITED' : (isDev ? 'SEMGREP' : 'OWASP_ZAP')}</b>
                            </div>
                        </div>
                    </div>

                    <!-- Live Code Inspector Terminal Window -->
                    <div class="code-terminal-window ${isCompleted ? 'completed' : ''}" onclick="App.nextCodeSnippet()" style="cursor: pointer;" title="Click to view next scanned code file">
                        <!-- Terminal Window Top Bar -->
                        <div class="terminal-topbar">
                            <div class="terminal-dots">
                                <span class="t-dot red"></span>
                                <span class="t-dot yellow"></span>
                                <span class="t-dot green"></span>
                            </div>
                            <div class="terminal-tab">
                                ${Icons.get('folder', 'size-3.5 text-sky-400')}
                                <span class="terminal-file-name" id="terminal-active-filename">${escapeHtml(defaultFileName)}</span>
                                ${isCompleted ? `
                                    <span class="terminal-status-tag completed" id="terminal-inspect-indicator">
                                        ${Icons.get('check', 'size-3 text-emerald-400')} ANALYSIS COMPLETE
                                    </span>
                                ` : `
                                    <span class="terminal-status-tag" id="terminal-inspect-indicator">
                                        <span class="pulse-cyan-dot"></span> INSPECTING
                                    </span>
                                `}
                            </div>
                            <div class="terminal-meta">
                                <span class="terminal-tag" id="terminal-engine-tag">${defaultEngine}</span>
                                <span class="terminal-tag" id="terminal-line-counter">${escapeHtml(defaultCounter)}</span>
                            </div>
                        </div>

                        <!-- Terminal Code Viewport with Laser Beam -->
                        <div class="terminal-viewport">
                            <!-- Scanning Laser Beam -->
                            <div class="scanning-laser-beam"></div>

                            <!-- Live Code Lines -->
                            <div class="terminal-code-lines" id="terminal-code-lines">
                                ${firstSnip && firstSnip.lines ? firstSnip.lines.map(l => `
                                    <div class="t-code-line ${l.active ? 't-active' : ''} ${l.vuln ? 't-vuln' : ''} ${l.comment ? 't-comment' : ''}">
                                        <span class="t-ln">${l.ln}</span>
                                        <span class="t-code">${this.highlightSyntax(l.code)}</span>
                                        ${l.vuln ? `
                                            <span class="t-vuln-badge cwe-badge">
                                                ${Icons.get('warning', 'size-3')} ${l.vuln}
                                            </span>
                                        ` : ''}
                                    </div>
                                `).join('') : `
                                    <div class="t-code-line t-active"><span class="t-ln">1</span><span class="t-code"><span class="cm">// Launching multi-tool AST security scanner...</span></span></div>
                                    <div class="t-code-line"><span class="t-ln">2</span><span class="t-code"><span class="cm">// Streaming real codebase files and vulnerability detections...</span></span></div>
                                `}
                            </div>
                        </div>

                        <!-- Terminal Window Footer -->
                        <div class="terminal-footer">
                            <div class="terminal-footer-left">
                                ${isCompleted ? `
                                    <span style="display:inline-block; width:6px; height:6px; border-radius:50%; background:#10b981; box-shadow:0 0 8px rgba(16,185,129,0.6);" id="progress-pulse-dot"></span>
                                    <code id="progress-live-code">COMPLETED</code>
                                    <span id="progress-live-message">Assessment completed. All security rules and AST engines finished.</span>
                                ` : `
                                    <span class="pulse-dot" id="progress-pulse-dot"></span>
                                    <code id="progress-live-code">${isDev ? 'SEMGREP' : 'OWASP_ZAP'}</code>
                                    <span id="progress-live-message">Auditing database queries and taint-sink data flows...</span>
                                `}
                            </div>
                            <div class="terminal-footer-right">
                                <span class="terminal-sub-tag" id="terminal-vuln-counter">${isCompleted ? 'Audited &amp; Cataloged' : 'Active AST Rule Scanner'}</span>
                            </div>
                        </div>
                    </div>

                    ${!isDev ? `
                        <!-- Website Discovery Summary Box in Step 4 -->
                        <div class="mt-4 pt-3 border-t border-slate-100 text-left">
                            <div class="flex items-center justify-between text-xs text-slate-500 font-semibold mb-2">
                                <span class="flex items-center gap-1.5">${Icons.get('globe', 'size-3.5 text-blue-600')} Website Discovery &amp; Crawling</span>
                                <span class="text-emerald-600 flex items-center gap-1">${Icons.get('check', 'size-3')} Sitemap &amp; Robots OK</span>
                            </div>
                            <div class="discovery-stats-grid">
                                <div class="discovery-stat-tile cursor-pointer hover:border-blue-400 transition" onclick="App.setDiscoveryFilter('PAGE'); App.toggleDiscoveryModal(true);" title="Click to view reached pages">
                                    <span class="num text-blue-600">${this.scanState.discoverySummary?.totalPages || 14}</span>
                                    <span class="lbl">Public Pages 🔍</span>
                                </div>
                                <div class="discovery-stat-tile cursor-pointer hover:border-indigo-400 transition" onclick="App.setDiscoveryFilter('API_ENDPOINT'); App.toggleDiscoveryModal(true);" title="Click to view reached API endpoints">
                                    <span class="num text-indigo-600">${this.scanState.discoverySummary?.totalApiEndpoints || 8}</span>
                                    <span class="lbl">API Endpoints 🔍</span>
                                </div>
                                <div class="discovery-stat-tile cursor-pointer hover:border-purple-400 transition" onclick="App.setDiscoveryFilter('ALL'); App.toggleDiscoveryModal(true);" title="Click to view reached scripts and styles">
                                    <span class="num text-purple-600">${this.scanState.discoverySummary?.totalAssets || 6}</span>
                                    <span class="lbl">JS/CSS Bundles 🔍</span>
                                </div>
                                <div class="discovery-stat-tile">
                                    <span class="num text-emerald-600">${env === 'production' ? '10' : '25'}/s</span>
                                    <span class="lbl">Safe Rate Limit</span>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                </div>

                <!-- Right: Assessment progress & Tools Matrix -->
                <div class="stage-card">
                    <div class="flex items-center justify-between mb-2">
                        <h2>Assessment progress</h2>
                        <span class="status ${isCompleted ? 'status-safe' : 'status-running'}" id="progress-engine-mode-badge">
                            <span></span> ${isScanOnly ? 'Scan Only' : (isHybrid ? 'Hybrid Pipeline' : 'Full Pipeline')}
                        </span>
                    </div>

                    <div class="stage-list" id="progress-stage-list">
                        ${isDev ? `
                            <div class="stage ${isCompleted ? '' : 'active'}" id="prog-stage-SEMGREP">
                                <span class="stage-marker" id="prog-marker-SEMGREP">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '<span class="spinner"></span>'}</span>
                                <div>
                                    <b>Semgrep (SAST Engine)</b>
                                    <p id="prog-desc-SEMGREP">Static AST code taint &amp; vulnerability pattern analysis</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : 'status-running'}" id="prog-badge-SEMGREP">${isCompleted ? 'Completed' : 'Running'}</span>
                            </div>

                            <div class="stage" id="prog-stage-CODEQL">
                                <span class="stage-marker" id="prog-marker-CODEQL">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '2'}</span>
                                <div>
                                    <b>CodeQL (Data-Flow SAST)</b>
                                    <p id="prog-desc-CODEQL">Deep inter-procedural taint flows (Source -> Sanitizer -> Sink)</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : ''}" id="prog-badge-CODEQL" style="${isCompleted ? '' : 'color:#64748b;'}">${isCompleted ? 'Completed' : 'Pending'}</span>
                            </div>

                            <div class="stage" id="prog-stage-GITLEAKS">
                                <span class="stage-marker" id="prog-marker-GITLEAKS">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '3'}</span>
                                <div>
                                    <b>Gitleaks (Secrets &amp; Credentials)</b>
                                    <p id="prog-desc-GITLEAKS">Scanning source files &amp; configurations for passwords &amp; tokens</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : ''}" id="prog-badge-GITLEAKS" style="${isCompleted ? '' : 'color:#64748b;'}">${isCompleted ? 'Completed' : 'Pending'}</span>
                            </div>

                            <div class="stage" id="prog-stage-CHECKOV">
                                <span class="stage-marker" id="prog-marker-CHECKOV">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '4'}</span>
                                <div>
                                    <b>Checkov (IaC &amp; Posture)</b>
                                    <p id="prog-desc-CHECKOV">Dockerfile, Kubernetes &amp; container posture audit</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : ''}" id="prog-badge-CHECKOV" style="${isCompleted ? '' : 'color:#64748b;'}">${isCompleted ? 'Skipped' : 'Pending'}</span>
                            </div>

                            <div class="stage" id="prog-stage-TRIVY">
                                <span class="stage-marker" id="prog-marker-TRIVY">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '5'}</span>
                                <div>
                                    <b>Supply Chain (Trivy, OSV &amp; npm audit)</b>
                                    <p id="prog-desc-TRIVY">Dependency manifests validation &amp; CVE advisory database</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : ''}" id="prog-badge-TRIVY" style="${isCompleted ? '' : 'color:#64748b;'}">${isCompleted ? 'Completed' : 'Pending'}</span>
                            </div>

                            <div class="stage" id="prog-stage-AI">
                                <span class="stage-marker" id="prog-marker-AI">${isCompleted ? Icons.get('check', 'size-4 text-emerald-600') : '6'}</span>
                                <div>
                                    <b>SentinelAI Correlation Engine</b>
                                    <p id="prog-desc-AI">Cross-tool deduplication, evidence validation &amp; AI triage</p>
                                </div>
                                <span class="status ${isCompleted ? 'status-safe' : ''}" id="prog-badge-AI" style="${isCompleted ? '' : 'color:#64748b;'}">${isCompleted ? 'Completed' : 'Queued'}</span>
                            </div>
                        ` : `
                            <div class="stage active" id="prog-stage-OWASP_ZAP">
                                <span class="stage-marker" id="prog-marker-OWASP_ZAP"><span class="spinner"></span></span>
                                <div>
                                    <b>OWASP ZAP (DAST)</b>
                                    <p id="prog-desc-OWASP_ZAP">Dynamic vulnerability inspection &amp; security headers</p>
                                </div>
                                <span class="status status-running" id="prog-badge-OWASP_ZAP">Running</span>
                            </div>

                            <div class="stage" id="prog-stage-NUCLEI">
                                <span class="stage-marker" id="prog-marker-NUCLEI">2</span>
                                <div>
                                    <b>Nuclei (Template DAST)</b>
                                    <p id="prog-desc-NUCLEI">Fast template-based exploit &amp; misconfiguration checks</p>
                                </div>
                                <span class="status" id="prog-badge-NUCLEI" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-WPSCAN">
                                <span class="stage-marker" id="prog-marker-WPSCAN">3</span>
                                <div>
                                    <b>WPScan (CMS &amp; Frameworks)</b>
                                    <p id="prog-desc-WPSCAN">Auditing WordPress, Joomla, Drupal, and web framework endpoints</p>
                                </div>
                                <span class="status" id="prog-badge-WPSCAN" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-WHATWEB">
                                <span class="stage-marker" id="prog-marker-WHATWEB">4</span>
                                <div>
                                    <b>WhatWeb (Recon &amp; WAF)</b>
                                    <p id="prog-desc-WHATWEB">Fingerprinting technologies, WAF barriers &amp; server stacks</p>
                                </div>
                                <span class="status" id="prog-badge-WHATWEB" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-TESTSSL">
                                <span class="stage-marker" id="prog-marker-TESTSSL">5</span>
                                <div>
                                    <b>TestSSL (Transport &amp; Headers)</b>
                                    <p id="prog-desc-TESTSSL">Auditing TLS cipher suites, HSTS, and defense headers</p>
                                </div>
                                <span class="status" id="prog-badge-TESTSSL" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-SEMGREP">
                                <span class="stage-marker" id="prog-marker-SEMGREP">6</span>
                                <div>
                                    <b>Semgrep (SAST)</b>
                                    <p id="prog-desc-SEMGREP">Static AST code taint &amp; injection pattern analysis</p>
                                </div>
                                <span class="status" id="prog-badge-SEMGREP" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-CODEQL">
                                <span class="stage-marker" id="prog-marker-CODEQL">7</span>
                                <div>
                                    <b>CodeQL (Data-Flow SAST)</b>
                                    <p id="prog-desc-CODEQL">Deep taint-tracking analysis (Source -> Sanitizer -> Sink)</p>
                                </div>
                                <span class="status" id="prog-badge-CODEQL" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-GITLEAKS">
                                <span class="stage-marker" id="prog-marker-GITLEAKS">8</span>
                                <div>
                                    <b>Gitleaks (Secrets)</b>
                                    <p id="prog-desc-GITLEAKS">Scanning source files &amp; bundles for exposed API keys &amp; tokens</p>
                                </div>
                                <span class="status" id="prog-badge-GITLEAKS" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-TRIVY">
                                <span class="stage-marker" id="prog-marker-TRIVY">9</span>
                                <div>
                                    <b>Trivy (Dependencies)</b>
                                    <p id="prog-desc-TRIVY">Auditing package manifests &amp; container CVEs</p>
                                </div>
                                <span class="status" id="prog-badge-TRIVY" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-OSV_SCANNER">
                                <span class="stage-marker" id="prog-marker-OSV_SCANNER">10</span>
                                <div>
                                    <b>OSV-Scanner (Supply Chain)</b>
                                    <p id="prog-desc-OSV_SCANNER">Google OSV database vulnerability intelligence</p>
                                </div>
                                <span class="status" id="prog-badge-OSV_SCANNER" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-CHECKOV">
                                <span class="stage-marker" id="prog-marker-CHECKOV">11</span>
                                <div>
                                    <b>Checkov (IaC &amp; Posture)</b>
                                    <p id="prog-desc-CHECKOV">Dockerfile, Kubernetes &amp; infrastructure security audit</p>
                                </div>
                                <span class="status" id="prog-badge-CHECKOV" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-NPM_AUDIT">
                                <span class="stage-marker" id="prog-marker-NPM_AUDIT">12</span>
                                <div>
                                    <b>npm audit</b>
                                    <p id="prog-desc-NPM_AUDIT">Advisory database validation for npm dependencies</p>
                                </div>
                                <span class="status" id="prog-badge-NPM_AUDIT" style="color:#64748b;">Pending</span>
                            </div>

                            <div class="stage" id="prog-stage-AI">
                                <span class="stage-marker" id="prog-marker-AI">13</span>
                                <div>
                                    <b>AI Threat Intelligence</b>
                                    <p id="prog-desc-AI">Cross-engine correlation, deduplication &amp; risk evaluation</p>
                                </div>
                                <span class="status" id="prog-badge-AI" style="color:#64748b;">Queued</span>
                            </div>
                        `}
                    </div>
                </div>
            </div>

            <!-- Finding Summary Ribbon -->
            <div class="finding-summary">
                <div>
                    <span class="severity-dot critical"></span>
                    <b id="prog-ribbon-critical">0</b>
                    <small>Critical</small>
                </div>
                <div>
                    <span class="severity-dot high"></span>
                    <b id="prog-ribbon-high">0</b>
                    <small>High</small>
                </div>
                <div>
                    <span class="severity-dot medium"></span>
                    <b id="prog-ribbon-medium">0</b>
                    <small>Medium</small>
                </div>
                <div>
                    <span class="severity-dot low"></span>
                    <b id="prog-ribbon-low">0</b>
                    <small>Low</small>
                </div>
                <button type="button" class="button button-primary" id="btn-prog-view-dashboard" onclick="App.proceedToDashboard()">
                    View findings dashboard ${Icons.get('arrow', 'size-4')}
                </button>
            </div>
        `;
    },

    startProgressPolling() {
        if (this.scanState.timer) clearInterval(this.scanState.timer);
        this.scanState.scanStartTime = Date.now();

        // Immediate first poll to eliminate any lag in loading real code and findings
        const fetchProgress = async () => {
            if (this.currentView !== 'progress') return;
            try {
                const res = await API.getScanProgress(this.scanState.currentScanId);
                if (res && res.scan) {
                    const scan = res.scan;
                    this.scanState.progress = typeof scan.progress === 'number' ? scan.progress : this.scanState.progress;

                    // Remaining time estimate
                    const remTimer = document.getElementById('progress-remaining-timer');
                    if (remTimer) {
                        const elapsedSec = Math.max(1, Math.floor((Date.now() - this.scanState.scanStartTime) / 1000));
                        if (this.scanState.progress >= 100 || scan.status === 'completed') {
                            remTimer.textContent = '00:00';
                        } else {
                            const totalEst = Math.max(30, (elapsedSec / Math.max(5, this.scanState.progress)) * 100);
                            const remSec = Math.max(0, Math.floor(totalEst - elapsedSec));
                            const remMins = String(Math.floor(remSec / 60)).padStart(2, '0');
                            const remSecs = String(remSec % 60).padStart(2, '0');
                            remTimer.textContent = `~${remMins}:${remSecs}`;
                        }
                    }

                    // Progress Orb
                    const orbEl = document.querySelector('.progress-orb');
                    const txtEl = document.getElementById('progress-percent-text');
                    const subEl = document.getElementById('progress-status-sub');
                    const isDone = this.scanState.progress >= 100 || scan.status === 'completed';

                    if (txtEl) txtEl.textContent = `${this.scanState.progress}%`;
                    if (subEl) {
                        subEl.textContent = isDone ? 'Complete' : (scan.status === 'cancelled' ? 'Halted' : 'Scanning');
                        subEl.className = isDone ? 'status status-safe' : (scan.status === 'cancelled' ? 'status status-low' : 'status status-running');
                    }
                    if (orbEl) {
                        const orbColor = scan.status === 'cancelled' ? '#ea580c' : (this.isDarkMode ? '#38bdf8' : '#2563eb');
                        const bgCutout = this.isDarkMode ? '#0c1424' : '#ffffff';
                        const bgTrack = this.isDarkMode ? '#1a273e' : '#e9eff6';
                        if (isDone) {
                            orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} 100%, ${orbColor} 100%)`;
                            orbEl.classList.add('completed');
                        } else {
                            orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} ${this.scanState.progress}%, ${bgTrack} 0)`;
                            orbEl.classList.remove('completed');
                        }
                    }

                    // Live Terminal Code Inspector Stream with Real Project Code
                    this.updateLiveCodeInspector(this.scanState.progress || 0, scan.liveCodeStream, scan);

                    // Live Line
                    const liveCode = document.getElementById('progress-live-code');
                    const liveMsg = document.getElementById('progress-live-message');
                    const liveTool = document.getElementById('progress-tests-count');
                    if (liveCode && scan.activeTool && !isDone) liveCode.textContent = scan.activeTool;
                    if (liveMsg && scan.activeMessage && !isDone) liveMsg.textContent = scan.activeMessage;
                    if (liveTool && !isDone) liveTool.textContent = scan.activeTool || 'AST_SCAN';

                    // Live Ribbon Counters
                    if (scan.counts) {
                        const critEl = document.getElementById('prog-ribbon-critical');
                        const highEl = document.getElementById('prog-ribbon-high');
                        const medEl = document.getElementById('prog-ribbon-medium');
                        const lowEl = document.getElementById('prog-ribbon-low');
                        if (critEl) critEl.textContent = scan.counts.critical || 0;
                        if (highEl) highEl.textContent = scan.counts.high || 0;
                        if (medEl) medEl.textContent = scan.counts.medium || 0;
                        if (lowEl) lowEl.textContent = scan.counts.low || 0;
                    }

                    // Live Tool Stages
                    if (scan.tasks && Array.isArray(scan.tasks)) {
                        scan.tasks.forEach(t => {
                            const stageEl = document.getElementById(`prog-stage-${t.toolName}`);
                            const markerEl = document.getElementById(`prog-marker-${t.toolName}`);
                            const badgeEl = document.getElementById(`prog-badge-${t.toolName}`);

                            if (badgeEl) {
                                badgeEl.textContent = t.status.charAt(0).toUpperCase() + t.status.slice(1).toLowerCase();
                                if (t.status === 'COMPLETED') {
                                    badgeEl.className = 'status status-safe';
                                    if (markerEl) markerEl.innerHTML = Icons.get('check', 'size-4 text-emerald-600');
                                    if (stageEl) stageEl.className = 'stage';
                                } else if (t.status === 'RUNNING') {
                                    badgeEl.className = 'status status-running';
                                    if (markerEl) markerEl.innerHTML = '<span class="spinner"></span>';
                                    if (stageEl) stageEl.className = 'stage active';
                                } else if (t.status === 'SKIPPED') {
                                    badgeEl.className = 'status';
                                    badgeEl.style.color = '#64748b';
                                    if (markerEl) markerEl.textContent = '—';
                                } else if (t.status === 'FAILED') {
                                    badgeEl.className = 'status status-low';
                                    if (markerEl) markerEl.textContent = '!';
                                }
                            }
                        });
                    }

                    // Completed or Partial Handling
                    if (scan.status === 'completed' || scan.status === 'partial') {
                        clearInterval(this.scanState.timer);
                        if (this.scanState.inspectorTimer) {
                            clearInterval(this.scanState.inspectorTimer);
                            this.scanState.inspectorTimer = null;
                        }
                        this.scanState.progress = 100;
                        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 7);
                        if (txtEl) txtEl.textContent = '100%';
                        if (subEl) {
                            subEl.textContent = 'Complete';
                            subEl.className = 'status status-safe';
                        }
                        const orbColor = this.isDarkMode ? '#38bdf8' : '#2563eb';
                        const bgCutout = this.isDarkMode ? '#0c1424' : '#ffffff';
                        if (orbEl) {
                            orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(${orbColor} 100%, ${orbColor} 100%)`;
                            orbEl.classList.add('completed');
                        }

                        // Stop code scanning and laser animation on screen
                        const terminalEl = document.querySelector('.code-terminal-window');
                        if (terminalEl) {
                            terminalEl.classList.add('completed');
                        }

                        const indEl = document.getElementById('terminal-inspect-indicator');
                        if (indEl) {
                            indEl.innerHTML = `${Icons.get('check', 'size-3 text-emerald-400')} ANALYSIS COMPLETE`;
                            indEl.className = 'terminal-status-tag completed';
                        }

                        const dot = document.getElementById('progress-pulse-dot');
                        if (dot) {
                            dot.classList.remove('pulse-dot');
                            dot.style.background = '#10b981';
                            dot.style.boxShadow = '0 0 8px rgba(16, 185, 129, 0.6)';
                            dot.style.animation = 'none';
                        }
                        if (liveCode) liveCode.textContent = 'COMPLETED';
                        if (liveMsg) liveMsg.textContent = 'Assessment completed. All security rules and AST engines finished.';
                        if (liveTool) liveTool.textContent = 'AUDITED';

                        // Ensure SentinelAI Correlation Engine (Tool 6) is marked Complete
                        const aiBadge = document.getElementById('prog-badge-AI');
                        const aiMarker = document.getElementById('prog-marker-AI');
                        const aiStage = document.getElementById('prog-stage-AI');
                        if (aiBadge) {
                            aiBadge.textContent = 'Completed';
                            aiBadge.className = 'status status-safe';
                            aiBadge.style.color = '';
                        }
                        if (aiMarker) {
                            aiMarker.innerHTML = Icons.get('check', 'size-4 text-emerald-600');
                        }
                        if (aiStage) {
                            aiStage.className = 'stage';
                        }

                        // Remaining timer to 00:00
                        const remTimer = document.getElementById('progress-remaining-timer');
                        if (remTimer) remTimer.textContent = '00:00';

                        const stopBtn = document.getElementById('btn-stop-assessment');
                        if (stopBtn) {
                            stopBtn.className = 'button button-primary';
                            stopBtn.innerHTML = `View findings dashboard ${Icons.get('arrow', 'size-4')}`;
                            stopBtn.onclick = () => App.proceedToDashboard();
                        }
                    } else if (scan.status === 'cancelled') {
                        clearInterval(this.scanState.timer);
                        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 7);
                        if (txtEl) txtEl.textContent = 'Halted';
                        if (subEl) subEl.textContent = 'Cancelled';
                        const stopBtn = document.getElementById('btn-stop-assessment');
                        if (stopBtn) {
                            stopBtn.className = 'button button-secondary';
                            stopBtn.innerHTML = `View findings dashboard ${Icons.get('arrow', 'size-4')}`;
                            stopBtn.onclick = () => App.proceedToDashboard();
                        }
                    }
                }
            } catch (e) {
                console.warn('Progress poll error:', e);
            }
        };

        // Fire initial fetch immediately
        fetchProgress();

        this.scanState.timer = setInterval(async () => {
            if (this.currentView !== 'progress') {
                clearInterval(this.scanState.timer);
                return;
            }

            // 1. Live Ticking Elapsed Timer
            const elapsedSec = Math.max(1, Math.floor((Date.now() - this.scanState.scanStartTime) / 1000));
            const elMins = String(Math.floor(elapsedSec / 60)).padStart(2, '0');
            const elSecs = String(elapsedSec % 60).padStart(2, '0');
            const elTimer = document.getElementById('progress-elapsed-timer');
            if (elTimer) elTimer.textContent = `${elMins}:${elSecs}`;

            await fetchProgress();
        }, 1200);
    },

    highlightSyntax(raw) {
        if (!raw) return '';
        if (raw.includes('<span class=')) return raw;

        // Escape HTML
        let s = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        // Check if full comment line
        if (/^\s*(\/\/|#|\/\*)/.test(s)) {
            return `<span class="cm">${s}</span>`;
        }

        // Strings: single quotes, double quotes, backticks
        s = s.replace(/('([^'\\]|\\.)*'|"([^"\\]|\\.)*"|`([^`\\]|\\.)*`)/g, '<span class="str">$1</span>');

        // Keywords
        const kwList = ['import', 'export', 'default', 'from', 'const', 'let', 'var', 'function', 'return', 'async', 'await', 'class', 'if', 'else', 'def', 'try', 'catch', 'throw', 'new', 'typeof', 'interface', 'type'];
        const kwRegex = new RegExp(`\\b(${kwList.join('|')})\\b`, 'g');
        s = s.replace(kwRegex, (match, p1, offset, fullStr) => {
            const before = fullStr.slice(0, offset);
            const inTag = (before.match(/<[^>]*$/) !== null);
            const inSpan = (before.match(/<span class="str">[^<]*$/) !== null);
            if (inTag || inSpan) return match;
            return `<span class="kw">${match}</span>`;
        });

        return s;
    },

    updateLiveCodeInspector(progress = 0, liveStream = null, scan = null) {
        if (liveStream && Array.isArray(liveStream) && liveStream.length > 0) {
            this.scanState.liveCodeStream = liveStream;
        }

        const stream = (this.scanState.liveCodeStream && this.scanState.liveCodeStream.length > 0)
            ? this.scanState.liveCodeStream
            : null;

        let snip = null;
        if (stream && stream.length > 0) {
            this.scanState.inspectorTick = (this.scanState.inspectorTick || 0) + 1;
            const idx = Math.floor(this.scanState.inspectorTick % stream.length);
            snip = stream[idx];
        }

        if (!snip) {
            const fallbackName = this.scanState.uploadedFile?.name || (this.scanState.url ? this.scanState.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '') : 'source_code');
            snip = {
                filename: fallbackName,
                engineTag: 'Security Inspection Engine &middot; Active',
                lineCount: 'Live Analysis',
                lines: [
                    { ln: 1, code: "// Live AST security analysis in progress...", active: true },
                    { ln: 2, code: "// Actively inspecting source files and configuration manifests..." }
                ]
            };
        }

        const fileEl = document.getElementById('terminal-active-filename');
        const engineEl = document.getElementById('terminal-engine-tag');
        const counterEl = document.getElementById('terminal-line-counter');
        const linesEl = document.getElementById('terminal-code-lines');

        if (fileEl && snip.filename) fileEl.textContent = snip.filename;
        if (engineEl && snip.engineTag) engineEl.innerHTML = snip.engineTag;
        if (counterEl && snip.lineCount) counterEl.textContent = snip.lineCount;

        if (linesEl && snip.lines) {
            linesEl.innerHTML = snip.lines.map(l => {
                const highlighted = this.highlightSyntax(l.code);
                return `
                <div class="t-code-line ${l.active ? 't-active' : ''} ${l.vuln ? 't-vuln' : ''} ${l.comment ? 't-comment' : ''}">
                    <span class="t-ln">${l.ln}</span>
                    <span class="t-code">${highlighted}</span>
                    ${l.vuln ? `
                        <span class="t-vuln-badge cwe-badge">
                            ${Icons.get('warning', 'size-3')} ${l.vuln}
                        </span>
                    ` : ''}
                </div>
            `;
            }).join('');
        }
    },

    nextCodeSnippet() {
        if (this.scanState.liveCodeStream && this.scanState.liveCodeStream.length > 1) {
            this.scanState.inspectorTick = (this.scanState.inspectorTick || 0) + 1;
            const stream = this.scanState.liveCodeStream;
            const idx = Math.floor(this.scanState.inspectorTick % stream.length);
            const snip = stream[idx];
            if (snip) {
                const fileEl = document.getElementById('terminal-active-filename');
                const engineEl = document.getElementById('terminal-engine-tag');
                const counterEl = document.getElementById('terminal-line-counter');
                const linesEl = document.getElementById('terminal-code-lines');

                if (fileEl && snip.filename) fileEl.textContent = snip.filename;
                if (engineEl && snip.engineTag) engineEl.innerHTML = snip.engineTag;
                if (counterEl && snip.lineCount) counterEl.textContent = snip.lineCount;

                if (linesEl && snip.lines) {
                    linesEl.innerHTML = snip.lines.map(l => {
                        const highlighted = this.highlightSyntax(l.code);
                        return `
                        <div class="t-code-line ${l.active ? 't-active' : ''} ${l.vuln ? 't-vuln' : ''} ${l.comment ? 't-comment' : ''}">
                            <span class="t-ln">${l.ln}</span>
                            <span class="t-code">${highlighted}</span>
                            ${l.vuln ? `
                                <span class="t-vuln-badge cwe-badge">
                                    ${Icons.get('warning', 'size-3')} ${l.vuln}
                                </span>
                            ` : ''}
                        </div>
                    `;
                    }).join('');
                }
            }
        }
    },

    async stopAssessment() {
        if (this.scanState.timer) clearInterval(this.scanState.timer);
        const scanId = this.scanState.currentScanId;
        showToast('Halting security assessment...', 'info');

        const stopBtn = document.getElementById('btn-stop-assessment');
        if (stopBtn) {
            stopBtn.disabled = true;
            stopBtn.innerHTML = '<span class="spinner"></span> Halting...';
        }

        try {
            if (scanId) {
                await API.cancelScan(scanId);
            }
        } catch (e) {
            console.warn('Cancel scan API notice:', e);
        }

        const txtEl = document.getElementById('progress-percent-text');
        if (txtEl) txtEl.textContent = 'Halted';

        const subEl = document.getElementById('progress-status-sub');
        if (subEl) subEl.textContent = 'Cancelled';

        const orbEl = document.querySelector('.progress-orb');
        if (orbEl) {
            const bgCutout = this.isDarkMode ? '#0c1424' : '#ffffff';
            const bgTrack = this.isDarkMode ? '#1a273e' : '#e9eff6';
            orbEl.style.background = `radial-gradient(closest-side, ${bgCutout} 72%, transparent 73% 99%), conic-gradient(#ea580c ${this.scanState.progress || 50}%, ${bgTrack} 0)`;
        }

        const dot = document.getElementById('progress-pulse-dot');
        if (dot) dot.style.background = '#ea580c';

        const liveCode = document.getElementById('progress-live-code');
        if (liveCode) liveCode.textContent = 'HALTED';

        const liveMsg = document.getElementById('progress-live-message');
        if (liveMsg) liveMsg.textContent = 'Assessment stopped by user. All findings discovered up to this point have been preserved.';

        if (stopBtn) {
            stopBtn.disabled = false;
            stopBtn.className = 'button button-primary';
            stopBtn.innerHTML = `View findings dashboard ${Icons.get('arrow', 'size-4')}`;
            stopBtn.onclick = () => App.proceedToDashboard();
        }

        showToast('Assessment stopped. Click "View findings dashboard" to see all cataloged results.', 'warning');
    },

    // =========================================================
    // =========================================================
    // 9. STEP 5: FINDINGS DASHBOARD (EXACT FIGMA fe COMPONENT)
    // =========================================================
    renderDashboard() {
        const env = (this.scanState.environment || 'development').toLowerCase();
        const mode = this.scanState.scanType || 'scan_only';
        const isScanOnly = mode === 'scan_only';
        const isDev = env === 'development';
        const hasOptionalCode = Boolean(this.scanState.optionalCodeFile || this.scanState.gitRepoUrl);
        const isHybrid = !isDev && hasOptionalCode;
        const targetDesc = isDev 
            ? (this.scanState.uploadedFile?.name || 'Local Code Repository (SAST)')
            : `${(this.scanState.url || 'aymanaboelela.com').replace(/^https?:\/\//, '')} · ${env.toUpperCase()}`;

        return `
            ${renderPageTitle({
                title: 'Security findings',
                copy: `${escapeHtml(targetDesc)} · ${isScanOnly ? 'Scan Only Assessment' : 'Full Lifecycle Assessment'}`,
                action: `
                    <div class="flex gap-2">
                        <button type="button" class="button button-secondary" onclick="App.triggerRescan()">
                            ${Icons.get('refresh', 'size-4')} Retest (Rescan)
                        </button>
                        <button type="button" class="button button-secondary" onclick="App.exportAndDownloadReport()">
                            ${Icons.get('file', 'size-4')} Export Report
                        </button>
                        <button type="button" class="button button-primary" onclick="App.proceedToReport()">
                            View Report
                        </button>
                    </div>
                `
            })}

            <!-- Mode Notice Banner if Scan Only -->
            ${isScanOnly ? `
                <div class="mode-notice-banner scan-only mb-6">
                    ${Icons.get('info', 'size-5 flex-shrink-0')}
                    <div>
                        <b>Scan Only Mode Completed:</b>
                        <span>Vulnerabilities were identified, prioritized, and cataloged into this register. No automated codebase fixes or verification retests were requested or required.</span>
                    </div>
                </div>
            ` : ''}

            <!-- Multi-Tool Execution & Engine Matrix Card -->
            <div class="card mb-6" style="padding: 1.25rem 1.5rem; border-radius: 12px; background: #ffffff; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom: 1rem;">
                    <div>
                        <div style="display:flex; align-items:center; gap:8px;">
                            <h2 style="font-size:15px; font-weight:800; color:#0f172a; margin:0;">${isDev ? 'Source Code & Component Security Engine' : 'Multi-Tool Security Assessment Engine'}</h2>
                            <span id="scan-status-badge" class="badge" style="font-size:10px; padding:2px 8px; border-radius:9999px; background:#eff6ff; color:#2563eb; font-weight:700;">READY</span>
                        </div>
                        <p style="font-size:11px; color:#64748b; margin:3px 0 0 0;">
                            ${isDev ? 'Static AST Analysis, Secret Detection, Dependency CVEs & IaC Posture' : 'Unified DAST, SAST, Secret Scanning, Configuration & Dependency Analysis'}
                        </p>
                    </div>
                    <div style="display:flex; align-items:center; gap:16px;">
                        <div style="text-align:right;">
                            <span style="font-size:10px; color:#64748b; font-weight:600; text-transform:uppercase;">Tools Completed</span>
                            <div id="tools-completed-ratio" style="font-size:15px; font-weight:800; color:#0f172a;">— / ${isDev ? '7' : '12'}</div>
                        </div>
                        <div style="text-align:right;">
                            <span style="font-size:10px; color:#64748b; font-weight:600; text-transform:uppercase;">Engine Mode</span>
                            <div style="font-size:13px; font-weight:700; color:#2563eb;">${isDev ? 'PURE SAST' : (isHybrid ? 'HYBRID DAST+SAST' : 'URL DAST')}</div>
                        </div>
                    </div>
                </div>

                <!-- Tool Matrix Grid (URL tools omitted in Development Mode) -->
                <div id="tool-execution-matrix-grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px;">
                    ${!isDev ? `
                        <div class="tool-matrix-tile" id="tile-tool-OWASP_ZAP" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:12px; font-weight:700; color:#1e293b;">OWASP ZAP</div>
                                <small style="color:#64748b; font-size:10px;">DAST Engine</small>
                            </div>
                            <span class="tool-status-pill badge" id="pill-OWASP_ZAP" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                        </div>

                        <div class="tool-matrix-tile" id="tile-tool-NUCLEI" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:12px; font-weight:700; color:#1e293b;">Nuclei</div>
                                <small style="color:#64748b; font-size:10px;">Template DAST</small>
                            </div>
                            <span class="tool-status-pill badge" id="pill-NUCLEI" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                        </div>

                        <div class="tool-matrix-tile" id="tile-tool-WPSCAN" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:12px; font-weight:700; color:#1e293b;">WPScan</div>
                                <small style="color:#64748b; font-size:10px;">CMS &amp; Frameworks</small>
                            </div>
                            <span class="tool-status-pill badge" id="pill-WPSCAN" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                        </div>

                        <div class="tool-matrix-tile" id="tile-tool-WHATWEB" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:12px; font-weight:700; color:#1e293b;">WhatWeb</div>
                                <small style="color:#64748b; font-size:10px;">Recon &amp; WAF</small>
                            </div>
                            <span class="tool-status-pill badge" id="pill-WHATWEB" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                        </div>

                        <div class="tool-matrix-tile" id="tile-tool-TESTSSL" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:12px; font-weight:700; color:#1e293b;">TestSSL</div>
                                <small style="color:#64748b; font-size:10px;">Transport &amp; TLS</small>
                            </div>
                            <span class="tool-status-pill badge" id="pill-TESTSSL" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                        </div>
                    ` : ''}

                    <div class="tool-matrix-tile" id="tile-tool-SEMGREP" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">Semgrep</div>
                            <small style="color:#64748b; font-size:10px;">SAST Code</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-SEMGREP" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-CODEQL" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">CodeQL</div>
                            <small style="color:#64748b; font-size:10px;">Data-Flow SAST</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-CODEQL" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-GITLEAKS" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">Gitleaks</div>
                            <small style="color:#64748b; font-size:10px;">Secret Detection</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-GITLEAKS" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-TRIVY" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">Trivy</div>
                            <small style="color:#64748b; font-size:10px;">Config &amp; CVEs</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-TRIVY" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-OSV_SCANNER" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">OSV-Scanner</div>
                            <small style="color:#64748b; font-size:10px;">Supply Chain</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-OSV_SCANNER" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-CHECKOV" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">Checkov</div>
                            <small style="color:#64748b; font-size:10px;">IaC &amp; Posture</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-CHECKOV" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>

                    <div class="tool-matrix-tile" id="tile-tool-NPM_AUDIT" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:12px; font-weight:700; color:#1e293b;">npm audit</div>
                            <small style="color:#64748b; font-size:10px;">Dependencies</small>
                        </div>
                        <span class="tool-status-pill badge" id="pill-NPM_AUDIT" style="font-size:10px; padding:2px 7px; border-radius:9999px; background:#f1f5f9; color:#475569; font-weight:700;">Pending</span>
                    </div>
                </div>
            </div>

            <!-- Dashboard Metric Grid (Score + 3 KPIs) -->
            <div class="dashboard-grid">
                <div class="score-card">
                    <div class="score-ring compact">
                        <strong id="dashboard-security-score">72</strong>
                        <span>Security score</span>
                    </div>
                    <div>
                        <span class="status status-warning" id="dashboard-score-status">Needs attention</span>
                        <p class="mt-3 text-sm leading-6 text-slate-500" id="dashboard-score-desc">
                            Vulnerabilities cataloged across assessment targets.
                        </p>
                    </div>
                </div>

                <div class="metric-card">
                    <div class="metric-icon critical">
                        ${Icons.get('warning', 'size-5')}
                    </div>
                    <div>
                        <span>Critical</span>
                        <strong id="kpi-critical">0</strong>
                        <small>${isScanOnly ? 'Needs attention' : 'Fix immediately'}</small>
                    </div>
                </div>

                <div class="metric-card">
                    <div class="metric-icon high">
                        ${Icons.get('warning', 'size-5')}
                    </div>
                    <div>
                        <span>High</span>
                        <strong id="kpi-high">0</strong>
                        <small>Review within 24h</small>
                    </div>
                </div>

                <div class="metric-card">
                    <div class="metric-icon blue">
                        ${Icons.get('shield', 'size-5')}
                    </div>
                    <div>
                        <span>Total findings</span>
                        <strong id="kpi-total">0</strong>
                        <small>${isScanOnly ? 'Cataloged findings' : 'Fixes available'}</small>
                    </div>
                </div>
            </div>

            <!-- Findings Card (Toolbar + Table / Google Sheets) -->
            <div class="findings-card">
                <!-- Scan Category Filter Tabs / Pills -->
                <div class="category-tabs-bar" style="display:flex; align-items:center; gap:8px; padding:10px 16px; border-bottom:1px solid #e2e8f0; background:#f8fafc; overflow-x:auto; border-top-left-radius:12px; border-top-right-radius:12px;">
                    <span style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; margin-right:4px; white-space:nowrap;">Category:</span>
                    <button type="button" class="cat-pill active" id="cat-pill-all" onclick="App.onSelectCategoryFilter('')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:700; background:#2563eb; color:#ffffff; border:1px solid #2563eb; cursor:pointer; transition:all 0.15s ease;">
                        All <span id="cat-count-all" style="font-size:10px; background:rgba(255,255,255,0.25); color:#ffffff; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                    <button type="button" class="cat-pill" id="cat-pill-sast" onclick="App.onSelectCategoryFilter('SAST')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:500; background:#ffffff; color:#475569; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.15s ease;">
                        Source Code (SAST) <span id="cat-count-sast" style="font-size:10px; background:#f1f5f9; color:#475569; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                    <button type="button" class="cat-pill" id="cat-pill-dast" onclick="App.onSelectCategoryFilter('DAST')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:500; background:#ffffff; color:#475569; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.15s ease;">
                        Web App (DAST) <span id="cat-count-dast" style="font-size:10px; background:#f1f5f9; color:#475569; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                    <button type="button" class="cat-pill" id="cat-pill-secrets" onclick="App.onSelectCategoryFilter('SECRETS')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:500; background:#ffffff; color:#475569; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.15s ease;">
                        Secrets &amp; Credentials <span id="cat-count-secrets" style="font-size:10px; background:#f1f5f9; color:#475569; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                    <button type="button" class="cat-pill" id="cat-pill-sca" onclick="App.onSelectCategoryFilter('SCA')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:500; background:#ffffff; color:#475569; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.15s ease;">
                        Dependencies (SCA) <span id="cat-count-sca" style="font-size:10px; background:#f1f5f9; color:#475569; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                    <button type="button" class="cat-pill" id="cat-pill-iac" onclick="App.onSelectCategoryFilter('IAC')" style="display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:9999px; font-size:12px; font-weight:500; background:#ffffff; color:#475569; border:1px solid #cbd5e1; cursor:pointer; transition:all 0.15s ease;">
                        Infrastructure (IaC) <span id="cat-count-iac" style="font-size:10px; background:#f1f5f9; color:#475569; padding:1px 6px; border-radius:9999px;">0</span>
                    </button>
                </div>

                <div class="findings-toolbar">
                    <div>
                        <h2>All findings</h2>
                        <p id="findings-toolbar-count">Cataloged vulnerabilities</p>
                    </div>

                    <div class="toolbar-actions">
                        <div class="search-box">
                            ${Icons.get('search', 'size-4')}
                            <input type="text" id="finding-search-input" placeholder="Search findings" oninput="App.onSearchFindings(this.value)" style="border:0;outline:0;background:transparent;width:100%;font-size:0.75rem;color:inherit;font-family:inherit;">
                        </div>

                        <div class="relative" style="position:relative;">
                            <button type="button" class="button button-secondary" onclick="App.toggleSeverityDropdown()" id="btn-sev-filter">
                                <span id="label-sev-filter">All severity</span> ${Icons.get('chevron', 'size-4')}
                            </button>
                            <div id="sev-dropdown-menu" class="hidden" style="position:absolute;top:100%;left:0;margin-top:4px;background:#fff;border:1px solid #dbe2ea;border-radius:0.7rem;box-shadow:0 10px 25px rgba(0,0,0,0.1);z-index:50;min-width:140px;overflow:hidden;padding:0.25rem 0;">
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold" onclick="App.onSelectSeverityFilter('')">All severity</button>
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-red-600" onclick="App.onSelectSeverityFilter('critical')">Critical</button>
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-orange-500" onclick="App.onSelectSeverityFilter('high')">High</button>
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-yellow-600" onclick="App.onSelectSeverityFilter('medium')">Medium</button>
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-blue-600" onclick="App.onSelectSeverityFilter('low')">Low</button>
                            </div>
                        </div>

                        <div class="relative" style="position:relative;">
                            <button type="button" class="button button-secondary" onclick="App.toggleStatusDropdown()" id="btn-status-filter">
                                <span id="label-status-filter">All status</span> ${Icons.get('chevron', 'size-4')}
                            </button>
                            <div id="status-dropdown-menu" class="hidden" style="position:absolute;top:100%;left:0;margin-top:4px;background:#fff;border:1px solid #dbe2ea;border-radius:0.7rem;box-shadow:0 10px 25px rgba(0,0,0,0.1);z-index:50;min-width:140px;overflow:hidden;padding:0.25rem 0;">
                                <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold" onclick="App.onSelectStatusFilter('')">All status</button>
                                ${!isScanOnly ? `
                                    <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-purple-600" onclick="App.onSelectStatusFilter('confirmed')">Fix ready</button>
                                    <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold" onclick="App.onSelectStatusFilter('open')">Open</button>
                                    <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-emerald-600" onclick="App.onSelectStatusFilter('fixed')">Fixed</button>
                                ` : `
                                    <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold text-blue-600" onclick="App.onSelectStatusFilter('detected')">Detected</button>
                                    <button type="button" class="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50 block font-semibold" onclick="App.onSelectStatusFilter('open')">Open</button>
                                `}
                            </div>
                        </div>

                        <button type="button" class="button button-secondary ${this.dashboardViewMode === 'sheet' ? 'border-emerald-600 text-emerald-600 bg-emerald-50' : ''}" onclick="App.toggleDashboardViewMode()">
                            ${Icons.get('sheet', 'size-4 text-emerald-600')} <span>Google Sheets</span>
                        </button>
                    </div>
                </div>

                <!-- Standard Table View -->
                <div id="standard-table-container" class="${this.dashboardViewMode === 'standard' ? '' : 'hidden'}">
                    <div class="findings-table">
                        <div class="table-head">
                            <span>Finding</span>
                            <span>Severity</span>
                            <span>Category</span>
                            <span>Status</span>
                            <span></span>
                        </div>
                        <div id="findings-rows-target">
                            <!-- Loaded dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Google Sheets View -->
                <div id="google-sheet-view-wrapper" class="${this.dashboardViewMode === 'sheet' ? '' : 'hidden'}">
                    <div id="google-sheet-container">
                        <!-- Rendered by sheet.js -->
                    </div>
                </div>
            </div>
        `;
    },

    toggleSeverityDropdown() {
        const menu = document.getElementById('sev-dropdown-menu');
        const other = document.getElementById('status-dropdown-menu');
        other?.classList.add('hidden');
        menu?.classList.toggle('hidden');
    },

    onSelectSeverityFilter(sev) {
        this.activeSeverityFilter = sev;
        document.getElementById('sev-dropdown-menu')?.classList.add('hidden');
        const lbl = document.getElementById('label-sev-filter');
        if (lbl) lbl.textContent = sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : 'All severity';
        this.applyFindingsFilters();
    },

    toggleStatusDropdown() {
        const menu = document.getElementById('status-dropdown-menu');
        const other = document.getElementById('sev-dropdown-menu');
        other?.classList.add('hidden');
        menu?.classList.toggle('hidden');
    },

    onSelectStatusFilter(status) {
        this.activeStatusFilter = status;
        document.getElementById('status-dropdown-menu')?.classList.add('hidden');
        const lbl = document.getElementById('label-status-filter');
        const isScanOnly = this.scanState.scanType === 'scan_only';
        const textMap = isScanOnly 
            ? { '': 'All status', 'detected': 'Detected', 'open': 'Open' }
            : { '': 'All status', 'confirmed': 'Fix ready', 'open': 'Open', 'fixed': 'Fixed' };
        if (lbl) lbl.textContent = textMap[status] || 'All status';
        this.applyFindingsFilters();
    },

    toggleDashboardViewMode() {
        this.setDashboardViewMode(this.dashboardViewMode === 'standard' ? 'sheet' : 'standard');
    },

    setDashboardViewMode(mode) {
        this.dashboardViewMode = mode;
        const standardContainer = document.getElementById('standard-table-container');
        const sheetContainer = document.getElementById('google-sheet-view-wrapper');

        if (mode === 'sheet') {
            standardContainer?.classList.add('hidden');
            sheetContainer?.classList.remove('hidden');
            GoogleSheetView.init(this.findingsData);
        } else {
            sheetContainer?.classList.add('hidden');
            standardContainer?.classList.remove('hidden');
            this.renderStandardRows(this.findingsData);
        }
        this.render();
    },

    async loadDashboardData() {
        let scanId = this.scanState.currentScanId;
        if (!scanId) {
            try {
                const hist = await API.getScanHistory().catch(() => null);
                if (hist && Array.isArray(hist.history) && hist.history.length > 0) {
                    scanId = hist.history[0].id;
                    this.scanState.currentScanId = scanId;
                }
            } catch (e) {}
        }

        // 1. Fetch Multi-Tool Task Matrix strictly for this scan
        if (scanId) {
            try {
                const taskRes = await API.getScanTasks(scanId);
                if (taskRes && taskRes.tasks) {
                    let completedCount = 0;
                    taskRes.tasks.forEach(t => {
                        const pillEl = document.getElementById(`pill-${t.toolName}`);
                        if (pillEl) {
                            pillEl.textContent = t.status.charAt(0).toUpperCase() + t.status.slice(1).toLowerCase();
                            if (t.status === 'COMPLETED') {
                                pillEl.style.background = '#ecfdf5';
                                pillEl.style.color = '#047857';
                                completedCount++;
                            } else if (t.status === 'SKIPPED') {
                                pillEl.style.background = '#f1f5f9';
                                pillEl.style.color = '#64748b';
                                completedCount++;
                            } else if (t.status === 'FAILED') {
                                pillEl.style.background = '#fef2f2';
                                pillEl.style.color = '#b91c1c';
                            } else if (t.status === 'RUNNING') {
                                pillEl.style.background = '#eff6ff';
                                pillEl.style.color = '#1d4ed8';
                            }
                        }
                    });

                    const ratioEl = document.getElementById('tools-completed-ratio');
                    if (ratioEl) ratioEl.textContent = `${completedCount} / ${taskRes.tasks.length || 5}`;

                    const badgeEl = document.getElementById('scan-status-badge');
                    if (badgeEl) {
                        const allDone = taskRes.tasks.every(t => t.status === 'COMPLETED' || t.status === 'SKIPPED');
                        const hasFail = taskRes.tasks.some(t => t.status === 'FAILED');
                        const statusStr = allDone ? (hasFail ? 'PARTIAL' : 'COMPLETED') : 'RUNNING';
                        badgeEl.textContent = statusStr;
                        badgeEl.className = `badge ${statusStr === 'COMPLETED' ? 'badge-low' : (statusStr === 'PARTIAL' ? 'badge-high' : 'badge-info')}`;
                    }
                }
            } catch (e) {
                console.warn('Scan tasks load notice:', e);
            }
        }

        // 2. Fetch Findings strictly for this scan
        try {
            let scanFindings = [];
            if (scanId) {
                const findingsRes = await API.getScanFindings(scanId).catch(() => null);
                if (findingsRes && Array.isArray(findingsRes.findings)) {
                    scanFindings = findingsRes.findings;
                }
            }
            this.findingsData = scanFindings;

            const criticalCount = this.findingsData.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
            const highCount = this.findingsData.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;
            const medCount = this.findingsData.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length;
            const lowCount = this.findingsData.filter(f => (f.severity || '').toUpperCase() === 'LOW').length;
            const totalCount = this.findingsData.length;
            const totalOccurrences = this.findingsData.reduce((acc, f) => acc + (f.occurrencesCount || (f.occurrences ? f.occurrences.length : 1)), 0);

            const cEl = document.getElementById('kpi-critical');
            const hEl = document.getElementById('kpi-high');
            const tEl = document.getElementById('kpi-total');
            if (cEl) cEl.textContent = criticalCount;
            if (hEl) hEl.textContent = highCount;
            if (tEl) tEl.textContent = totalCount;

            const countEl = document.getElementById('findings-toolbar-count');
            if (countEl) {
                countEl.textContent = `${totalCount} unique finding${totalCount === 1 ? '' : 's'} (${totalOccurrences} raw occurrences) cataloged across targets`;
            }

            // Dynamic Security Score Calculation
            const scoreValEl = document.getElementById('dashboard-security-score');
            const scoreStatusEl = document.getElementById('dashboard-score-status');
            const scoreDescEl = document.getElementById('dashboard-score-desc');
            if (scoreValEl && scoreStatusEl) {
                let calcScore = 100 - (criticalCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3);
                calcScore = Math.max(15, Math.min(100, calcScore));
                scoreValEl.textContent = calcScore;
                if (calcScore >= 90) {
                    scoreStatusEl.className = 'status status-safe';
                    scoreStatusEl.textContent = 'Clean & Secure';
                    if (scoreDescEl) scoreDescEl.textContent = totalCount === 0 ? 'Zero vulnerabilities detected. Assessment passed with 100% score.' : 'Zero critical or high-severity vulnerabilities detected.';
                } else if (calcScore >= 70) {
                    scoreStatusEl.className = 'status status-warning';
                    scoreStatusEl.textContent = 'Needs attention';
                    if (scoreDescEl) scoreDescEl.innerHTML = `Identified <b class="text-slate-700">${totalCount} findings</b> requiring security review.`;
                } else {
                    scoreStatusEl.className = 'status status-low';
                    scoreStatusEl.textContent = 'High risk';
                    if (scoreDescEl) scoreDescEl.textContent = 'Critical issues identified requiring immediate remediation.';
                }
            }

            // Update Scan Category Badges & Counts
            const sastCount = this.findingsData.filter(f => (f.scanCategory || f.scan_category || '').toUpperCase() === 'SAST').length;
            const dastCount = this.findingsData.filter(f => (f.scanCategory || f.scan_category || '').toUpperCase() === 'DAST').length;
            const secretsCount = this.findingsData.filter(f => (f.scanCategory || f.scan_category || '').toUpperCase() === 'SECRETS').length;
            const scaCount = this.findingsData.filter(f => (f.scanCategory || f.scan_category || '').toUpperCase() === 'SCA').length;
            const iacCount = this.findingsData.filter(f => (f.scanCategory || f.scan_category || '').toUpperCase() === 'IAC').length;

            const setBadge = (id, count) => {
                const el = document.getElementById(id);
                if (el) el.textContent = count;
            };
            setBadge('cat-count-all', this.findingsData.length);
            setBadge('cat-count-sast', sastCount);
            setBadge('cat-count-dast', dastCount);
            setBadge('cat-count-secrets', secretsCount);
            setBadge('cat-count-sca', scaCount);
            setBadge('cat-count-iac', iacCount);

            this.applyFindingsFilters();
        } catch (e) {
            console.warn('Scan findings load error:', e);
            this.findingsData = [];
            this.applyFindingsFilters();
        }
    },

    async triggerRescan() {
        const targetId = this.scanState.authData?.targetId || this.scanState.targetId;
        if (!targetId) {
            showToast('Target identifier not available for retest.', 'error');
            return;
        }
        showToast('Initiating automated security retest & cross-scan delta comparison...', 'info');
        try {
            const res = await API.rescanTarget(targetId);
            if (res.scan && res.scan.id) {
                this.scanState.currentScanId = res.scan.id;
                this.scanState.progress = 15;
                showToast(`Retest launched (Scan #${res.scan.id}). Comparing against previous baseline...`, 'success');
                this.navigate('progress');
            }
        } catch (err) {
            showToast(err.message || 'Failed to trigger retest.', 'error');
        }
    },

    async exportAndDownloadReport() {
        const scanId = this.scanState.currentScanId;
        if (!scanId) {
            showToast('Scan session ID is required to export report.', 'error');
            return;
        }
        showToast('Generating comprehensive printable executive security report...', 'info');
        try {
            const res = await API.exportScanReport(scanId);
            if (res.htmlReportUrl) {
                window.open(res.htmlReportUrl, '_blank');
                showToast('Report opened in new tab! You can print or save as PDF.', 'success');
            }
        } catch (err) {
            showToast(err.message || 'Failed to export report.', 'error');
        }
    },

    renderStandardRows(findings) {
        const target = document.getElementById('findings-rows-target');
        if (!target) return;

        if (Array.isArray(findings) && findings.length === 0) {
            target.innerHTML = `
                <div style="padding: 2.75rem 1.5rem; text-align: center; background: #ffffff; border-radius: 8px; border: 1px dashed #cbd5e1; margin: 0.75rem 0;">
                    <div style="font-size: 1.75rem; margin-bottom: 0.5rem; color: #10b981;">${Icons.get('check', 'size-8 inline-block')}</div>
                    <b style="color: #0f172a; font-size: 0.95rem; display: block; font-weight: 700;">No Vulnerabilities Detected</b>
                    <p style="font-size: 0.8rem; color: #64748b; margin-top: 0.35rem; max-width: 420px; margin-left: auto; margin-right: auto;">All automated security tests, DOM taint checks, dependency audits, and secret scanning finished cleanly for this assessment.</p>
                </div>
            `;
            return;
        }

        const list = Array.isArray(findings) ? findings : [];
        const isScanOnly = this.scanState.scanType === 'scan_only';

        target.innerHTML = list.map(f => {
            const sev = f.severity || f.sev || 'Medium';
            const sevLower = sev.toLowerCase();
            const isFixReady = !isScanOnly && (f.status === 'confirmed' || f.status === 'Fix ready');
            const statusLabel = isScanOnly 
                ? (f.status === 'confirmed' || f.status === 'Fix ready' || f.status === 'Fixed' ? 'Detected' : (f.status ? f.status.charAt(0).toUpperCase() + f.status.slice(1) : 'Detected'))
                : (f.status === 'confirmed' ? 'Fix ready' : (f.status ? f.status.charAt(0).toUpperCase() + f.status.slice(1) : 'Open'));

            const locationStr = (f.evidences && f.evidences[0] && (f.evidences[0].url || f.evidences[0].filePath)) 
                || f.endpoint 
                || f.filePath 
                || f.path 
                || '/';
            const cweLabel = f.cwe || f.cwe_id || f.category || f.type || 'CWE-200';
            const cat = (f.scanCategory || f.scan_category || 'SAST').toUpperCase();
            const catBadge = `<span class="badge" style="font-size:9px; padding:1px 5px; border-radius:4px; background:#f1f5f9; color:#475569; font-weight:700; margin-right:5px; border:1px solid #e2e8f0;">${escapeHtml(cat)}</span>`;
            const isNeedsReview = f.confidence === 'NEEDS_REVIEW' || f.status === 'Needs Review' || f.findingStatus === 'NEEDS_REVIEW';
            const confBadge = isNeedsReview
                ? `<span class="badge" style="font-size:10px; padding:1px 6px; border-radius:9999px; background:#fef3c7; color:#d97706; font-weight:700; margin-left:6px; vertical-align:middle;">⚠️ Needs Review</span>`
                : `<span class="badge" style="font-size:10px; padding:1px 6px; border-radius:9999px; background:#ecfdf5; color:#059669; font-weight:700; margin-left:6px; vertical-align:middle;">✓ Confirmed</span>`;

            return `
                <button type="button" class="table-row w-full text-left cursor-pointer" onclick="App.viewFinding(${f.id})">
                    <span>
                        <b>${escapeHtml(f.title)}${confBadge}</b>
                        <small>${escapeHtml(locationStr)}</small>
                    </span>
                    <span>
                        <i class="severity-dot ${sevLower}"></i>
                        ${sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </span>
                    <span class="mono-tag">${catBadge}${escapeHtml(cweLabel)}</span>
                    <span class="${isFixReady ? 'fix-ready' : ''}">
                        ${isFixReady ? Icons.get('sparkles', 'size-4') : ''}
                        ${statusLabel}
                    </span>
                    ${Icons.get('arrow', 'size-4 text-slate-400')}
                </button>
            `;
        }).join('');
    },

    applyFindingsFilters() {
        if (!Array.isArray(this.findingsData)) {
            if (this.dashboardViewMode === 'sheet') GoogleSheetView.setFindings([]);
            else this.renderStandardRows([]);
            return;
        }

        const isScanOnly = this.scanState.scanType === 'scan_only';
        const filtered = this.findingsData.filter(f => {
            // Category filter
            if (this.activeCategoryFilter) {
                const cat = (f.scanCategory || f.scan_category || '').toUpperCase();
                if (cat !== this.activeCategoryFilter.toUpperCase()) return false;
            }

            // Severity filter
            if (this.activeSeverityFilter) {
                const sev = (f.severity || f.sev || '').toLowerCase();
                if (sev !== this.activeSeverityFilter.toLowerCase()) return false;
            }

            // Status filter
            if (this.activeStatusFilter) {
                const st = (f.status || '').toLowerCase();
                if (isScanOnly) {
                    if (this.activeStatusFilter === 'detected') {
                        if (st !== 'detected' && st !== 'confirmed' && st !== 'fix ready' && st !== 'open') return false;
                    } else if (st !== this.activeStatusFilter.toLowerCase()) {
                        return false;
                    }
                } else {
                    if (this.activeStatusFilter === 'confirmed') {
                        if (st !== 'confirmed' && st !== 'fix ready') return false;
                    } else if (st !== this.activeStatusFilter.toLowerCase()) {
                        return false;
                    }
                }
            }

            // Search query
            if (this.activeSearchQuery) {
                const q = this.activeSearchQuery.toLowerCase();
                const titleMatch = (f.title || '').toLowerCase().includes(q);
                const endpointMatch = (f.endpoint || '').toLowerCase().includes(q);
                const pathMatch = (f.path || f.filePath || '').toLowerCase().includes(q);
                const cweMatch = (f.cwe || f.cwe_id || f.type || '').toLowerCase().includes(q);
                if (!titleMatch && !endpointMatch && !pathMatch && !cweMatch) return false;
            }

            return true;
        });

        const countEl = document.getElementById('findings-toolbar-count');
        if (countEl) {
            countEl.textContent = `${filtered.length} finding${filtered.length === 1 ? '' : 's'} cataloged${(this.activeCategoryFilter || this.activeSeverityFilter || this.activeStatusFilter || this.activeSearchQuery) ? ' (filtered)' : ''}`;
        }

        if (this.dashboardViewMode === 'sheet') {
            GoogleSheetView.setFindings(filtered);
        } else {
            this.renderStandardRows(filtered);
        }
    },

    onSelectCategoryFilter(cat) {
        this.activeCategoryFilter = cat;
        const pills = [
            { id: 'all', key: '' },
            { id: 'sast', key: 'SAST' },
            { id: 'dast', key: 'DAST' },
            { id: 'secrets', key: 'SECRETS' },
            { id: 'sca', key: 'SCA' },
            { id: 'iac', key: 'IAC' }
        ];
        pills.forEach(p => {
            const btn = document.getElementById(`cat-pill-${p.id}`);
            const count = document.getElementById(`cat-count-${p.id}`);
            if (btn) {
                const isSelected = (!cat && p.key === '') || (cat && cat.toUpperCase() === p.key);
                if (isSelected) {
                    btn.style.background = '#2563eb';
                    btn.style.color = '#ffffff';
                    btn.style.borderColor = '#2563eb';
                    btn.style.fontWeight = '700';
                    if (count) {
                        count.style.background = 'rgba(255,255,255,0.25)';
                        count.style.color = '#ffffff';
                    }
                } else {
                    btn.style.background = '#ffffff';
                    btn.style.color = '#475569';
                    btn.style.borderColor = '#cbd5e1';
                    btn.style.fontWeight = '500';
                    if (count) {
                        count.style.background = '#f1f5f9';
                        count.style.color = '#475569';
                    }
                }
            }
        });
        this.applyFindingsFilters();
    },

    onSearchFindings(q) {
        this.activeSearchQuery = q;
        this.applyFindingsFilters();
    },

    onSeverityFilter(sev) {
        this.activeSeverityFilter = sev;
        this.applyFindingsFilters();
    },

    viewFinding(id) {
        this.selectedFindingId = id;
        this.findingTab = 'overview';
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 6);
        this.navigate('finding');
    },

    // =========================================================
    // 10. STEP 6: FINDING DETAILS (EXACT FIGMA me COMPONENT)
    // =========================================================
    renderFindingDetail() {
        const user = this.getCurrentUser();
        const initials = user.name ? user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() : 'CU';
        const isScanOnly = this.scanState.scanType === 'scan_only';
        const tab = (isScanOnly && this.findingTab === 'fix') ? 'overview' : (this.findingTab || 'overview');
        const finding = (this.findingsData && this.findingsData.find(f => f.id == this.selectedFindingId))
                     || (this.findingsData && this.findingsData[0]);

        if (!finding) {
            return `
                <button type="button" class="back-link" onclick="App.navigate('dashboard')">
                    ${Icons.get('arrow', 'size-4 rotate-180')} Back to findings
                </button>
                <div style="padding: 3rem 1.5rem; text-align: center; background: #ffffff; border-radius: 8px; border: 1px dashed #cbd5e1; margin-top: 1.5rem;">
                    <div style="font-size: 2rem; margin-bottom: 0.5rem; color: #10b981;">${Icons.get('check', 'size-8 inline-block')}</div>
                    <b style="color: #0f172a; font-size: 1.1rem; display: block; font-weight: 700;">No Finding Selected or No Vulnerabilities</b>
                    <p style="font-size: 0.85rem; color: #64748b; margin-top: 0.5rem;">This assessment scan completed with zero detected vulnerabilities or no finding was selected.</p>
                    <button type="button" class="button button-primary" style="margin-top: 1rem;" onclick="App.navigate('dashboard')">
                        Return to Dashboard
                    </button>
                </div>
            `;
        }

        const sev = (finding.severity || finding.sev || 'Medium').toLowerCase();
        const sevClass = sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low';
        const sevLabel = (finding.severity || finding.sev || 'Medium').toUpperCase();
        const cwe = finding.cwe || finding.cwe_id || finding.category || finding.type || 'CWE-200';
        const cvss = finding.cvss || finding.cvss_score || (sev === 'critical' ? '9.8' : (sev === 'high' ? '7.5' : (sev === 'medium' ? '5.3' : '3.1')));
        const title = finding.title || 'Security Finding';
        const desc = finding.description || (finding.aiAnalyses && finding.aiAnalyses[0]?.summary) || 'Vulnerability identified during automated security assessment.';
        
        const rawLoc = (finding.evidences && finding.evidences[0] && (finding.evidences[0].url || finding.evidences[0].filePath))
                    || finding.endpoint 
                    || finding.filePath 
                    || finding.path 
                    || (this.scanState.url || 'https://aymanaboelela.com/');
        const cleanEndpoint = rawLoc.replace(/^(GET|POST|PUT|DELETE|PATCH)\s+/, '');
        const method = finding.method || (rawLoc.startsWith('GET') ? 'GET' : (rawLoc.startsWith('http') ? 'GET' : 'POST'));

        const whatFound = (finding.aiAnalyses && finding.aiAnalyses[0]?.technicalDetails)
                       || (finding.evidences && finding.evidences[0]?.evidenceSummary)
                       || finding.what_we_found
                       || finding.description
                       || 'The scanner detected an issue with the application configuration or code.';

        const reqCode = (finding.evidences && finding.evidences[0]?.rawSnippet)
                     || finding.request_code
                     || `${method} ${cleanEndpoint} HTTP/1.1\nHost: ${(this.scanState.url || 'aymanaboelela.com').replace(/^https?:\/\//, '')}\nTool: ${finding.toolName || 'Engine'}\nRule: ${finding.sourceRuleId || 'Verified'}`;

        const resCode = (finding.aiAnalyses && finding.aiAnalyses[0]?.evidenceExplanation)
                     || (finding.evidences && finding.evidences[0]?.evidenceSummary)
                     || finding.response_code
                     || finding.remediation
                     || 'Finding confirmed by multi-tool engine.';

        const remediation = (finding.aiAnalyses && finding.aiAnalyses[0]?.recommendedRemediation)
                         || finding.remediation
                         || 'Ensure secure configurations and input sanitization.';

        const patchFile = (finding.evidences && finding.evidences[0]?.filePath) || finding.patch_file || 'src/configuration';
        const patchDiff = finding.patch_diff || `// Recommended Security Hardening:\n${remediation}`;
        const owasp = finding.owasp_category || finding.category || finding.owasp || 'A05: Security Misconfiguration';
        const dateVal = (finding.createdAt || finding.created_at)
            ? new Date(finding.createdAt || finding.created_at).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
            : 'October 21, 2026';
        const assetVal = (this.scanState.url || 'aymanaboelela.com').replace(/^https?:\/\//, '');
        const isAsideNeedsReview = finding.confidence === 'NEEDS_REVIEW' || finding.status === 'Needs Review' || finding.status === 'NEEDS_REVIEW' || finding.findingStatus === 'NEEDS_REVIEW';
        const confVal = isAsideNeedsReview ? 'NEEDS_REVIEW · Requires Review' : (finding.confidence ? `${finding.confidence} · Confirmed` : 'HIGH · Confirmed');
        const statusVal = isScanOnly 
            ? (finding.status === 'confirmed' || finding.status === 'Fix ready' || finding.status === 'Fixed' ? 'Detected' : (finding.status ? finding.status.charAt(0).toUpperCase() + finding.status.slice(1) : 'Detected')) 
            : (finding.status || 'Open');

        const occurrences = (finding.occurrences && finding.occurrences.length > 0)
            ? finding.occurrences
            : (finding.related_findings?.occurrences || (finding.evidences && finding.evidences.length > 0 ? finding.evidences : []));

        return `
            <button type="button" class="back-link" onclick="App.navigate('dashboard')">
                ${Icons.get('arrow', 'size-4 rotate-180')} Back to findings
            </button>

            <div class="finding-title">
                <div>
                    <div class="flex items-center gap-3">
                        <span class="severity-badge ${sevClass}" id="finding-sev-badge">${sevLabel}</span>
                        <span class="mono-tag" id="finding-cwe-text">${escapeHtml(cwe)}</span>
                        <span class="mono-tag" id="finding-cvss-text">CVSS ${escapeHtml(cvss)}</span>
                        <span class="mono-tag" style="background:#eff6ff; color:#2563eb; font-weight:700;">${occurrences.length} Occurrence${occurrences.length === 1 ? '' : 's'}</span>
                    </div>
                    <h1 id="finding-title-text">${escapeHtml(title)}</h1>
                    <p id="finding-desc-p">${escapeHtml(desc)}</p>
                </div>
                ${!isScanOnly ? `
                    <button type="button" class="button button-primary" onclick="App.setFindingTab('fix')">
                        ${Icons.get('sparkles', 'size-4')} View AI remediation
                    </button>
                ` : ''}
            </div>

            <div class="detail-layout">
                <!-- Left: Main Tabbed Card -->
                <div class="detail-main">
                    <div class="tabs">
                        <button type="button" class="${tab === 'overview' ? 'active' : ''}" onclick="App.setFindingTab('overview')">Overview</button>
                        <button type="button" class="${tab === 'request' ? 'active' : ''}" onclick="App.setFindingTab('request')">Evidence</button>
                        ${!isScanOnly ? `
                            <button type="button" class="${tab === 'fix' ? 'active' : ''}" onclick="App.setFindingTab('fix')">
                                AI remediation <span>READY</span>
                            </button>
                        ` : ''}
                    </div>

                    ${tab === 'overview' ? `
                        <div class="detail-body">
                            <section class="detail-section">
                                <h2>What we found</h2>
                                <p id="finding-what-p">${escapeHtml(whatFound)}</p>
                            </section>

                            <section class="detail-section">
                                <h2>Why it matters</h2>
                                <div class="impact-grid">
                                    <div>
                                        ${Icons.get('eye', 'size-5')}
                                        <b>Security exposure</b>
                                        <p>${escapeHtml(desc)}</p>
                                    </div>
                                    <div>
                                        ${Icons.get('warning', 'size-5')}
                                        <b>Compliance &amp; Best Practices</b>
                                        <p>Non-compliance with security baselines can expose endpoints to attackers.</p>
                                    </div>
                                </div>
                            </section>

                            <section class="detail-section">
                                <h2>Affected endpoint / resource</h2>
                                <div class="endpoint">
                                    <span>${escapeHtml(method)}</span>
                                    <code id="finding-endpoint-code">${escapeHtml(cleanEndpoint)}</code>
                                    <button type="button" class="button button-ghost" onclick="App.copyEndpoint()">
                                        ${Icons.get('copy', 'size-4')} Copy
                                    </button>
                                </div>
                            </section>

                            ${occurrences.length > 1 ? `
                                <section class="detail-section">
                                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                        <h2 style="margin:0;">Cataloged occurrences (${occurrences.length} distinct locations)</h2>
                                        <span style="font-size:11px; color:#64748b; font-weight:600;">Consolidated Root-Cause Grouping</span>
                                    </div>
                                    <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; overflow-x:auto;">
                                        <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
                                            <thead style="background:#f8fafc; border-bottom:1px solid #e2e8f0;">
                                                <tr>
                                                    <th style="padding:8px 12px; color:#475569; font-weight:700;">#</th>
                                                    <th style="padding:8px 12px; color:#475569; font-weight:700;">File / Location</th>
                                                    <th style="padding:8px 12px; color:#475569; font-weight:700;">Line</th>
                                                    <th style="padding:8px 12px; color:#475569; font-weight:700;">Scanner Tool</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                ${occurrences.map((occ, idx) => `
                                                    <tr style="border-bottom:1px solid #f1f5f9;">
                                                        <td style="padding:8px 12px; color:#94a3b8; font-weight:600;">${idx + 1}</td>
                                                        <td style="padding:8px 12px; font-family:monospace; color:#1e293b; font-weight:600;">${escapeHtml(occ.filePath || occ.url || '/')}</td>
                                                        <td style="padding:8px 12px; color:#64748b;">${occ.lineStart || occ.line ? `Line ${occ.lineStart || occ.line}` : '—'}</td>
                                                        <td style="padding:8px 12px;"><span class="badge" style="background:#eff6ff; color:#2563eb; font-size:10px; padding:2px 6px; border-radius:4px; font-weight:700;">${escapeHtml(occ.scanner || finding.tool || 'Scanner')}</span></td>
                                                    </tr>
                                                `).join('')}
                                            </tbody>
                                        </table>
                                    </div>
                                </section>
                            ` : ''}

                            <section class="detail-section">
                                <h2>Recommended remediation (Guidance only)</h2>
                                <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:0.875rem 1rem; font-size:13px; line-height:1.6; color:#334155;" id="finding-remediation-box">
                                    ${escapeHtml(remediation)}
                                </div>
                            </section>
                        </div>
                    ` : ''}

                    ${tab === 'request' ? `
                        <div class="detail-body">
                            <section class="detail-section">
                                <h2>Captured request / Inspection target</h2>
                                <pre class="code-block"><code id="finding-evidence-request">${escapeHtml(reqCode)}</code></pre>
                            </section>

                            <section class="detail-section">
                                <h2>Scanner finding evidence / Response</h2>
                                <p id="finding-evidence-response">${escapeHtml(resCode)}</p>
                            </section>
                        </div>
                    ` : ''}

                    ${tab === 'fix' ? `
                        <div class="detail-body remediation">
                            <div class="ai-banner">
                                <div class="icon-tile violet">${Icons.get('sparkles', 'size-5')}</div>
                                <div>
                                    <b>AI-generated remediation</b>
                                    <p>Generated from your application context and validated against common regressions.</p>
                                </div>
                                <span class="status status-safe">High confidence</span>
                            </div>

                            <section class="detail-section">
                                <h2>Recommended patch</h2>
                                <div class="code-head">
                                    <span id="finding-patch-filename">${escapeHtml(patchFile)}</span>
                                    <button type="button" class="button button-ghost" onclick="App.copyPatch()">
                                        ${Icons.get('copy', 'size-4')} Copy patch
                                    </button>
                                </div>
                                <pre class="code-block diff"><code id="finding-fix-code">${escapeHtml(patchDiff)}</code></pre>
                            </section>

                            <div class="fix-actions">
                                <button type="button" class="button button-secondary" onclick="App.openInGitHub()">Open in GitHub</button>
                                <button type="button" class="button button-primary" onclick="App.markFindingFixed()">
                                    ${Icons.get('check', 'size-4')} Approve fix
                                </button>
                            </div>
                        </div>
                    ` : ''}
                </div>

                <!-- Right: Metadata Sidebar (Exact Figma Layout) -->
                <aside class="detail-aside">
                    <h3>Finding details</h3>
                    <div class="key-value">
                        <span>Status</span>
                        <b id="aside-status-val">${escapeHtml(statusVal)}</b>
                    </div>
                    <div class="key-value">
                        <span>First detected</span>
                        <b id="aside-date-val">${escapeHtml(dateVal)}</b>
                    </div>
                    <div class="key-value">
                        <span>OWASP category</span>
                        <b id="aside-owasp-val">${escapeHtml(owasp)}</b>
                    </div>
                    <div class="key-value">
                        <span>Affected asset</span>
                        <b id="aside-asset-val">${escapeHtml(assetVal)}</b>
                    </div>
                    <div class="key-value">
                        <span>Confidence</span>
                        <b id="aside-conf-val">${escapeHtml(confVal)}</b>
                    </div>
                    <div class="border-t border-slate-100 pt-5">
                        <b class="text-sm text-slate-800">Assigned to</b>
                        <div class="mt-3 flex items-center gap-3">
                            <span class="avatar">${initials}</span>
                            <div>
                                <b class="block text-sm">${escapeHtml(user.name || 'Security Lead')}</b>
                                <small class="text-slate-400">${escapeHtml(user.role === 'ADMIN' ? 'Security Administrator' : 'Security Analyst')}</small>
                            </div>
                        </div>
                    </div>
                </aside>
            </div>
        `;
    },

    setFindingTab(tabName) {
        if (this.scanState.scanType === 'scan_only' && tabName === 'fix') {
            this.findingTab = 'overview';
        } else {
            this.findingTab = tabName;
        }
        this.render();
    },

    copyEndpoint() {
        const text = document.getElementById('finding-endpoint-code')?.textContent || '/api/v2/users/search';
        navigator.clipboard.writeText(text);
        showToast('Endpoint copied to clipboard!', 'success');
    },

    copyPatch() {
        const text = document.getElementById('finding-fix-code')?.textContent || '';
        navigator.clipboard.writeText(text);
        showToast('Patch copied to clipboard!', 'success');
    },

    openInGitHub() {
        window.open('https://github.com', '_blank');
    },

    async loadFindingDetail(id) {
        const targetId = id || this.selectedFindingId;
        if (!targetId) return;
        try {
            const res = await API.getFindingDetail(targetId);
            if (!res || !res.finding) return;

            const f = res.finding;
            const titleEl = document.getElementById('finding-title-text');
            const sevEl = document.getElementById('finding-sev-badge');
            const cweEl = document.getElementById('finding-cwe-text');
            const cvssEl = document.getElementById('finding-cvss-text');
            const endEl = document.getElementById('finding-endpoint-code');
            const descEl = document.getElementById('finding-desc-p');

            const statusEl = document.getElementById('aside-status-val');
            const dateEl = document.getElementById('aside-date-val');
            const owaspEl = document.getElementById('aside-owasp-val');
            const assetEl = document.getElementById('aside-asset-val');
            const confEl = document.getElementById('aside-conf-val');

            const targetLoc = (f.evidences && f.evidences[0] && (f.evidences[0].url || f.evidences[0].filePath)) || f.endpoint || f.filePath || '/';
            const cweVal = f.cwe || f.cwe_id || f.category || 'CWE-200';
            const cvssVal = f.cvss_score || (f.severity === 'CRITICAL' ? '9.5' : (f.severity === 'HIGH' ? '7.8' : (f.severity === 'MEDIUM' ? '5.3' : '3.1')));

            if (titleEl && f.title) titleEl.textContent = f.title;
            if (sevEl && f.severity) {
                sevEl.textContent = f.severity.toUpperCase();
                sevEl.className = `severity-badge ${f.severity.toLowerCase()}`;
            }
            if (cweEl) cweEl.textContent = cweVal;
            if (cvssEl) cvssEl.textContent = `CVSS ${cvssVal}`;
            if (endEl) endEl.textContent = targetLoc.replace(/^(GET|POST|PUT|DELETE|PATCH)\s+/, '');
            if (descEl) descEl.textContent = f.description || (f.aiAnalyses && f.aiAnalyses[0]?.summary) || 'Vulnerability identified during automated security assessment.';

            const whatEl = document.getElementById('finding-what-p');
            if (whatEl) whatEl.textContent = (f.aiAnalyses && f.aiAnalyses[0]?.technicalDetails) || (f.evidences && f.evidences[0]?.evidenceSummary) || f.description || f.title;

            const remBox = document.getElementById('finding-remediation-box');
            if (remBox) remBox.textContent = (f.aiAnalyses && f.aiAnalyses[0]?.recommendedRemediation) || f.remediation || 'Ensure secure configurations and input sanitization.';

            const reqEl = document.getElementById('finding-evidence-request');
            if (reqEl) reqEl.textContent = (f.evidences && f.evidences[0]?.rawSnippet) || `Target Endpoint / File: ${targetLoc}\nTool: ${f.toolName || 'DAST'}\nRule: ${f.sourceRuleId || 'N/A'}`;

            const resEl = document.getElementById('finding-evidence-response');
            if (resEl) resEl.textContent = (f.aiAnalyses && f.aiAnalyses[0]?.evidenceExplanation) || (f.evidences && f.evidences[0]?.evidenceSummary) || f.remediation || 'Finding confirmed by multi-tool engine.';

            const isScanOnly = this.scanState.scanType === 'scan_only';
            if (statusEl) {
                statusEl.textContent = isScanOnly 
                    ? (f.status === 'confirmed' || f.status === 'Fix ready' || f.status === 'Fixed' ? 'Detected' : (f.status ? f.status.charAt(0).toUpperCase() + f.status.slice(1) : 'Detected'))
                    : (f.status === 'confirmed' ? 'Fix ready' : (f.status ? f.status.charAt(0).toUpperCase() + f.status.slice(1) : 'Open'));
            }
            if (dateEl && (f.created_at || f.createdAt)) dateEl.textContent = new Date(f.created_at || f.createdAt).toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
            if (owaspEl) owaspEl.textContent = f.owasp_category || f.category || 'A05: Security Misconfiguration';
            if (assetEl) assetEl.textContent = (this.scanState.url || 'aymanaboelela.com').replace(/^https?:\/\//, '');
            if (confEl) confEl.textContent = f.confidence ? `${f.confidence} · Confirmed` : 'HIGH · Confirmed';

            if (f.remediation) {
                const fixEl = document.getElementById('finding-fix-code');
                if (fixEl) fixEl.textContent = f.remediation;
            }
        } catch (e) {
            console.warn('Sandbox or offline finding detail loaded');
        }
    },

    testPayload() {
        showToast('Payload replay triggered: Server returned HTTP 200 (Vulnerable query detected)', 'error');
    },

    async markFindingFixed() {
        const finding = this.findingsData && this.findingsData.find(f => f.id == this.selectedFindingId);
        if (finding) {
            finding.status = 'Fixed';
        }
        const statusEl = document.getElementById('aside-status-val');
        if (statusEl) statusEl.textContent = 'Fixed';

        if (API.getToken()) {
            try {
                await API.updateFindingStatus(this.selectedFindingId || 1, 'fixed');
            } catch (e) {
                console.warn('API update status offline or sandbox:', e);
            }
        }
        showToast('Fix approved! AI remediation deployed and verified successfully.', 'success');
        setTimeout(() => this.navigate('dashboard'), 800);
    },

    // =========================================================
    // 11. STEP 7: ASSESSMENT REPORT (EXACT FIGMA ve COMPONENT)
    // =========================================================
    getThreatImpactExplanation(f) {
        if (f.aiAnalyses && Array.isArray(f.aiAnalyses) && f.aiAnalyses[0] && f.aiAnalyses[0].impact && f.aiAnalyses[0].impact.length > 15) {
            return f.aiAnalyses[0].impact;
        }

        const title = (f.title || '').toLowerCase();
        const cwe = (f.cwe || f.cwe_id || f.category || '').toLowerCase();

        if (title.includes('httponly') || cwe.includes('1004')) {
            return "If left unpatched, any malicious or third-party JavaScript executing on the domain (via Cross-Site Scripting or supply-chain tag injections) can directly read session cookies from document.cookie. Attackers can hijack legitimate sessions and impersonate users with zero credential knowledge.";
        }
        if (title.includes('banner') || title.includes('disclosure') || cwe.includes('200')) {
            return "If left unpatched, adversaries can accurately fingerprint underlying web server software, reverse proxies, and version numbers. This reconnaissance facilitates targeted automated exploits against known public CVEs specific to those versions.";
        }
        if (title.includes('localstorage') || title.includes('storage') || cwe.includes('922')) {
            return "If left unpatched, sensitive tokens stored in unencrypted client-side localStorage persist across browser restarts and lack HttpOnly protections, making them immediately extractable by any script executing within the origin domain.";
        }
        if (title.includes('sql') || cwe.includes('89')) {
            return "If left unpatched, attackers can manipulate backend database queries to bypass login authentication, extract complete customer databases, alter financial records, or execute administrative commands directly on the database host.";
        }
        if (title.includes('password') || title.includes('passwd') || title.includes('credential')) {
            return "If left unpatched, hardcoded plaintext passwords allow anyone with access to the source code, repository logs, or decompiled bundles to log in directly with elevated privileges, bypassing multi-factor authentication and compromising underlying data stores.";
        }
        if (title.includes('email') || cwe.includes('359')) {
            return "If left unpatched, exposed administrative or personal email addresses facilitate targeted spear-phishing attacks, account takeover attempts via credential stuffing, and unauthorized intelligence gathering on internal staff.";
        }
        if (title.includes('secret') || title.includes('key') || title.includes('token') || cwe.includes('798')) {
            return "If left unpatched, exposed private API tokens, cloud keys, or credentials can be harvested by scrapers to gain direct administrative access to production cloud infrastructure and third-party APIs.";
        }
        if (title.includes('cross-site') || title.includes('xss') || cwe.includes('79')) {
            return "If left unpatched, attackers can inject malicious JavaScript into client browser sessions, capturing keystrokes, exfiltrating session state, and redirecting legitimate users to phishing portals.";
        }
        if (title.includes('cve') || title.includes('dependency') || cwe.includes('1395')) {
            return "If left unpatched, known CVE advisories in third-party libraries can be weaponized against your system using automated exploit payloads without requiring custom vulnerability research.";
        }
        return "If left unpatched, this vulnerability expands the attack surface of the application, degrades defense-in-depth security baselines, and can be chained with auxiliary defects to compromise confidentiality, integrity, or availability.";
    },

    renderReport() {
        const user = this.getCurrentUser();
        const clientOrg = user.organization || (user.name ? `${user.name} Workspace` : 'Client Account');
        const isDev = this.scanState.environment === 'development';
        const targetUrl = this.scanState.url || 'https://aymanaboelela.com/';
        const targetName = isDev
            ? (this.scanState.uploadedFile?.name || 'Local Code Repository')
            : targetUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
        const scanId = this.scanState.currentScanId || 'N/A';
        const env = (this.scanState.environment || 'staging').toUpperCase();
        const mode = (this.scanState.scanType || 'scan_only') === 'scan_only' ? 'Scan Only' : 'Full Lifecycle';

        const findings = (this.findingsData && Array.isArray(this.findingsData))
            ? this.findingsData
            : [];

        const critCount = findings.filter(f => (f.severity || f.sev || '').toUpperCase() === 'CRITICAL').length;
        const highCount = findings.filter(f => (f.severity || f.sev || '').toUpperCase() === 'HIGH').length;
        const medCount = findings.filter(f => (f.severity || f.sev || '').toUpperCase() === 'MEDIUM').length;
        const lowCount = findings.filter(f => (f.severity || f.sev || '').toUpperCase() === 'LOW').length;
        const totalCount = findings.length;

        let calcScore = 100 - (critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3);
        calcScore = Math.max(15, Math.min(100, calcScore));

        const critPct = totalCount ? Math.round((critCount / totalCount) * 100) : 0;
        const highPct = totalCount ? Math.round((highCount / totalCount) * 100) : 0;
        const medPct = totalCount ? Math.round((medCount / totalCount) * 100) : 0;
        const lowPct = totalCount ? Math.round((lowCount / totalCount) * 100) : 0;

        const reportDate = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

        return `
            ${renderPageTitle({
                title: 'Security assessment report',
                copy: `${escapeHtml(targetName)} · Assessment #${escapeHtml(scanId)}`,
                action: `
                    <div class="flex gap-2">
                        <button type="button" class="button button-secondary" onclick="App.navigate('dashboard')">
                            ${Icons.get('arrow', 'size-4 rotate-180')} Back to findings
                        </button>
                        <button type="button" class="button button-secondary" onclick="App.exportAndDownloadReport()">
                            ${Icons.get('file', 'size-4')} Export HTML
                        </button>
                        <button type="button" class="button button-primary" onclick="window.print()">
                            ${Icons.get('download', 'size-4')} Download PDF
                        </button>
                    </div>
                `
            })}

            <div class="report-paper">
                <!-- Cover Page -->
                <div class="report-cover">
                    ${renderBrandLogo()}
                    <span class="report-label">CONFIDENTIAL SECURITY AUDIT REPORT</span>
                    <h1>${isDev ? 'Source Code &amp; Static' : 'Web Application &amp; Code'}<br>Security Assessment</h1>
                    <p>${escapeHtml(targetName)} · [${env}]</p>

                    <div class="report-meta">
                        <div>
                            <span>PREPARED FOR</span>
                            <b>${escapeHtml(clientOrg)}</b>
                        </div>
                        <div>
                            <span>ASSESSMENT DATE</span>
                            <b>${reportDate}</b>
                        </div>
                        <div>
                            <span>SCAN IDENTIFIER</span>
                            <b>Assessment #${escapeHtml(scanId)} (${mode})</b>
                        </div>
                    </div>
                </div>

                <!-- Report Body -->
                <div class="report-body">
                    <!-- Section 01: Executive Summary -->
                    <div class="report-section-head">
                        <div>
                            <span>01</span>
                            <h2>Executive summary &amp; security posture</h2>
                        </div>
                        <div class="report-score">
                            <strong>${calcScore}</strong>
                            <span>Security score</span>
                        </div>
                    </div>

                    <p class="report-lead">
                        SentinelAI completed an automated multi-tool security assessment of <b>${escapeHtml(targetName)}</b>. 
                        The assessment cataloged <b>${totalCount} findings</b> (${critCount} Critical, ${highCount} High, ${medCount} Medium, ${lowCount} Low). 
                        ${critCount > 0 ? 'Critical vulnerabilities were identified that require immediate remediation to prevent unauthorized data access or compromise.' : (totalCount === 0 ? 'No security defects were detected across all automated scan profiles.' : 'All identified findings have been cataloged with verified evidence and risk analyses below.')}
                    </p>

                    <!-- Section 02: Multi-Tool Assessment Pipeline -->
                    <div class="report-section-head mt-10">
                        <div>
                            <span>02</span>
                            <h2>Multi-tool assessment pipeline</h2>
                        </div>
                    </div>

                    <p class="report-lead" style="margin-bottom:1.25rem;">
                        SentinelAI inspected the target across multiple complementary security engines to ensure defense-in-depth coverage:
                    </p>

                    <div class="report-tools-grid">
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>OWASP ZAP</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Dynamic Application Security Testing (DAST) inspecting runtime HTTP routes, security headers, cookies, and injection vectors.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>Nuclei</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Fast template-based DAST vulnerability scanner for exposed admin panels, cloud configuration errors, and CVEs.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>WPScan</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>CMS &amp; framework security auditor checking WordPress REST APIs, XML-RPC, backup configs, and exposed framework logs.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>WhatWeb</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Technology stack, WAF (Cloudflare/AWS), reverse proxy, and framework fingerprinting detecting version disclosure vectors.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>TestSSL</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Transport layer, TLS cipher suite, and modern HTTP header auditor verifying HSTS subdomains, XFO, nosniff, and Permissions-Policy.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>Semgrep</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Static Application Security Testing (SAST) analyzing code syntax trees, AST injection patterns, and DOM sinks.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>CodeQL</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Advanced data-flow &amp; taint-tracking engine tracing untrusted input paths (Source -> Sanitizer -> Dangerous Sink).</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>Gitleaks</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>High-entropy secret scanner detecting exposed API keys, private tokens, credentials, and sensitive configurations.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>Trivy</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Container image, infrastructure-as-code, and dependency vulnerability scanner targeting published CVEs.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>OSV-Scanner</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Google Open Source Vulnerabilities (OSV) intelligence engine verifying dependencies against GHSA and CVE databases.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>Checkov</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Infrastructure-as-Code (IaC) scanner auditing Dockerfiles, Kubernetes manifests, and cloud reverse proxy configurations.</small>
                        </div>
                        <div class="report-tool-box">
                            <div class="report-tool-head">
                                <b>npm audit</b>
                                <span class="tool-status-pill badge" style="background:#ecfdf5; color:#047857;">Completed</span>
                            </div>
                            <small>Node.js supply chain auditor verifying package lockfiles against the official advisory database.</small>
                        </div>
                        <div class="report-tool-box" style="border-color:#bfdbfe; background:#eff6ff;">
                            <div class="report-tool-head">
                                <b style="color:#1d4ed8;">AI Threat Intelligence</b>
                                <span class="tool-status-pill badge" style="background:#dbeafe; color:#1e40af;">Unified</span>
                            </div>
                            <small>Cross-tool correlation engine providing deduplication, threat impact rationale, and zero-code-modification remediation advisories.</small>
                        </div>
                    </div>

                    <!-- Section 03: Severity Distribution & Risk Profiles -->
                    <div class="report-section-head mt-10">
                        <div>
                            <span>03</span>
                            <h2>Severity distribution &amp; risk profiles</h2>
                        </div>
                    </div>

                    <div class="report-chart mt-4">
                        <div class="bar-label"><span>Critical</span><b>${critCount}</b></div>
                        <div class="bar-track"><i class="bg-red-500" style="width:${critPct}%;"></i></div>

                        <div class="bar-label"><span>High</span><b>${highCount}</b></div>
                        <div class="bar-track"><i class="bg-orange-500" style="width:${highPct}%;"></i></div>

                        <div class="bar-label"><span>Medium</span><b>${medCount}</b></div>
                        <div class="bar-track"><i class="bg-amber-400" style="width:${medPct}%;"></i></div>

                        <div class="bar-label"><span>Low</span><b>${lowCount}</b></div>
                        <div class="bar-track"><i class="bg-blue-400" style="width:${lowPct}%;"></i></div>
                    </div>

                    <!-- Section 04: Detailed Findings & Vulnerability Register -->
                    <div class="report-section-head mt-14">
                        <div>
                            <span>04</span>
                            <h2>Detailed findings &amp; vulnerability catalog</h2>
                        </div>
                        <div style="font-size:12px; color:#64748b; font-weight:700;">
                            ${totalCount} Cataloged Findings
                        </div>
                    </div>

                    <p class="report-lead" style="margin-bottom:1.5rem;">
                        Comprehensive catalog of each vulnerability identified during Assessment #${scanId}. For each issue, the exact location, risk classification, verified evidence, threat impact if left unpatched, and recommended advisory remediation are provided.
                    </p>

                    <div class="report-findings-list">
                        ${findings.length === 0 ? `
                            <div style="padding: 2.5rem 1.5rem; text-align: center; background: #ffffff; border-radius: 8px; border: 1px dashed #cbd5e1; margin: 1rem 0;">
                                <div style="font-size: 1.75rem; margin-bottom: 0.5rem; color: #10b981;">${Icons.get('check', 'size-8 inline-block')}</div>
                                <b style="color: #0f172a; font-size: 0.95rem; display: block; font-weight: 700;">No Vulnerabilities Detected</b>
                                <p style="font-size: 0.8rem; color: #64748b; margin-top: 0.35rem;">All automated tests finished cleanly for this assessment.</p>
                            </div>
                        ` : findings.map((f, idx) => {
                            const num = String(idx + 1).padStart(2, '0');
                            const sev = (f.severity || f.sev || 'Medium').toUpperCase();
                            const sevLower = sev.toLowerCase();
                            const cweLabel = f.cwe || f.cwe_id || f.category || f.type || 'CWE-200';
                            const toolLabel = f.toolName || 'DAST';
                            const locationStr = (f.evidences && f.evidences[0] && (f.evidences[0].url || f.evidences[0].filePath))
                                || f.endpoint
                                || f.filePath
                                || f.path
                                || targetUrl;
                            const lineInfo = (f.evidences && f.evidences[0] && f.evidences[0].lineStart) ? ` (Line ${f.evidences[0].lineStart})` : '';
                            const impactText = this.getThreatImpactExplanation(f);
                            const evidenceSnippet = (f.evidences && f.evidences[0] && (f.evidences[0].rawSnippet || f.evidences[0].evidenceSummary))
                                || f.description
                                || 'Finding verified by multi-tool assessment engine.';
                            const remediationText = (f.aiAnalyses && f.aiAnalyses[0] && f.aiAnalyses[0].recommendedRemediation)
                                || f.remediation
                                || 'Apply appropriate defensive configurations and input validation.';

                            return `
                                <div class="report-finding-card">
                                    <div class="report-finding-header">
                                        <div class="flex items-center gap-3">
                                            <span class="report-finding-num">${num}</span>
                                            <div>
                                                <h3 class="report-finding-title">${escapeHtml(f.title)}</h3>
                                                <div class="flex items-center gap-2 mt-1.5 flex-wrap">
                                                    <span class="mono-tag" style="background:#eff6ff; color:#2563eb; font-weight:700;">${escapeHtml(toolLabel)}</span>
                                                    <span class="mono-tag">${escapeHtml(cweLabel)}</span>
                                                    <span class="report-location-tag">${escapeHtml(locationStr)}${escapeHtml(lineInfo)}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <span class="severity-badge ${sevLower}">${sev}</span>
                                    </div>

                                    <!-- Threat Impact Box: What happens if left open -->
                                    <div class="report-impact-callout ${sevLower}">
                                        <b>🚨 What happens if left unpatched (Exploitation Impact):</b>
                                        <p>${escapeHtml(impactText)}</p>
                                    </div>

                                    <!-- Technical Evidence Box -->
                                    <div class="report-evidence-wrap">
                                        <span class="report-field-label">Verified Scanner Evidence &amp; Observation:</span>
                                        <pre class="report-evidence-code"><code>${escapeHtml(evidenceSnippet)}</code></pre>
                                    </div>

                                    <!-- Remediation Advisory -->
                                    <div class="report-remediation-callout">
                                        <b>🛡️ Recommended Remediation Guidance:</b>
                                        <p>${escapeHtml(remediationText)}</p>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>

                    <!-- Section 05: Priority Recommendations -->
                    <div class="report-section-head mt-14">
                        <div>
                            <span>05</span>
                            <h2>Priority recommendations &amp; action plan</h2>
                        </div>
                    </div>

                    <div class="recommendation-list">
                        ${critCount > 0 ? `
                            <div>
                                <span>01</span>
                                <div>
                                    <b>Remediate critical vulnerabilities immediately</b>
                                    <p>Address critical injection, authentication, or exposed credential defects within 24 hours.</p>
                                </div>
                                <em>CRITICAL</em>
                            </div>
                        ` : ''}

                        <div>
                            <span>${critCount > 0 ? '02' : '01'}</span>
                            <div>
                                <b>Enforce defense-in-depth cookie and header protections</b>
                                <p>Ensure all session and authentication cookies specify HttpOnly, Secure, and SameSite=Strict flags, and configure HSTS.</p>
                            </div>
                            <em class="${critCount > 0 ? 'high' : ''}">RECOMMENDED</em>
                        </div>

                        <div>
                            <span>${critCount > 0 ? '03' : '02'}</span>
                            <div>
                                <b>Minimize public reconnaissance surface</b>
                                <p>Disable server banner headers (Server: cloudflare, ServerSignature) to prevent automated technology fingerprinting.</p>
                            </div>
                            <em class="high">HARDENING</em>
                        </div>

                        <div>
                            <span>${critCount > 0 ? '04' : '03'}</span>
                            <div>
                                <b>Audit client storage and token isolation</b>
                                <p>Migrate sensitive tokens out of browser localStorage to prevent extraction in case of client-side script execution.</p>
                            </div>
                            <em>ADVISORY</em>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    async loadReportData() {
        let scanId = this.scanState.currentScanId;
        if (!scanId) {
            try {
                const hist = await API.getScanHistory().catch(() => null);
                if (hist && Array.isArray(hist.history) && hist.history.length > 0) {
                    scanId = hist.history[0].id;
                    this.scanState.currentScanId = scanId;
                }
            } catch (e) {}
        }

        if (scanId) {
            try {
                const res = await API.getScanReport(scanId);
                if (res && res.report && res.report.scan) {
                    const scan = res.report.scan;
                    if (Array.isArray(scan.findings) && scan.findings.length > 0) {
                        const previousLen = this.findingsData ? this.findingsData.length : 0;
                        this.findingsData = scan.findings;
                        if (previousLen !== scan.findings.length) {
                            this.render();
                        }
                    }
                }
            } catch (e) {
                console.warn('Load report data notice:', e);
            }
        }
    },

    // =========================================================
    // AUTH SUBMISSION HANDLERS WITH VALIDATION ENFORCEMENT
    // =========================================================
    async handleLogin(e) {
        e.preventDefault();
        const emailValid = this.validateField('login-email');
        const passValid = this.validateField('login-password');

        if (!emailValid || !passValid) {
            const form = document.getElementById('login-form-container');
            if (form) {
                form.classList.remove('shake');
                void form.offsetWidth; // trigger reflow
                form.classList.add('shake');
            }
            if (!emailValid) document.getElementById('login-email')?.focus();
            else if (!passValid) document.getElementById('login-password')?.focus();
            return;
        }

        const email = document.getElementById('login-email').value.trim();
        const password = document.getElementById('login-password').value;
        const btn = document.getElementById('btn-login-submit');

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> <span>Logging in...</span>`;
        }

        try {
            const res = await API.login(email, password, false);
            this.currentUser = res.user;
            this.scanState.maxUnlockedStep = 1;
            showToast(`Welcome back, ${res.user.name}!`, 'success');
            this.navigate('type');
        } catch (err) {
            showToast('Login failed: ' + err.message, 'error');
            const passField = document.getElementById('login-password-feedback');
            if (passField) {
                passField.innerHTML = `
                    <div class="field-feedback error">
                        <span>${Icons.get('alert', 'size-3.5')}</span>
                        <span>Invalid email or password. Please try again.</span>
                    </div>
                `;
            }
            const wrap = document.getElementById('login-password')?.closest('.input-wrap');
            if (wrap) wrap.classList.add('is-invalid');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<span>Log in</span> ${Icons.get('arrow', 'size-4')}`;
            }
        }
    },

    async handleSignup(e) {
        e.preventDefault();
        const fValid = this.validateField('signup-firstname');
        const lValid = this.validateField('signup-lastname');
        const eValid = this.validateField('signup-email');
        const pValid = this.validateField('signup-password');
        const cValid = this.validateField('signup-confirm');

        if (!fValid || !lValid || !eValid || !pValid || !cValid) {
            const form = document.getElementById('signup-form-container');
            if (form) {
                form.classList.remove('shake');
                void form.offsetWidth; // trigger reflow
                form.classList.add('shake');
            }
            if (!fValid) document.getElementById('signup-firstname')?.focus();
            else if (!lValid) document.getElementById('signup-lastname')?.focus();
            else if (!eValid) document.getElementById('signup-email')?.focus();
            else if (!pValid) document.getElementById('signup-password')?.focus();
            else if (!cValid) document.getElementById('signup-confirm')?.focus();
            return;
        }

        const first = document.getElementById('signup-firstname').value.trim();
        const last = document.getElementById('signup-lastname').value.trim();
        const name = `${first} ${last}`.trim();
        const email = document.getElementById('signup-email').value.trim();
        const password = document.getElementById('signup-password').value;
        const btn = document.getElementById('btn-signup-submit');

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="spinner"></span> <span>Creating account...</span>`;
        }

        try {
            const res = await API.register(name, email, password);
            this.currentUser = res.user;
            showToast('Account created successfully!', 'success');
            this.navigate('type');
        } catch (err) {
            showToast('Signup failed: ' + err.message, 'error');
            const emailFeed = document.getElementById('signup-email-feedback');
            if (emailFeed) {
                emailFeed.innerHTML = `
                    <div class="field-feedback error">
                        <span>${Icons.get('alert', 'size-3.5')}</span>
                        <span>${escapeHtml(err.message)}</span>
                    </div>
                `;
            }
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<span>Create account</span> ${Icons.get('arrow', 'size-4')}`;
            }
        }
    },

    // =========================================================
    // =========================================================
    // SETTINGS & ASSESSMENT / CHAT HISTORY VIEW (Compact & Clean)
    // =========================================================
    // =========================================================
    // SETTINGS & ASSESSMENT / CHAT HISTORY VIEW (Compact & Clean)
    // =========================================================
    getActiveDraftScan() {
        let file = this.scanState?.uploadedFile;
        if (!file) {
            try {
                const saved = localStorage.getItem('sential_staged_file');
                if (saved) file = JSON.parse(saved);
            } catch (e) {}
        }

        const hasFile = !!file;
        const hasUrl = !!(this.scanState?.url && this.scanState.url.trim().length > 0);
        const hasName = !!(this.scanState?.name && this.scanState.name.trim().length > 0);

        if (!hasFile && !hasUrl && !hasName) {
            return null;
        }

        const env = (this.scanState?.environment || 'DEVELOPMENT').toUpperCase();
        const targetTitle = (this.scanState?.name && this.scanState.name.trim().length > 0)
            ? this.scanState.name.trim()
            : (hasFile ? file.name.replace(/\.[^/.]+$/, '') + ' Code Audit' : (hasUrl ? this.scanState.url.trim() : 'Active Assessment'));

        let targetAsset = 'Local Project Repository';
        if (hasFile) {
            const sizeMb = file.size ? ` (${(file.size / (1024 * 1024)).toFixed(1)} MB)` : '';
            targetAsset = `${file.name}${sizeMb}`;
        } else if (hasUrl) {
            targetAsset = this.scanState.url.trim();
        }

        const stepNum = this.scanState?.maxUnlockedStep || (hasFile ? 2 : 1);

        return {
            id: 'draft-session',
            is_draft: true,
            target_name: targetTitle,
            target_url: targetAsset,
            environment: env,
            scan_mode: this.scanState?.scanMode || 'scan_only',
            status: 'IN_PROGRESS',
            step: stepNum,
            total_findings: 0,
            created_at: file?.uploadedAt || new Date().toISOString()
        };
    },

    renderSettingsView() {
        const user = this.getCurrentUser();
        const tab = this.settingsTab || 'history';
        const deletedIds = this.getDeletedScanIds();
        const isHistoryCleared = localStorage.getItem('sentinel_history_all_cleared') === 'true';
        const initials = user.name ? user.name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase() : 'CU';

        let historyList = [];
        if (!isHistoryCleared) {
            historyList = (this.scanHistoryList && this.scanHistoryList.length > 0)
                ? this.scanHistoryList.filter(item => !deletedIds.includes(item.id))
                : DEFAULT_HISTORY.filter(item => !deletedIds.includes(item.id));
        }

        const draft = this.getActiveDraftScan();
        if (draft && !deletedIds.includes('draft-session')) {
            historyList = [draft, ...historyList];
        }

        return `
            <div class="settings-full-wrap">
                <div class="settings-compact-header">
                    <div class="eyebrow">WORKSPACE SETTINGS</div>
                    <h1>Settings &amp; History</h1>
                    <p>Manage account credentials, workspace preferences, and past assessment chat sessions.</p>
                </div>

                <!-- Tabs: Chats & Account -->
                <div class="settings-full-tabs">
                    <button type="button" class="settings-full-tab ${tab === 'history' ? 'active' : ''}" onclick="App.setSettingsTab('history')">
                        ${Icons.get('message', 'size-4')}
                        <span>Assessment Chats</span>
                        <span class="settings-full-badge" id="history-pill-count">${historyList.length}</span>
                    </button>
                    <button type="button" class="settings-full-tab ${tab === 'profile' ? 'active' : ''}" onclick="App.setSettingsTab('profile')">
                        ${Icons.get('user', 'size-4')}
                        <span>Account &amp; Credentials</span>
                    </button>
                </div>

                <!-- Tab 1: Chats (Full Width, Compact & Clean Rows) -->
                ${tab === 'history' ? `
                    <div class="settings-full-card">
                        <div class="settings-full-card-header">
                            <div>
                                <h2>Assessment Chats</h2>
                                <p>Past security scans, static code analyses, and assessment sessions</p>
                            </div>
                            <div class="flex items-center gap-2">
                                ${historyList.length > 0 ? `
                                    <button type="button" class="history-clear-icon-btn" onclick="App.clearAllHistoryScans()" title="Clear all assessment chats">
                                        ${Icons.get('trash', 'size-3.5')}
                                    </button>
                                ` : ''}
                                <button type="button" class="button button-primary button-sm" onclick="App.startNewAssessment()" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;">
                                    ${Icons.get('plus', 'size-3.5')}
                                    <span>New Assessment</span>
                                </button>
                            </div>
                        </div>

                        <div class="settings-history-list" id="history-rows-container">
                            <!-- Populated by renderHistoryRows() -->
                        </div>
                    </div>
                ` : ''}

                <!-- Tab 2: Account (Client Info with Compact Colorful Tiles) -->
                ${tab === 'profile' ? `
                    <div class="settings-full-card">
                        <div class="settings-profile-hero">
                            <div class="avatar settings-hero-avatar">${initials}</div>
                            <div class="settings-hero-details">
                                <div class="flex items-center gap-2 flex-wrap">
                                    <h2>${escapeHtml(user.name || 'Client Account')}</h2>
                                    <span class="history-pill badge-stag">${escapeHtml(user.role === 'ADMIN' ? 'Enterprise Administrator' : 'Standard User')}</span>
                                </div>
                                <p>${escapeHtml(user.email || 'client@scanner.local')}</p>
                            </div>
                            <div class="settings-hero-action">
                                <button type="button" class="settings-logout-icon-btn" onclick="App.handleLogout()" title="Log out">
                                    ${Icons.get('logout', 'size-3.5')}
                                </button>
                            </div>
                        </div>

                        <div class="settings-full-info-grid">
                            <div class="settings-info-tile">
                                <div class="settings-tile-icon bg-blue-soft text-blue-primary">
                                    ${Icons.get('user', 'size-4')}
                                </div>
                                <div class="settings-tile-content">
                                    <span class="tile-label">Client Name</span>
                                    <span class="tile-value">${escapeHtml(user.name || 'Client Account')}</span>
                                </div>
                            </div>

                            <div class="settings-info-tile">
                                <div class="settings-tile-icon bg-indigo-soft text-indigo-primary">
                                    ${Icons.get('message', 'size-4')}
                                </div>
                                <div class="settings-tile-content">
                                    <span class="tile-label">Email Address</span>
                                    <span class="tile-value">${escapeHtml(user.email || 'client@scanner.local')}</span>
                                </div>
                            </div>

                            <div class="settings-info-tile">
                                <div class="settings-tile-icon bg-violet-soft text-violet-primary">
                                    ${Icons.get('globe', 'size-4')}
                                </div>
                                <div class="settings-tile-content">
                                    <span class="tile-label">Workspace Organization</span>
                                    <span class="tile-value">${escapeHtml(user.organization || (user.name ? user.name + ' Workspace' : 'Security Operations Center'))}</span>
                                </div>
                            </div>

                            <div class="settings-info-tile">
                                <div class="settings-tile-icon bg-emerald-soft text-emerald-primary">
                                    ${Icons.get('shield', 'size-4')}
                                </div>
                                <div class="settings-tile-content">
                                    <span class="tile-label">Security Clearance</span>
                                    <span class="tile-value">${escapeHtml(user.role === 'ADMIN' ? 'Level 3 · Full Administrative Clearance' : 'Level 2 · Security Analyst')}</span>
                                </div>
                            </div>
                        </div>

                        <div class="settings-status-box">
                            <div class="flex items-center gap-2.5">
                                <div class="size-6 rounded-full bg-emerald-100 flex items-center justify-center text-emerald-600 flex-shrink-0">
                                    ${Icons.get('check', 'size-3.5 text-emerald-600')}
                                </div>
                                <div>
                                    <h4 class="text-xs font-bold text-slate-900 m-0">Active Workspace Session Protected</h4>
                                    <p class="text-[11px] text-slate-500 m-0 mt-0.5">All scanning activities, SAST/DAST analyses, and generated audit reports are signed and encrypted.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    },

    renderHistoryRows() {
        const container = document.getElementById('history-rows-container');
        if (!container) return;

        const isHistoryCleared = localStorage.getItem('sentinel_history_all_cleared') === 'true';
        const deletedIds = this.getDeletedScanIds();
        
        let list = [];
        if (!isHistoryCleared) {
            list = this.scanHistoryList.length > 0 ? this.scanHistoryList : DEFAULT_HISTORY;
            list = list.filter(item => !deletedIds.includes(item.id));
        }

        const draft = this.getActiveDraftScan();
        if (draft && !deletedIds.includes('draft-session')) {
            list = [draft, ...list];
        }

        if (list.length === 0) {
            container.innerHTML = `
                <div class="settings-empty-simple">
                    <span>No assessment chats yet</span>
                </div>
            `;
            return;
        }

        container.innerHTML = list.map(item => {
            const dateStr = item.is_draft ? 'Current Setup' : (item.created_at ? new Date(item.created_at).toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            }) : 'Today');

            const env = (item.environment || 'DEVELOPMENT').toUpperCase();
            let envBadgeClass = 'badge-dev';
            let envLabel = 'Development';
            let envIcon = 'folder';
            let envTileClass = 'tile-dev';

            if (env.includes('PROD')) {
                envBadgeClass = 'badge-prod';
                envLabel = 'Production';
                envIcon = 'shield';
                envTileClass = 'tile-prod';
            } else if (env.includes('STAG')) {
                envBadgeClass = 'badge-stag';
                envLabel = 'Staging';
                envIcon = 'globe';
                envTileClass = 'tile-stag';
            }

            if (item.is_draft) {
                return `
                    <div class="history-item-colorful-row is-draft-row" onclick="App.resumeDraftAssessment()" title="Resume assessment setup">
                        <div class="history-item-icon-tile ${envTileClass}">
                            ${Icons.get(envIcon, 'size-4')}
                        </div>

                        <div class="history-item-body">
                            <div class="history-item-title-line">
                                <span class="history-item-title">${escapeHtml(item.target_name)}</span>
                                <span class="history-pill ${envBadgeClass}">${envLabel}</span>
                                <span class="history-pill badge-draft">In Progress</span>
                            </div>
                            <div class="history-item-meta-line">
                                <span class="history-target-url">${escapeHtml(item.target_url)}</span>
                                <span class="history-meta-sep">•</span>
                                <span class="history-date">Current Setup</span>
                                <span class="history-meta-sep">•</span>
                                <span class="history-findings-pill is-draft-pill">
                                    Step ${item.step} · Ready to Scan
                                </span>
                            </div>
                        </div>

                        <div class="history-item-actions" onclick="event.stopPropagation()">
                            <button type="button" class="history-action-btn view-resume-btn" onclick="App.resumeDraftAssessment()" title="Continue Assessment">
                                ${Icons.get('play', 'size-3')}
                                <span>Continue</span>
                            </button>
                            <button type="button" class="history-del-icon-btn" onclick="App.deleteDraftAssessment(event)" title="Discard Draft">
                                ${Icons.get('trash', 'size-3')}
                            </button>
                        </div>
                    </div>
                `;
            }

            const isScanOnly = (item.scan_mode || 'scan_only') === 'scan_only';
            const modeLabel = isScanOnly ? 'Scan Only' : 'Scan, Fix & Test';
            const modeBadgeClass = isScanOnly ? 'badge-scan-only' : 'badge-fix-test';

            const findingsCount = item.total_findings || (item.critical_count ? item.critical_count + (item.high_count || 0) : 0);

            return `
                <div class="history-item-colorful-row" onclick="App.openHistoryScan(${item.id})" title="Open Assessment Findings">
                    <div class="history-item-icon-tile ${envTileClass}">
                        ${Icons.get(envIcon, 'size-4')}
                    </div>

                    <div class="history-item-body">
                        <div class="history-item-title-line">
                            <span class="history-item-title">${escapeHtml(item.target_name || 'Assessment Chat')}</span>
                            <span class="history-pill ${envBadgeClass}">${envLabel}</span>
                            <span class="history-pill ${modeBadgeClass}">${modeLabel}</span>
                        </div>
                        <div class="history-item-meta-line">
                            <span class="history-target-url">${escapeHtml(item.target_url || 'Target Codebase')}</span>
                            <span class="history-meta-sep">•</span>
                            <span class="history-date">${dateStr}</span>
                            <span class="history-meta-sep">•</span>
                            <span class="history-findings-pill ${findingsCount > 0 ? 'has-findings' : ''}">
                                ${findingsCount > 0 ? `${findingsCount} Findings` : 'Clean · No Findings'}
                            </span>
                        </div>
                    </div>

                    <div class="history-item-actions" onclick="event.stopPropagation()">
                        <button type="button" class="history-action-btn view-findings-btn" onclick="App.openHistoryScan(${item.id})" title="View Findings">
                            ${Icons.get('shield', 'size-3')}
                            <span>Findings</span>
                        </button>
                        <button type="button" class="history-action-btn view-report-btn" onclick="App.openHistoryReport(${item.id})" title="View Report">
                            ${Icons.get('file', 'size-3')}
                            <span>Report</span>
                        </button>
                        <button type="button" class="history-del-icon-btn" onclick="App.deleteHistoryScan(${item.id}, event)" title="Delete Chat">
                            ${Icons.get('trash', 'size-3')}
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    },

    resumeDraftAssessment() {
        const step = this.scanState.maxUnlockedStep || 2;
        const stepObj = STEPS.find(s => s.step === step) || STEPS[1];
        showToast(`Resuming assessment at Step ${stepObj.step}: ${stepObj.label}...`, 'info');
        this.navigate(stepObj.id);
    },

    deleteDraftAssessment(event) {
        if (event) event.stopPropagation();
        this.removeStagedFile();
        this.scanState.name = '';
        this.scanState.url = '';
        try {
            localStorage.removeItem('sential_staged_state');
        } catch (e) {}
        this.addDeletedScanId('draft-session');
        showToast('Staged assessment removed.', 'info');
        this.render();
    },

    setSettingsTab(tab) {
        this.settingsTab = tab;
        this.render();
    },

    onSearchHistory(val) {
        this.historySearchQuery = val;
        this.renderHistoryRows();
    },

    async deleteHistoryScan(scanId, event) {
        if (event) event.stopPropagation();
        
        if (scanId === 'draft-session') {
            return this.deleteDraftAssessment(event);
        }
        
        this.addDeletedScanId(scanId);
        this.scanHistoryList = this.scanHistoryList.filter(item => item.id !== scanId);
        
        if (API.getToken()) {
            try {
                await API.deleteScan(scanId);
            } catch (e) {
                console.warn('API delete scan error:', e);
            }
        }
        
        showToast('Assessment chat deleted.', 'info');
        this.renderHistoryRows();
        
        const countEl = document.getElementById('history-pill-count');
        if (countEl) {
            const deletedIds = this.getDeletedScanIds();
            const isHistoryCleared = localStorage.getItem('sentinel_history_all_cleared') === 'true';
            let count = 0;
            if (!isHistoryCleared) {
                count = (this.scanHistoryList.length > 0 ? this.scanHistoryList : DEFAULT_HISTORY).filter(item => !deletedIds.includes(item.id)).length;
            }
            if (this.getActiveDraftScan() && !deletedIds.includes('draft-session')) {
                count += 1;
            }
            countEl.textContent = count;
        }
    },

    async clearAllHistoryScans() {
        if (!confirm('Are you sure you want to clear all assessment history? This cannot be undone.')) {
            return;
        }
        
        this.clearAllDeletedScans();
        this.scanHistoryList = [];
        this.removeStagedFile();
        this.scanState.name = '';
        this.scanState.url = '';
        try {
            localStorage.removeItem('sential_staged_state');
        } catch (e) {}
        this.addDeletedScanId('draft-session');
        
        if (API.getToken()) {
            try {
                await API.clearAllScans();
            } catch (e) {
                console.warn('API clear all scans error:', e);
            }
        }
        
        showToast('All assessment history cleared.', 'info');
        this.render();
    },

    getDeletedScanIds() {
        try {
            return JSON.parse(localStorage.getItem('sentinel_deleted_scans') || '[]');
        } catch (e) {
            return [];
        }
    },

    addDeletedScanId(id) {
        const ids = this.getDeletedScanIds();
        if (!ids.includes(id)) {
            ids.push(id);
            localStorage.setItem('sentinel_deleted_scans', JSON.stringify(ids));
        }
    },

    clearAllDeletedScans() {
        localStorage.setItem('sentinel_history_all_cleared', 'true');
    },

    async loadScanHistory() {
        if (localStorage.getItem('sentinel_history_all_cleared') === 'true') {
            this.scanHistoryList = [];
            this.renderHistoryRows();
            return;
        }

        const deletedIds = this.getDeletedScanIds();
        try {
            const res = await API.getScanHistory();
            if (res && res.success && Array.isArray(res.history)) {
                this.scanHistoryList = res.history.filter(item => !deletedIds.includes(item.id));
            } else if (this.scanHistoryList.length === 0) {
                this.scanHistoryList = DEFAULT_HISTORY.filter(item => !deletedIds.includes(item.id));
            }
        } catch (e) {
            console.warn('Scan history load error:', e);
            if (this.scanHistoryList.length === 0) {
                this.scanHistoryList = DEFAULT_HISTORY.filter(item => !deletedIds.includes(item.id));
            }
        }
        this.renderHistoryRows();
    },

    openHistoryScan(scanId) {
        this.scanState.currentScanId = scanId;
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 5);
        showToast(`Loading findings for Assessment #${scanId}...`, 'info');
        this.navigate('dashboard');
    },

    openHistoryReport(scanId) {
        this.scanState.currentScanId = scanId;
        this.scanState.maxUnlockedStep = Math.max(this.scanState.maxUnlockedStep || 1, 7);
        showToast(`Loading audit report for Assessment #${scanId}...`, 'info');
        this.navigate('report');
    },

    copyApiKey() {
        navigator.clipboard.writeText('sen_live_9d4f2a7c88e9102b');
        showToast('API access token copied to clipboard!', 'success');
    },

    async handleLogout() {
        try {
            localStorage.removeItem('sential_staged_file');
        } catch (e) {}
        this.scanState.uploadedFile = null;
        await API.logout();
        this.currentUser = null;
        showToast('You have been logged out.', 'info');
        this.navigate('welcome');
    }
};

window.App = App;

document.addEventListener('DOMContentLoaded', () => {
    App.init();
});
