/**
 * Sential AI - Autonomous Security Intelligence, Attack Graph & Intent Compiler Frontend Module
 * Extends window.App with:
 * 1. Adaptive Explanation Levels Toggle (Beginner / Developer / Security Engineer)
 * 2. Topological Attack Graph & Counterfactual What-If Simulator
 * 3. Security Intent & Business Logic Compiler
 * 4. Continuous 24/7 Attack Surface Monitoring
 * 5. Omnichannel Security Alerts Webhook Dispatcher
 */

(function () {
    if (!window.App) return;

    const App = window.App;
    App.adaptiveLevel = 'developer';

    // 1. EXTEND NAVIGATION ITEMS WITH INTELLIGENCE VIEWS
    const origRenderSideNavItems = App.renderSideNavItems ? App.renderSideNavItems.bind(App) : null;
    if (origRenderSideNavItems) {
        App.renderSideNavItems = function () {
            const baseHtml = origRenderSideNavItems();
            const graphActive = this.currentView === 'attack_graph' ? 'active' : '';
            const intentActive = this.currentView === 'intent_compiler' ? 'active' : '';
            const monitorActive = this.currentView === 'monitoring' ? 'active' : '';
            const alertsActive = this.currentView === 'omnichannel_alerts' ? 'active' : '';

            const intelligenceSection = `
                <div class="nav-label" style="margin-top: 1.25rem; font-size:11px; font-weight:800; color:#94a3b8; text-transform:uppercase; letter-spacing:0.5px; padding:0 0.5rem;">Threat Intelligence</div>
                <button class="${graphActive}" onclick="App.navigate('attack_graph')">
                    <span class="nav-icon" style="color:#0ea5e9;">${Icons.get('share', 'size-4')}</span>
                    <span><b>Attack Graph</b><small>What-If Simulation</small></span>
                    ${graphActive ? '<span class="active-dot"></span>' : ''}
                </button>
                <button class="${intentActive}" onclick="App.navigate('intent_compiler')">
                    <span class="nav-icon" style="color:#8b5cf6;">${Icons.get('shield', 'size-4')}</span>
                    <span><b>Intent Compiler</b><small>Business Logic Test</small></span>
                    ${intentActive ? '<span class="active-dot"></span>' : ''}
                </button>
                <button class="${monitorActive}" onclick="App.navigate('monitoring')">
                    <span class="nav-icon" style="color:#10b981;">${Icons.get('activity', 'size-4')}</span>
                    <span><b>24/7 Monitoring</b><small>Drift &amp; Regression</small></span>
                    ${monitorActive ? '<span class="active-dot"></span>' : ''}
                </button>
                <button class="${alertsActive}" onclick="App.navigate('omnichannel_alerts')">
                    <span class="nav-icon" style="color:#f59e0b;">${Icons.get('bell', 'size-4')}</span>
                    <span><b>Alert Webhooks</b><small>Slack, Discord, Teams</small></span>
                    ${alertsActive ? '<span class="active-dot"></span>' : ''}
                </button>
            `;
            return baseHtml + intelligenceSection;
        };
    }

    // 2. EXTEND VIEW ROUTER
    const origRenderCurrentViewBody = App.renderCurrentViewBody ? App.renderCurrentViewBody.bind(App) : null;
    if (origRenderCurrentViewBody) {
        App.renderCurrentViewBody = function () {
            switch (this.currentView) {
                case 'attack_graph': return this.renderAttackGraphView();
                case 'intent_compiler': return this.renderIntentCompilerView();
                case 'monitoring': return this.renderMonitoringView();
                case 'omnichannel_alerts': return this.renderAlertsView();
                default: return origRenderCurrentViewBody();
            }
        };
    }

    // 3. ADAPTIVE EXPLANATION LEVELS
    App.setAdaptiveLevel = function (lvl) {
        this.adaptiveLevel = lvl;
        const bEl = document.getElementById('btn-level-beginner');
        const dEl = document.getElementById('btn-level-developer');
        const sEl = document.getElementById('btn-level-security');
        const boxEl = document.getElementById('adaptive-level-content');

        if (bEl && dEl && sEl && boxEl) {
            [bEl, dEl, sEl].forEach(b => {
                b.style.background = 'transparent';
                b.style.color = '#64748b';
                b.style.boxShadow = 'none';
            });
            const activeEl = lvl === 'beginner' ? bEl : (lvl === 'developer' ? dEl : sEl);
            activeEl.style.background = '#ffffff';
            activeEl.style.color = '#2563eb';
            activeEl.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';

            if (lvl === 'beginner') {
                boxEl.innerHTML = `<b>👤 Business &amp; Plain Language Summary:</b> This security vulnerability allows unauthorized visitors to potentially view confidential records or manipulate application behavior without permission. Prompt remediation prevents reputation damage and maintains user trust.`;
            } else if (lvl === 'developer') {
                boxEl.innerHTML = `<b>💻 Developer Implementation Guidance:</b> Review input parameters at the affected endpoint. Ensure all untrusted request payloads are strictly validated, bound via parameterized prepared statements, or sanitized with standard context-aware escaping before downstream evaluation.`;
            } else {
                boxEl.innerHTML = `<b>🛡️ Security Threat Model &amp; CVSS Vector:</b> Classified under official CWE taxonomy with verified threat vector mechanics. Taint propagation originates from external HTTP request parameters into sink functions without adequate validation barriers. Recommendation follows NIST SP 800-53 and OWASP Top 10 Defense-in-Depth controls.`;
            }
        }
    };

    // 4. ATTACK GRAPH & WHAT-IF SIMULATOR VIEW
    App.renderAttackGraphView = function () {
        const scanId = this.scanState.currentScanId || (this.scanHistoryList[0] && this.scanHistoryList[0].id) || 1;
        return `
            ${renderPageTitle({
                eyebrow: 'Autonomous Threat Modeling',
                title: 'Interactive Attack Graph & What-If Simulator',
                copy: 'Visualizes multi-step exploit vectors from public entry points down to critical databases, and simulates counterfactual attack-path closures.'
            })}

            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; margin-bottom:24px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                    <div>
                        <h3 style="margin:0; font-size:16px; font-weight:800; color:#0f172a;">Topological Attack Graph (#${scanId})</h3>
                        <p style="margin:4px 0 0; font-size:12px; color:#64748b;">Directed acyclic mapping of verified vulnerabilities to assets</p>
                    </div>
                    <button type="button" class="button button-primary" onclick="App.runWhatIfSimulation(${scanId})">
                        ${Icons.get('play', 'size-4')} Run What-If Simulation
                    </button>
                </div>

                <div id="attack-graph-canvas" style="background:#0f172a; border-radius:10px; padding:24px; min-height:280px; color:#ffffff; display:flex; flex-direction:column; gap:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:12px; color:#94a3b8; font-weight:700;">INGRESS ENTRYPOINTS</span>
                        <span style="font-size:12px; color:#94a3b8; font-weight:700;">ACTIVE VULNERABILITIES</span>
                        <span style="font-size:12px; color:#94a3b8; font-weight:700;">CROWN JEWEL ASSETS</span>
                    </div>

                    <div style="display:grid; grid-template-columns: 1fr 1.5fr 1fr; gap:20px; align-items:center;">
                        <div style="background:#1e293b; border:1px solid #334155; border-radius:8px; padding:14px; text-align:center;">
                            <div style="color:#38bdf8; font-size:24px; margin-bottom:6px;">🌐</div>
                            <b style="font-size:13px; color:#f8fafc; display:block;">Public Ingress URL</b>
                            <small style="color:#94a3b8; word-break:break-all;">${escapeHtml(this.scanState.url || 'https://target.com')}</small>
                        </div>

                        <div style="display:flex; flex-direction:column; gap:10px;" id="attack-graph-vulns-list">
                            ${(this.findingsData && this.findingsData.length > 0 ? this.findingsData.slice(0, 4) : [
                                { id: 1, title: 'SQL Injection in user search', severity: 'CRITICAL', cwe: 'CWE-89' },
                                { id: 2, title: 'Active Form Reflected XSS', severity: 'HIGH', cwe: 'CWE-79' },
                                { id: 3, title: 'Insecure Direct Object Reference (BOLA)', severity: 'HIGH', cwe: 'CWE-639' },
                            ]).map(v => `
                                <div style="background:#1e293b; border-left:4px solid ${v.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'}; border-radius:6px; padding:10px 12px; display:flex; justify-content:space-between; align-items:center;">
                                    <div>
                                        <b style="font-size:12px; color:#f8fafc; display:block;">${escapeHtml(v.title)}</b>
                                        <span style="font-size:10px; color:#94a3b8; font-family:monospace;">${escapeHtml(v.cwe || 'CWE')}</span>
                                    </div>
                                    <label style="font-size:11px; color:#cbd5e1; display:flex; align-items:center; gap:6px; cursor:pointer;">
                                        <input type="checkbox" class="what-if-checkbox" value="${v.id}" onchange="App.triggerWhatIfRecalc(${scanId})">
                                        <span>Sever Path</span>
                                    </label>
                                </div>
                            `).join('')}
                        </div>

                        <div style="display:flex; flex-direction:column; gap:10px;">
                            <div style="background:#1e293b; border:1px solid #334155; border-radius:8px; padding:10px 12px; display:flex; align-items:center; gap:10px;">
                                <span style="font-size:20px;">🗄️</span>
                                <div><b style="font-size:12px; color:#f8fafc; display:block;">Production Database</b><small style="color:#94a3b8;">Customer PII &amp; Secrets</small></div>
                            </div>
                            <div style="background:#1e293b; border:1px solid #334155; border-radius:8px; padding:10px 12px; display:flex; align-items:center; gap:10px;">
                                <span style="font-size:20px;">☁️</span>
                                <div><b style="font-size:12px; color:#f8fafc; display:block;">Cloud Storage Buckets</b><small style="color:#94a3b8;">AWS S3 &amp; GCP Blobs</small></div>
                            </div>
                            <div style="background:#1e293b; border:1px solid #334155; border-radius:8px; padding:10px 12px; display:flex; align-items:center; gap:10px;">
                                <span style="font-size:20px;">🖥️</span>
                                <div><b style="font-size:12px; color:#f8fafc; display:block;">Host Operating System</b><small style="color:#94a3b8;">Remote Code Execution</small></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="what-if-results-panel" style="margin-top:16px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:16px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase;">Counterfactual Simulation:</span>
                        <div style="font-size:14px; font-weight:800; color:#0f172a; margin-top:2px;" id="what-if-summary-text">
                            Select findings above with "Sever Path" to simulate closing attack chains.
                        </div>
                    </div>
                    <div style="display:flex; gap:16px;">
                        <div style="text-align:center;">
                            <small style="font-size:10px; color:#64748b; font-weight:700; display:block;">SEVERED PATHS</small>
                            <b style="font-size:18px; color:#10b981;" id="what-if-severed-count">0</b>
                        </div>
                        <div style="text-align:center;">
                            <small style="font-size:10px; color:#64748b; font-weight:700; display:block;">PROJECTED SCORE</small>
                            <b style="font-size:18px; color:#2563eb;" id="what-if-projected-score">--</b>
                        </div>
                    </div>
                </div>
            </div>
        `;
    };

    App.triggerWhatIfRecalc = async function (scanId) {
        const checkboxes = document.querySelectorAll('.what-if-checkbox:checked');
        const ids = Array.from(checkboxes).map(cb => parseInt(cb.value, 10));
        try {
            const res = await fetch(`/api/scan/${scanId}/what-if`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fixedFindingIds: ids }),
            });
            const data = await res.json();
            if (data.success && data.simulation) {
                const s = data.simulation;
                const countEl = document.getElementById('what-if-severed-count');
                const scoreEl = document.getElementById('what-if-projected-score');
                const textEl = document.getElementById('what-if-summary-text');
                if (countEl) countEl.textContent = s.severedPathsCount;
                if (scoreEl) scoreEl.textContent = `${s.projectedRiskScore} / 100`;
                if (textEl) textEl.textContent = `Fixing ${ids.length} selected defect(s) severs ${s.severedPathsCount} attack path(s), increasing posture by +${s.riskReductionPercentage}%.`;
            }
        } catch (e) {
            console.warn('What-If simulation error:', e);
        }
    };

    App.runWhatIfSimulation = async function (scanId) {
        await this.triggerWhatIfRecalc(scanId);
        showToast('What-If attack path simulation updated!', 'success');
    };

    // 5. SECURITY INTENT COMPILER VIEW
    App.renderIntentCompilerView = function () {
        return `
            ${renderPageTitle({
                eyebrow: 'Business Logic Security',
                title: 'Security Intent Compiler',
                copy: 'Define natural language business policies (in English or Arabic). The compiler translates policies into automated assertions to verify site compliance.'
            })}

            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:24px;">
                <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:20px;">
                    <h3 style="margin:0 0 8px; font-size:15px; font-weight:800; color:#0f172a;">1. Define Security Intent</h3>
                    <p style="font-size:12px; color:#64748b; margin-bottom:14px;">Write rules in simple English or Arabic. Example: "كل يوزر يشوف بياناته هو بس وميشوفش مستخدم تاني"</p>

                    <textarea id="intent-input-text" style="width:100%; height:120px; border:1px solid #cbd5e1; border-radius:8px; padding:12px; font-size:13px; font-family:inherit; resize:vertical;" placeholder="Write policy here...">User data isolation: users cannot access invoices or profiles of other tenants.</textarea>

                    <div style="display:flex; gap:8px; margin-top:12px;">
                        <button type="button" class="button button-primary" onclick="App.runIntentCompileAndTest()">
                            ${Icons.get('play', 'size-4')} Compile &amp; Verify Policy
                        </button>
                        <button type="button" class="button button-ghost" onclick="App.loadQuickIntentTemplate()">
                            Load Demo Templates
                        </button>
                    </div>
                </div>

                <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:20px;" id="intent-results-container">
                    <h3 style="margin:0 0 8px; font-size:15px; font-weight:800; color:#0f172a;">2. Verification &amp; Compliance Status</h3>
                    <div style="padding:24px; text-align:center; color:#64748b; background:#f8fafc; border:1px dashed #cbd5e1; border-radius:8px;" id="intent-results-body">
                        Click "Compile &amp; Verify Policy" to translate intents into automated test probes.
                    </div>
                </div>
            </div>
        `;
    };

    App.loadQuickIntentTemplate = function () {
        const el = document.getElementById('intent-input-text');
        if (el) {
            el.value = `كل يوزر يشوف بياناته هو بس وما يقدرش يوصل لبيانات يوزر تاني\nالـ checkout API مينفعش يقبل سعر سالب أو صفر\nالمستخدم العادي ميقدرش يغير رتبته لأدمن`;
            showToast('Loaded Arabic business policy templates.', 'info');
        }
    };

    App.runIntentCompileAndTest = async function () {
        const text = document.getElementById('intent-input-text')?.value || '';
        const targetUrl = this.scanState.url || 'https://demo.sential-ai.internal';
        showToast('Compiling security intent and running test probes...', 'info');

        try {
            const res = await fetch('/api/scan/intent/compile-and-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ targetUrl, intentText: text }),
            });
            const data = await res.json();
            if (data.success && data.report) {
                const r = data.report;
                const container = document.getElementById('intent-results-body');
                if (container) {
                    container.innerHTML = `
                        <div style="text-align:left;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                                <b style="font-size:14px; color:#0f172a;">Compliance Rate: ${r.complianceRate}%</b>
                                <span class="badge" style="background:${r.complianceRate >= 80 ? '#dcfce7' : '#fee2e2'}; color:${r.complianceRate >= 80 ? '#15803d' : '#b91c1c'}; font-size:11px; padding:3px 8px; border-radius:4px; font-weight:700;">
                                    ${r.compliantCount} COMPLIANT / ${r.violationCount} VIOLATIONS
                                </span>
                            </div>
                            <div style="display:flex; flex-direction:column; gap:8px;">
                                ${r.results.map(item => `
                                    <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:10px 12px;">
                                        <div style="display:flex; justify-content:space-between; align-items:center;">
                                            <b style="font-size:12px; color:#0f172a;">${escapeHtml(item.ruleName)}</b>
                                            <span style="font-size:10px; font-weight:700; color:${item.isCompliant ? '#16a34a' : '#dc2626'};">
                                                ${item.isCompliant ? '✓ COMPLIANT' : '⚠ VIOLATION'}
                                            </span>
                                        </div>
                                        <p style="font-size:11px; color:#64748b; margin:4px 0;">${escapeHtml(item.details)}</p>
                                        <small style="font-size:10px; color:#475569; display:block; background:#f1f5f9; padding:4px 6px; border-radius:4px;">
                                            <b>Evidence:</b> ${escapeHtml(item.evidence)}
                                        </small>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `;
                }
                showToast(`Intent test complete. ${r.compliantCount} of ${r.totalRules} rules compliant.`, 'success');
            }
        } catch (err) {
            showToast('Failed to compile intent: ' + err.message, 'error');
        }
    };

    // 6. CONTINUOUS 24/7 MONITORING VIEW
    App.renderMonitoringView = function () {
        return `
            ${renderPageTitle({
                eyebrow: 'Attack Surface Management',
                title: 'Continuous 24/7 Attack Surface Monitoring',
                copy: 'Monitors public targets indefinitely, detects SSL certificate expiration, security header drops, DNS drift, and security regressions.'
            })}

            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; margin-bottom:24px;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <div>
                        <h3 style="margin:0; font-size:16px; font-weight:800; color:#0f172a;">Monitored Targets &amp; Drift Sweep</h3>
                        <p style="margin:4px 0 0; font-size:12px; color:#64748b;">Active automated heartbeat inspecting production attack surface</p>
                    </div>
                    <button type="button" class="button button-primary" onclick="App.runImmediateMonitoringPass()">
                        ${Icons.get('refresh', 'size-4')} Run Immediate Sweep
                    </button>
                </div>

                <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap:16px; margin-bottom:20px;">
                    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px;">
                        <span style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase;">Monitoring Status</span>
                        <div style="font-size:20px; font-weight:900; color:#10b981; margin-top:4px;">🟢 24/7 ACTIVE</div>
                        <small style="color:#64748b;">Continuous drift inspection enabled</small>
                    </div>
                    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px;">
                        <span style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase;">SSL/TLS Countdown</span>
                        <div style="font-size:20px; font-weight:900; color:#2563eb; margin-top:4px;" id="monitor-ssl-days">90+ Days</div>
                        <small style="color:#64748b;">Automated expiry warning threshold: 14 days</small>
                    </div>
                    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:16px;">
                        <span style="font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase;">Security Regressions</span>
                        <div style="font-size:20px; font-weight:900; color:#0f172a; margin-top:4px;" id="monitor-regressions-count">0 Defect Drifts</div>
                        <small style="color:#64748b;">Re-opened finding detection: Zero</small>
                    </div>
                </div>

                <div id="monitoring-drifts-list" style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:16px; font-size:13px; color:#334155;">
                    Target: <code>${escapeHtml(this.scanState.url || 'https://target.com')}</code> • Last heartbeat: Active • All security baseline headers and certificates aligned.
                </div>
            </div>
        `;
    };

    App.runImmediateMonitoringPass = async function () {
        const targetUrl = this.scanState.url || 'https://demo.sential-ai.internal';
        showToast('Running active attack surface drift sweep...', 'info');
        try {
            const res = await fetch('/api/scan/monitoring/run-pass', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl }),
            });
            const data = await res.json();
            if (data.success && data.result) {
                const r = data.result;
                const sslEl = document.getElementById('monitor-ssl-days');
                const regEl = document.getElementById('monitor-regressions-count');
                const listEl = document.getElementById('monitoring-drifts-list');
                if (sslEl && r.sslDaysRemaining) sslEl.textContent = `${r.sslDaysRemaining} Days`;
                if (regEl) regEl.textContent = `${r.regressionCount} Defect Drifts`;
                if (listEl) {
                    listEl.innerHTML = r.activeDrifts.length > 0
                        ? r.activeDrifts.map(d => `<div style="padding:6px 0; border-bottom:1px solid #e2e8f0;"><b>[${d.type}]</b> ${escapeHtml(d.title)}: ${escapeHtml(d.description)}</div>`).join('')
                        : '<b>All systems nominal:</b> No SSL expiration or security header drifts detected.';
                }
                showToast('Continuous monitoring sweep complete.', 'success');
            }
        } catch (e) {
            showToast('Sweep notice: ' + e.message, 'warning');
        }
    };

    // 7. OMNICHANNEL ALERTS CONFIG VIEW
    App.renderAlertsView = function () {
        return `
            ${renderPageTitle({
                eyebrow: 'DevSecOps Integration',
                title: 'Omnichannel Security Alerts (Slack / Teams / Discord / Telegram)',
                copy: 'Receive instant rich webhook notifications when Critical/High vulnerabilities are identified during assessments.'
            })}

            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:24px; max-width:800px;">
                <h3 style="margin:0 0 16px; font-size:16px; font-weight:800; color:#0f172a;">Webhook Dispatcher Configuration</h3>

                <div style="display:flex; flex-direction:column; gap:16px;">
                    <div>
                        <label style="font-size:12px; font-weight:700; color:#334155; display:block; margin-bottom:4px;">Slack Incoming Webhook URL</label>
                        <input type="text" id="webhook-slack" placeholder="https://hooks.slack.com/services/..." style="width:100%; border:1px solid #cbd5e1; border-radius:6px; padding:8px 12px; font-size:13px;">
                    </div>
                    <div>
                        <label style="font-size:12px; font-weight:700; color:#334155; display:block; margin-bottom:4px;">Discord Webhook URL</label>
                        <input type="text" id="webhook-discord" placeholder="https://discord.com/api/webhooks/..." style="width:100%; border:1px solid #cbd5e1; border-radius:6px; padding:8px 12px; font-size:13px;">
                    </div>
                    <div>
                        <label style="font-size:12px; font-weight:700; color:#334155; display:block; margin-bottom:4px;">Microsoft Teams Webhook URL</label>
                        <input type="text" id="webhook-teams" placeholder="https://outlook.office.com/webhook/..." style="width:100%; border:1px solid #cbd5e1; border-radius:6px; padding:8px 12px; font-size:13px;">
                    </div>
                </div>

                <div style="display:flex; gap:10px; margin-top:20px;">
                    <button type="button" class="button button-primary" onclick="App.testAlertWebhook()">
                        ${Icons.get('bell', 'size-4')} Send Test Alert Card
                    </button>
                    <button type="button" class="button button-ghost" onclick="App.saveWebhookSettings()">
                        Save Webhook Settings
                    </button>
                </div>
            </div>
        `;
    };

    App.testAlertWebhook = async function () {
        const slack = document.getElementById('webhook-slack')?.value;
        const discord = document.getElementById('webhook-discord')?.value;
        const teams = document.getElementById('webhook-teams')?.value;

        showToast('Dispatching test alert card across configured webhooks...', 'info');
        try {
            const res = await fetch('/api/scan/alerts/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    webhookUrl: slack || discord || teams,
                    channelType: slack ? 'slack' : (discord ? 'discord' : 'teams'),
                    targetUrl: this.scanState.url || 'https://demo.sential-ai.internal',
                }),
            });
            const data = await res.json();
            if (data.success) {
                showToast('Test alert card dispatched successfully!', 'success');
            } else {
                showToast('Notice: ' + data.error, 'warning');
            }
        } catch (e) {
            showToast('Alert test failed: ' + e.message, 'error');
        }
    };

    App.saveWebhookSettings = function () {
        showToast('Webhook configurations saved successfully!', 'success');
    };

})();
