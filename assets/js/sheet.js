// =========================================================
// SentinelAI - Google Sheets Interactive Spreadsheet View
// Renders findings with colored pills, formula bar, & English headers
// =========================================================

const GoogleSheetView = {
    findings: [],
    activeCell: { row: 1, col: 'A', value: '' },

    init(findings) {
        this.findings = findings || [];
        this.render();
    },

    setFindings(findings) {
        this.findings = findings || [];
        this.render();
    },

    render() {
        const container = document.getElementById('google-sheet-container');
        if (!container) return;

        const count = this.findings.length;
        const criticalCount = this.findings.filter(f => f.severity === 'critical').length;
        const highCount = this.findings.filter(f => f.severity === 'high').length;
        const mediumCount = this.findings.filter(f => f.severity === 'medium').length;

        container.innerHTML = `
            <div class="sheet-container">
                <!-- Google Sheets Top Bar -->
                <div class="sheet-topbar">
                    <div class="sheet-title-wrap">
                        ${Icons.get('sheet', 'sheet-icon')}
                        <h3 class="sheet-title">SentinelAI_Findings_Master_Sheet.xlsx</h3>
                        <span class="sheet-badge">LIVE SYNCED</span>
                    </div>

                    <div class="sheet-toolbar">
                        <select id="sheet-filter-severity" class="sheet-tool-btn" onchange="GoogleSheetView.onFilterChange(this.value)">
                            <option value="">All Severities (${count})</option>
                            <option value="critical">Critical (${criticalCount})</option>
                            <option value="high">High (${highCount})</option>
                            <option value="medium">Medium (${mediumCount})</option>
                        </select>

                        <button class="sheet-tool-btn" onclick="GoogleSheetView.refreshData()">
                            ${Icons.get('refresh', 'size-3.5')}
                            <span>Refresh</span>
                        </button>

                        <button class="sheet-tool-btn primary" onclick="GoogleSheetView.exportCSV()">
                            ${Icons.get('download', 'size-3.5')}
                            <span>Export CSV (Google Sheet)</span>
                        </button>
                    </div>
                </div>

                <!-- Formula Bar -->
                <div class="sheet-formula-bar">
                    <span id="sheet-cell-addr" class="sheet-cell-address">A2</span>
                    <span class="sheet-fx-symbol">fx</span>
                    <input id="sheet-formula-val" class="sheet-formula-input" type="text" readonly 
                           value='=FINDING("SQL Injection in user search", SEVERITY="CRITICAL")'>
                </div>

                <!-- Spreadsheet Grid -->
                <div class="sheet-grid-wrapper">
                    <table class="sheet-table" id="sheet-main-table">
                        <thead>
                            <!-- Column Letters Row -->
                            <tr>
                                <th class="sheet-row-num"></th>
                                <th>A</th>
                                <th>B</th>
                                <th>C</th>
                                <th>D</th>
                                <th>E</th>
                                <th>F</th>
                                <th>G</th>
                                <th>H</th>
                                <th>I</th>
                            </tr>
                            <!-- English Column Headers Row -->
                            <tr>
                                <th class="sheet-row-num">1</th>
                                <th>Finding Title</th>
                                <th>CWE Identifier</th>
                                <th>Vulnerability Category</th>
                                <th>Target Endpoint</th>
                                <th>Parameter</th>
                                <th>Severity Level</th>
                                <th>CVSS Score</th>
                                <th>Status</th>
                                <th>First Detected</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.renderRows()}
                        </tbody>
                    </table>
                </div>

                <!-- Sheet Footer with Tabs & Formula Summary -->
                <div class="sheet-footer">
                    <div class="sheet-tabs">
                        <div class="sheet-tab">Findings Assessment (Sheet1)</div>
                    </div>
                    <div class="sheet-stats-summary">
                        <span>Total Rows: <b>${count}</b></span>
                        <span>=COUNTIF(Severity, "CRITICAL"): <b style="color:#dc2626">${criticalCount}</b></span>
                        <span>=COUNTIF(Severity, "HIGH"): <b style="color:#ea580c">${highCount}</b></span>
                        <span>=AVERAGE(CVSS): <b>${this.calcAvgCvss()}</b></span>
                    </div>
                </div>
            </div>
        `;

        this.bindCellClicks();
    },

    renderRows() {
        if (!this.findings || this.findings.length === 0) {
            return `<tr><td colspan="10" style="text-align:center; padding:2rem; color:#94a3b8;">No findings match your spreadsheet filter.</td></tr>`;
        }

        return this.findings.map((f, idx) => {
            const rowNum = idx + 2; // Row 1 is header
            const sev = (f.severity || 'info').toLowerCase();
            const statusKey = (f.status || 'open').toLowerCase().replace('_', '-');

            return `
                <tr data-finding-id="${f.id}" data-row="${rowNum}">
                    <td class="sheet-row-num">${rowNum}</td>
                    <td data-col="A" class="font-bold text-slate-800" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'A', '${escapeHtml(f.title)}')" ondblclick="App.viewFinding(${f.id})">
                        ${escapeHtml(f.title)}
                    </td>
                    <td data-col="B" class="font-mono text-slate-600" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'B', '${escapeHtml(f.cwe_id || 'N/A')}')">
                        ${escapeHtml(f.cwe_id || 'N/A')}
                    </td>
                    <td data-col="C" class="text-slate-600" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'C', '${escapeHtml(f.category || '')}')">
                        ${f.scanCategory ? `<span style="font-size:10px; font-weight:700; color:#2563eb; background:#eff6ff; padding:1px 5px; border-radius:4px; margin-right:4px;">${escapeHtml(f.scanCategory)}</span>` : ''}${escapeHtml(f.category || '')}
                    </td>
                    <td data-col="D" class="font-mono text-blue-700" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'D', '${escapeHtml(f.endpoint || '')}')">
                        ${escapeHtml(f.endpoint || '')}
                    </td>
                    <td data-col="E" class="font-mono text-slate-500" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'E', '${escapeHtml(f.parameter || 'N/A')}')">
                        ${escapeHtml(f.parameter || 'N/A')}
                    </td>
                    <td data-col="F" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'F', '${sev.toUpperCase()}')">
                        <span class="sheet-pill sheet-pill-${sev}">${sev}</span>
                    </td>
                    <td data-col="G" class="font-bold text-center" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'G', '${f.cvss_score || '0.0'}')">
                        ${f.cvss_score || '0.0'}
                    </td>
                    <td data-col="H" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'H', '${escapeHtml(f.status || 'open')}')">
                        <span class="sheet-pill sheet-pill-status-${statusKey}">
                            ${escapeHtml(formatStatus(f.status))}
                        </span>
                    </td>
                    <td data-col="I" class="text-slate-500 font-mono text-xs" onclick="GoogleSheetView.selectCell(this, ${rowNum}, 'I', '${escapeHtml(f.first_detected_at || '')}')">
                        ${escapeHtml(f.first_detected_at || '')}
                    </td>
                </tr>
            `;
        }).join('');
    },

    selectCell(cellEl, row, col, value) {
        document.querySelectorAll('.sheet-active-cell').forEach(el => el.classList.remove('sheet-active-cell'));
        cellEl.classList.add('sheet-active-cell');

        const addrEl = document.getElementById('sheet-cell-addr');
        const formValEl = document.getElementById('sheet-formula-val');
        if (addrEl) addrEl.textContent = `${col}${row}`;
        if (formValEl) formValEl.value = value;
    },

    bindCellClicks() {
        const firstCell = document.querySelector('#sheet-main-table tbody tr td[data-col="A"]');
        if (firstCell) {
            firstCell.classList.add('sheet-active-cell');
        }
    },

    calcAvgCvss() {
        if (!this.findings || this.findings.length === 0) return '0.0';
        const sum = this.findings.reduce((acc, curr) => acc + parseFloat(curr.cvss_score || 0), 0);
        return (sum / this.findings.length).toFixed(1);
    },

    async onFilterChange(sev) {
        try {
            const scanId = (typeof App !== 'undefined' && App.scanState?.currentScanId) ? App.scanState.currentScanId : undefined;
            const res = await API.getFindings({ severity: sev, scan_id: scanId });
            this.setFindings(res.findings);
        } catch (e) {
            console.error(e);
        }
    },

    async refreshData() {
        try {
            const filter = document.getElementById('sheet-filter-severity')?.value || '';
            const scanId = (typeof App !== 'undefined' && App.scanState?.currentScanId) ? App.scanState.currentScanId : undefined;
            const res = await API.getFindings({ severity: filter, scan_id: scanId });
            this.setFindings(res.findings);
            showToast('Spreadsheet data refreshed successfully!', 'success');
        } catch (e) {
            showToast('Failed to refresh data: ' + e.message, 'error');
        }
    },

    exportCSV() {
        const token = API.getToken();
        const scanId = (typeof App !== 'undefined' && App.scanState?.currentScanId) ? App.scanState.currentScanId : '';
        const exportUrl = `/api/findings/export-csv?token=${encodeURIComponent(token || '')}${scanId ? `&scan_id=${encodeURIComponent(scanId)}` : ''}`;
        const a = document.createElement('a');
        a.href = exportUrl;
        a.download = `SentinelAI_Findings_${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        showToast('Google Sheet CSV downloaded!', 'success');
    }
};

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatStatus(status) {
    if (!status) return 'Open';
    if (status === 'confirmed') return 'Fix ready';
    if (status === 'in_progress') return 'Reviewing';
    return status.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
}

window.GoogleSheetView = GoogleSheetView;
