import fs from 'fs';
import path from 'path';
import { prisma } from '../config/db';
import { generateScanExecutiveSummary } from './ai-analysis.service';
import { compareWithPreviousScan } from './findings-deduplication.service';

export interface GeneratedReportData {
  reportId: number;
  scanId: number;
  targetUrl: string;
  environment: string;
  scanStatus: string;
  generatedAt: string;
  executiveSummary: any;
  toolsExecution: any[];
  findingsCount: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: any[];
  comparison: any;
  htmlReportPath?: string;
  jsonReportPath?: string;
}

export async function generateScanReport(scanId: number): Promise<GeneratedReportData> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      target: true,
      tasks: {
        include: { executions: true },
      },
      findings: {
        include: { evidences: true, aiAnalyses: true },
      },
    },
  });

  if (!scan) {
    throw new Error(`Scan #${scanId} not found.`);
  }

  const reportsDir = path.join(process.cwd(), 'storage', 'reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  // 1. Executive Summary & AI Intelligence
  const executiveSummary = await generateScanExecutiveSummary(scanId);

  // 2. Cross-Scan Comparison
  const comparison = await compareWithPreviousScan(scan.targetId, scanId);

  // 3. Severity Distribution
  const counts = {
    total: scan.findings.length,
    critical: scan.findings.filter(f => f.severity === 'CRITICAL').length,
    high: scan.findings.filter(f => f.severity === 'HIGH').length,
    medium: scan.findings.filter(f => f.severity === 'MEDIUM').length,
    low: scan.findings.filter(f => f.severity === 'LOW').length,
    info: scan.findings.filter(f => f.severity === 'INFO').length,
  };

  const reportPayload: GeneratedReportData = {
    reportId: 0,
    scanId: scan.id,
    targetUrl: scan.target.url,
    environment: scan.environment,
    scanStatus: scan.status,
    generatedAt: new Date().toISOString(),
    executiveSummary,
    toolsExecution: scan.tasks.map(t => ({
      toolName: t.toolName,
      status: t.status,
      startedAt: t.startedAt,
      finishedAt: t.finishedAt,
      errorMessage: t.errorMessage,
      executions: t.executions,
    })),
    findingsCount: counts,
    findings: scan.findings,
    comparison,
  };

  // Save JSON report file
  const jsonPath = path.join(reportsDir, `report-scan-${scanId}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(reportPayload, null, 2), 'utf8');

  // Save HTML report file
  const htmlPath = path.join(reportsDir, `report-scan-${scanId}.html`);
  const htmlContent = generatePrintableHtmlReport(reportPayload);
  fs.writeFileSync(htmlPath, htmlContent, 'utf8');

  reportPayload.jsonReportPath = `/storage/reports/report-scan-${scanId}.json`;
  reportPayload.htmlReportPath = `/storage/reports/report-scan-${scanId}.html`;

  // Persist record in database
  const reportRecord = await prisma.report.create({
    data: {
      projectId: scan.target.projectId,
      scanId: scan.id,
      title: `Security Assessment Report - ${scan.target.name || scan.target.url}`,
      reportUrl: reportPayload.htmlReportPath,
      format: 'HTML',
      storagePath: htmlPath,
      summaryJson: JSON.stringify({
        counts,
        executiveSummary,
        comparison: {
          newCount: comparison.newFindingsCount,
          recurrentCount: comparison.recurrentFindingsCount,
          fixedCount: comparison.fixedFindingsCount,
        },
      }),
    },
  });

  reportPayload.reportId = reportRecord.id;
  return reportPayload;
}

function generatePrintableHtmlReport(data: GeneratedReportData): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelAI Security Assessment Report #${data.scanId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #0f172a; margin: 0; padding: 32px; background: #f8fafc; }
    .container { max-width: 960px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px; }
    .header { border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 26px; font-weight: 800; color: #0f172a; margin: 0; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    .badge-high { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
    .badge-medium { background: #fefce8; color: #a16207; border: 1px solid #fef08a; }
    .badge-low { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
    .badge-info { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; margin-bottom: 20px; }
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }
    .stat-box { background: #f1f5f9; border-radius: 8px; padding: 16px; text-align: center; }
    .stat-val { font-size: 28px; font-weight: 800; color: #0f172a; }
    .stat-lbl { font-size: 12px; color: #64748b; font-weight: 600; text-transform: uppercase; }
    .finding-card { border: 1px solid #cbd5e1; border-radius: 8px; padding: 20px; margin-bottom: 16px; background: #ffffff; }
    .code-snippet { background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; margin-top: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { padding: 10px; border-bottom: 1px solid #e2e8f0; text-align: left; }
    th { background: #f8fafc; font-weight: 700; color: #475569; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 class="title">SentinelAI Security Assessment</h1>
        <p style="color:#64748b; margin:6px 0 0 0; font-size:14px;">Target: <b>${data.targetUrl}</b> [${data.environment}] · Generated: ${data.generatedAt}</p>
      </div>
      <span class="badge ${data.scanStatus === 'COMPLETED' ? 'badge-low' : 'badge-high'}">${data.scanStatus}</span>
    </div>

    <!-- Stats -->
    <div class="stat-grid">
      <div class="stat-box"><div class="stat-val">${data.findingsCount.total}</div><div class="stat-lbl">Total Findings</div></div>
      <div class="stat-box"><div class="stat-val" style="color:#b91c1c;">${data.findingsCount.critical}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat-box"><div class="stat-val" style="color:#c2410c;">${data.findingsCount.high}</div><div class="stat-lbl">High</div></div>
      <div class="stat-box"><div class="stat-val" style="color:#2563eb;">${data.executiveSummary.riskScore}/100</div><div class="stat-lbl">Security Score</div></div>
    </div>

    <!-- Executive Summary -->
    <div class="card">
      <h3 style="margin-top:0; color:#0f172a;">AI Threat Intelligence & Executive Summary</h3>
      <p style="font-size:13px; color:#334155;"><b>Overall Posture:</b> ${data.executiveSummary.overallPosture.replace('_', ' ')}</p>
      <p style="font-size:13px; color:#334155;">${data.executiveSummary.assessmentLimitations}</p>
      <h4 style="font-size:13px; margin-bottom:6px;">Recommended Prioritized Actions (Advisory):</h4>
      <ul style="font-size:12px; color:#475569; padding-left:20px; margin:0;">
        ${data.executiveSummary.remediationPriorities.map((p: string) => `<li>${p}</li>`).join('')}
      </ul>
    </div>

    <!-- Tool Execution Matrix -->
    <h3>Multi-Tool Verification Matrix</h3>
    <table>
      <thead>
        <tr>
          <th>Tool Name</th>
          <th>Status</th>
          <th>Execution Time</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        ${data.toolsExecution.map(t => `
          <tr>
            <td><b>${t.toolName}</b></td>
            <td><span class="badge ${t.status === 'COMPLETED' ? 'badge-low' : (t.status === 'SKIPPED' ? 'badge-info' : 'badge-high')}">${t.status}</span></td>
            <td>${t.executions && t.executions[0] ? `${t.executions[0].durationMs}ms` : '—'}</td>
            <td style="color:#64748b; font-size:11px;">${t.errorMessage || (t.status === 'COMPLETED' ? 'Executed with clean output' : 'N/A')}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <!-- Detailed Findings -->
    <h3 style="margin-top:36px;">Verified Vulnerabilities &amp; Findings Catalog</h3>
    ${data.findings.length === 0 ? '<p style="color:#15803d; font-weight:600;">No security findings detected for this assessment.</p>' : ''}
    ${data.findings.map((f, idx) => {
      const loc = (f.evidences && f.evidences[0] && (f.evidences[0].url || f.evidences[0].filePath)) || data.targetUrl || '/';
      const line = (f.evidences && f.evidences[0] && f.evidences[0].lineStart) ? ` (Line ${f.evidences[0].lineStart})` : '';
      const impact = (f.aiAnalyses && f.aiAnalyses[0] && f.aiAnalyses[0].impact) 
        || 'If left unpatched, this vulnerability expands the attack surface, degrades security baselines, and can be leveraged by attackers to compromise system confidentiality, integrity, or availability.';
      const rem = (f.aiAnalyses && f.aiAnalyses[0] && f.aiAnalyses[0].recommendedRemediation) || f.remediation || 'Apply appropriate security configurations and input validation.';

      return `
      <div class="finding-card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h4 style="margin:0; font-size:15px; color:#0f172a;">${idx + 1}. ${f.title}</h4>
          <span class="badge badge-${(f.severity || 'low').toLowerCase()}">${f.severity}</span>
        </div>
        <p style="font-size:11px; color:#64748b; margin:4px 0 8px 0;">Discovered by <b>${f.toolName}</b> · Rule: ${f.sourceRuleId || 'N/A'} · ${f.cwe || 'CWE-200'} · Confidence: ${f.confidence}</p>
        <p style="font-size:12px; font-family:monospace; color:#3b82f6; margin:0 0 8px 0; word-break:break-all;"><b>Target Location:</b> ${loc}${line}</p>
        <p style="font-size:13px; color:#334155; margin:0 0 10px 0;">${f.description || ''}</p>
        
        <!-- Threat Impact: What happens if left open -->
        <div style="margin:10px 0; padding:10px 12px; background:#fff7ed; border-left:4px solid #ea580c; border-radius:4px; font-size:12px; color:#9a3412;">
          <b>🚨 What happens if left unpatched (Exploitation Impact):</b>
          <p style="margin:4px 0 0 0; color:#7c2d12;">${impact}</p>
        </div>

        ${f.evidences && f.evidences[0] ? `
          <div style="font-size:12px; color:#475569; margin-top:8px;"><b>Observed Evidence:</b> ${f.evidences[0].evidenceSummary || ''}</div>
          ${f.evidences[0].rawSnippet ? `<pre class="code-snippet">${f.evidences[0].rawSnippet}</pre>` : ''}
        ` : ''}

        <div style="margin-top:10px; padding:10px 12px; background:#f0fdf4; border-left:4px solid #16a34a; border-radius:4px; font-size:12px; color:#14532d;">
          <b>🛡️ Recommended Remediation Guidance (Advisory):</b>
          <p style="margin:4px 0 0 0; color:#166534;">${rem}</p>
        </div>
      </div>
    `}).join('')}
  </div>
</body>
</html>`;
}
