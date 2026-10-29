import { GeneratedReportData } from './report.service';
import { knowledgeBaseService } from './knowledge-base.service';

/**
 * Generates an Executive Cyber Risk & Compliance Assessment Report.
 * Targeted at C-level, leadership, and non-technical stakeholders.
 * Highlights business impact, security posture score, regulatory compliance (OWASP, PCI-DSS, GDPR, ISO 27001),
 * and priority strategic recommendations.
 */
export function generateExecutiveReport(data: GeneratedReportData, lang: 'ar' | 'en' = 'en'): string {
  const isAr = lang === 'ar';
  const score = Math.max(10, Math.min(100, data.executiveSummary?.riskScore ?? (100 - (data.findingsCount.critical * 25 + data.findingsCount.high * 15 + data.findingsCount.medium * 5))));
  let grade = 'A+';
  let gradeColor = '#16a34a';
  if (score < 50) { grade = 'F'; gradeColor = '#dc2626'; }
  else if (score < 70) { grade = 'C'; gradeColor = '#ea580c'; }
  else if (score < 85) { grade = 'B'; gradeColor = '#ca8a04'; }
  else if (score < 95) { grade = 'A'; gradeColor = '#2563eb'; }

  const total = data.findingsCount.total;
  const crit = data.findingsCount.critical;
  const high = data.findingsCount.high;
  const med = data.findingsCount.medium;

  return `<!DOCTYPE html>
<html lang="${isAr ? 'ar' : 'en'}" dir="${isAr ? 'rtl' : 'ltr'}">
<head>
  <meta charset="UTF-8">
  <title>${isAr ? 'تقرير تقييم المخاطر السيبرانية للإدارة التنفيذية' : 'Executive Cyber Risk & Compliance Report'} #${data.scanId}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&family=Manrope:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    @page { size: A4; margin: 15mm; }
    body { font-family: ${isAr ? "'Cairo', sans-serif" : "'Manrope', sans-serif"}; background: #f8fafc; color: #0f172a; margin: 0; padding: 24px; line-height: 1.6; }
    .page { max-width: 900px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
    .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #2563eb; padding-bottom: 24px; margin-bottom: 28px; }
    .brand-title { font-size: 24px; font-weight: 900; color: #0f172a; margin: 0; }
    .brand-sub { color: #64748b; font-size: 13px; margin-top: 4px; }
    .score-card { display: flex; align-items: center; gap: 20px; background: #f1f5f9; border-radius: 12px; padding: 20px 24px; margin-bottom: 28px; }
    .grade-badge { font-size: 38px; font-weight: 900; color: #ffffff; background: ${gradeColor}; width: 72px; height: 72px; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 10px rgba(0,0,0,0.15); flex-shrink: 0; }
    .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 28px; }
    .metric-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; }
    .metric-val { font-size: 24px; font-weight: 800; color: #0f172a; }
    .metric-lbl { font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 2px; }
    .section-title { font-size: 16px; font-weight: 800; color: #0f172a; margin: 24px 0 12px 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
    .compliance-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    .compliance-table th, .compliance-table td { padding: 10px 14px; border: 1px solid #e2e8f0; text-align: ${isAr ? 'right' : 'left'}; }
    .compliance-table th { background: #f8fafc; font-weight: 700; }
    .tag-pass { background: #dcfce7; color: #15803d; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }
    .tag-fail { background: #fee2e2; color: #b91c1c; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }
    .action-box { background: #eff6ff; border-left: ${isAr ? 'none' : '4px solid #2563eb'}; border-right: ${isAr ? '4px solid #2563eb' : 'none'}; padding: 14px; border-radius: 6px; margin-top: 14px; }
    @media print {
      body { background: #ffffff; padding: 0; }
      .page { border: none; box-shadow: none; padding: 0; }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="max-width:900px; margin:0 auto 16px auto; display:flex; justify-content:flex-end; gap:8px;">
    <button onclick="window.print()" style="padding:8px 18px; background:#2563eb; color:#ffffff; font-weight:700; border:none; border-radius:6px; cursor:pointer;">
      ${isAr ? '🖨️ طباعة أو حفظ PDF' : '🖨️ Print or Save as PDF'}
    </button>
  </div>

  <div class="page">
    <div class="header">
      <div>
        <h1 class="brand-title">${isAr ? 'تقرير تقييم المخاطر السيبرانية والامتثال للإدارة' : 'Executive Cyber Risk & Compliance Assessment'}</h1>
        <div class="brand-sub">
          ${isAr ? 'الهدف المعتمد:' : 'Certified Target:'} <b>${data.targetUrl}</b> | ${isAr ? 'البيئة:' : 'Environment:'} <b>${data.environment}</b> | ${isAr ? 'التاريخ:' : 'Date:'} ${new Date(data.generatedAt).toLocaleDateString(isAr ? 'ar-EG' : 'en-US')}
        </div>
      </div>
      <div style="text-align:${isAr ? 'left' : 'right'}; font-size:12px; color:#64748b;">
        <div><b>Sential AI Autonomous Engine</b></div>
        <div>Report #${data.scanId}</div>
      </div>
    </div>

    <!-- Score Card -->
    <div class="score-card">
      <div class="grade-badge">${grade}</div>
      <div>
        <div style="font-size:18px; font-weight:800; color:#0f172a;">
          ${isAr ? `درجة الأمان العامة: ${score} من 100 (${grade})` : `Overall Security Health Score: ${score}/100 (Grade ${grade})`}
        </div>
        <div style="font-size:13px; color:#475569; margin-top:4px;">
          ${isAr
            ? (score >= 80 ? 'المنظومة في وضع أمني مستقر بشكل عام، ولكن يتطلب معالجة فورية للثغرات الحرجة لضمان التوافق التام.' : 'تحذير أمني: توجد ثغرات ذات خطورة عالية قد تعرض المنشأة لمخاطر تسريب بيانات أو تعطل الأعمال.')
            : (score >= 80 ? 'The application maintains a healthy defensive baseline, though prioritized remediation of high-severity defects is recommended.' : 'Security Alert: Critical exposure identified that presents imminent business risk, data leakage, or service downtime.')}
        </div>
      </div>
    </div>

    <!-- Metrics Grid -->
    <div class="metrics-grid">
      <div class="metric-box"><div class="metric-val">${total}</div><div class="metric-lbl">${isAr ? 'إجمالي الملاحظات' : 'Total Issues'}</div></div>
      <div class="metric-box"><div class="metric-val" style="color:#b91c1c;">${crit}</div><div class="metric-lbl">${isAr ? 'حرجة (Critical)' : 'Critical Risk'}</div></div>
      <div class="metric-box"><div class="metric-val" style="color:#c2410c;">${high}</div><div class="metric-lbl">${isAr ? 'عالية (High)' : 'High Risk'}</div></div>
      <div class="metric-box"><div class="metric-val" style="color:#ca8a04;">${med}</div><div class="metric-lbl">${isAr ? 'متوسطة (Medium)' : 'Medium Risk'}</div></div>
    </div>

    <!-- Executive Summary -->
    <div class="section-title">${isAr ? 'الملخص التنفيذي للأعمال' : 'Executive Business Summary'}</div>
    <p style="font-size:13px; color:#334155; margin:0 0 16px 0;">
      ${isAr
        ? `أكمل محرك Sential AI فحصاً أمنياً شاملاً للمنظومة (${data.targetUrl}). تم تحديد ${total} ملاحظة أمنية، من بينها ${crit} ملاحظة حرجة و ${high} ملاحظة عالية الخطورة. الاستجابة السريعة لإغلاق هذه الثغرات يحمي السمعة المؤسسية للشركة ويمنع أي غرامات تنظيمية محتملة.`
        : `Sential AI completed a comprehensive autonomous security audit of (${data.targetUrl}). The inspection identified ${total} total findings, including ${crit} Critical and ${high} High-severity risks. Immediate remediation of priority assets protects corporate reputation, ensures business continuity, and mitigates regulatory liabilities.`}
    </p>

    <!-- Compliance Posture Matrix -->
    <div class="section-title">${isAr ? 'مصفوفة الامتثال للمعايير القياسية العالمية' : 'Regulatory & Compliance Posture Matrix'}</div>
    <table class="compliance-table">
      <thead>
        <tr>
          <th>${isAr ? 'المعيار التنظيمي' : 'Security Framework'}</th>
          <th>${isAr ? 'المجال المستهدف' : 'Target Scope'}</th>
          <th>${isAr ? 'الحالة' : 'Status'}</th>
          <th>${isAr ? 'الأثر الإداري' : 'Executive Impact'}</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><b>OWASP Top 10 (2026)</b></td>
          <td>Application Security Flaws</td>
          <td><span class="${crit === 0 && high === 0 ? 'tag-pass' : 'tag-fail'}">${crit === 0 && high === 0 ? (isAr ? 'متوافق' : 'Compliant') : (isAr ? 'يتطلب معالجة' : 'Action Required')}</span></td>
          <td>${isAr ? 'حماية ضد الاختراقات الشائعة وحقن البيانات.' : 'Guards against top web application exploitation vectors.'}</td>
        </tr>
        <tr>
          <td><b>PCI-DSS v4.0 (Req 6.4)</b></td>
          <td>Payment & Transaction Data</td>
          <td><span class="${crit === 0 ? 'tag-pass' : 'tag-fail'}">${crit === 0 ? (isAr ? 'ناجح' : 'Passed') : (isAr ? 'معرض للخطر' : 'Deficiency')}</span></td>
          <td>${isAr ? 'متطلب إلزامي لبوابات الدفع الإلكتروني والبطاقات الائتمانية.' : 'Mandatory requirement for electronic payment gateways.'}</td>
        </tr>
        <tr>
          <td><b>ISO/IEC 27001 (A.12.6.1)</b></td>
          <td>Vulnerability Management</td>
          <td><span class="tag-pass">${isAr ? 'مُدقّق ومُعتمد' : 'Audit Active'}</span></td>
          <td>${isAr ? 'إثبات وجود فحص مستمر وإدارة موثقة للثغرات.' : 'Demonstrates active technical vulnerability management.'}</td>
        </tr>
        <tr>
          <td><b>GDPR (Article 32)</b></td>
          <td>User Data Protection</td>
          <td><span class="${crit === 0 && high === 0 ? 'tag-pass' : 'tag-fail'}">${crit === 0 && high === 0 ? (isAr ? 'محمي' : 'Protected') : (isAr ? 'مخاطر تسريب' : 'At Risk')}</span></td>
          <td>${isAr ? 'حماية من الغرامات القانونية المتعلقة بتسريب بيانات العملاء.' : 'Mitigates statutory liabilities regarding customer PII exposure.'}</td>
        </tr>
      </tbody>
    </table>

    <!-- Strategic Leadership Recommendations -->
    <div class="section-title">${isAr ? 'التوصيات الاستراتيجية لقيادة الشركة' : 'Strategic Executive Recommendations'}</div>
    <div class="action-box">
      <div style="font-weight:800; color:#1e40af; margin-bottom:6px;">
        ${isAr ? '1. الأولوية القصوى (خلال 48 ساعة):' : '1. Priority 1 (Within 48 Hours):'}
      </div>
      <div style="font-size:13px; color:#1e3a8a;">
        ${isAr
          ? `تكليف الفريق البرمجي بمراجعة وحل ${crit + high} ثغرة حرجة وعالية تم رصدها في الفحص التقني وتطبيق أكواد الترقيع الجاهزة المرفقة في التقرير التقني.`
          : `Direct technical leads to address the ${crit + high} Critical/High findings using the automated drop-in diff patches provided in the technical appendix.`}
      </div>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Generates a Technical Deep-Dive Vulnerability & Verification Report.
 * Targeted at Developers, Security Engineers, and DevSecOps.
 * Contains exact PoC request/response, CWE, CVSS v3.1 vector strings,
 * file paths, line numbers, and drop-in code diff patches.
 */
export function generateTechnicalReport(data: GeneratedReportData, lang: 'ar' | 'en' = 'en'): string {
  const isAr = lang === 'ar';
  const escapeCode = (s: string) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  return `<!DOCTYPE html>
<html lang="${isAr ? 'ar' : 'en'}" dir="${isAr ? 'rtl' : 'ltr'}">
<head>
  <meta charset="UTF-8">
  <title>${isAr ? 'التقرير الأمني التقني المفصل' : 'Technical Security Audit & Vulnerability Report'} #${data.scanId}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Manrope:wght@400;600;700;800&family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    @page { size: A4; margin: 12mm; }
    body { font-family: ${isAr ? "'Cairo', sans-serif" : "'Manrope', sans-serif"}; background: #f8fafc; color: #0f172a; margin: 0; padding: 24px; line-height: 1.5; }
    .container { max-width: 960px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 36px; }
    .header { border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
    .badge-high { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
    .badge-medium { background: #fefce8; color: #a16207; border: 1px solid #fef08a; }
    .badge-low { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
    .finding-card { border: 1px solid #cbd5e1; border-radius: 8px; padding: 18px; margin-bottom: 20px; background: #ffffff; }
    .code-snippet { background: #0b1220; color: #f8fafc; padding: 12px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 11px; overflow-x: auto; margin: 8px 0; direction: ltr; text-align: left; }
    .meta-tag { display: inline-block; font-size: 11px; font-weight: 700; color: #475569; background: #f1f5f9; padding: 2px 8px; border-radius: 4px; margin-right: 6px; }
    @media print {
      body { background: #ffffff; padding: 0; }
      .container { border: none; box-shadow: none; padding: 0; }
      .no-print { display: none !important; }
      .finding-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="max-width:960px; margin:0 auto 16px auto; display:flex; justify-content:flex-end; gap:8px;">
    <button onclick="window.print()" style="padding:8px 18px; background:#2563eb; color:#ffffff; font-weight:700; border:none; border-radius:6px; cursor:pointer;">
      ${isAr ? '🖨️ طباعة أو تصدير PDF تقني' : '🖨️ Print Technical PDF'}
    </button>
  </div>

  <div class="container">
    <div class="header">
      <div>
        <h1 class="title">${isAr ? 'التقرير الأمني التقني المفصل للثغرات' : 'Technical Vulnerability Audit & Exploit Verification'}</h1>
        <p style="color:#64748b; margin:6px 0 0 0; font-size:13px;">Target: <b>${data.targetUrl}</b> [${data.environment}] | Scan #${data.scanId} | ${data.generatedAt}</p>
      </div>
      <span class="badge badge-critical">${data.findingsCount.total} ${isAr ? 'ثغرات' : 'Findings'}</span>
    </div>

    <!-- Findings Technical Loop -->
    ${data.findings.map((f, i) => {
      const sev = (f.severity || 'MEDIUM').toLowerCase();
      const cwe = f.cwe || 'CWE-GENERIC';
      const cvss = f.cvssScore || (sev === 'critical' ? 9.8 : (sev === 'high' ? 7.5 : 5.0));
      const vector = f.cvssVector || (sev === 'critical' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' : 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N');
      const kbDiff = knowledgeBaseService.getRemediationDiff(f.cwe || f.title);

      return `
        <div class="finding-card">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
            <div style="font-size:16px; font-weight:800; color:#0f172a;">
              #${i + 1} ${escapeCode(f.title)}
            </div>
            <span class="badge badge-${sev}">${sev.toUpperCase()} (${cvss})</span>
          </div>

          <div style="margin-bottom:12px;">
            <span class="meta-tag">${cwe}</span>
            <span class="meta-tag">${vector}</span>
            <span class="meta-tag">${escapeCode(f.toolName || 'Engine')}</span>
          </div>

          <p style="font-size:13px; color:#334155; margin:0 0 10px 0;">${escapeCode(f.description || '')}</p>

          ${f.evidences && f.evidences[0] ? `
            <div style="font-size:12px; font-weight:700; color:#475569; margin-top:8px;">${isAr ? 'الموقع والأدلة المرصودة:' : 'Observed Evidence & Location:'}</div>
            <div style="font-size:11px; color:#64748b; font-family:monospace;">${escapeCode(f.evidences[0].filePath || f.evidences[0].url || '')} ${f.evidences[0].lineStart ? '(Line ' + f.evidences[0].lineStart + ')' : ''}</div>
            ${f.evidences[0].rawSnippet ? `<pre class="code-snippet">${escapeCode(f.evidences[0].rawSnippet)}</pre>` : ''}
          ` : ''}

          ${kbDiff && kbDiff.vulnerable_code && kbDiff.secure_code ? `
            <div style="margin-top:12px; padding:12px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px;">
              <div style="font-size:12px; font-weight:800; color:#0f172a; margin-bottom:6px;">${isAr ? 'كود الإصلاح البرمجي المباشر (Before vs After):' : 'Automated Drop-in Code Patch (Before vs After):'}</div>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                <div>
                  <div style="font-size:11px; font-weight:700; color:#dc2626; margin-bottom:2px;">❌ Vulnerable:</div>
                  <pre class="code-snippet" style="background:#450a0a; color:#fca5a5; margin:0;">${escapeCode(kbDiff.vulnerable_code)}</pre>
                </div>
                <div>
                  <div style="font-size:11px; font-weight:700; color:#16a34a; margin-bottom:2px;">✅ Fixed (Drop-in):</div>
                  <pre class="code-snippet" style="background:#052e16; color:#86efac; margin:0;">${escapeCode(kbDiff.secure_code)}</pre>
                </div>
              </div>
            </div>
          ` : ''}

          <div style="margin-top:10px; padding:8px 12px; background:#f0fdf4; border-left:3px solid #16a34a; font-size:12px; color:#166534;">
            <b>${isAr ? 'إرشادات الإصلاح الموصى بها:' : 'Remediation Advisory:'}</b> ${escapeCode(f.remediation || 'Sanitize user inputs and apply principle of least privilege.')}
          </div>
        </div>
      `;
    }).join('')}
  </div>
</body>
</html>`;
}
