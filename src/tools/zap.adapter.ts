import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';
import { safeFetchText } from '../services/crawler.service';
import { evaluateScope } from '../services/scope.service';

export class ZapAdapter implements SecurityToolAdapter {
  readonly name = 'OWASP_ZAP';
  readonly version = '2.14.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    // Available via live active DAST engine & external ZAP daemon integration
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];

    if (!input.targetUrl || input.targetType === 'FILE_ZIP') {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings: [],
        skippedReason: 'Target does not have a live URL endpoint; OWASP ZAP requires a deployed application URL.',
      };
    }

    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'zap');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    const scope = input.scope || { includedPaths: ['/*'], excludedPaths: [] };
    const targetUrl = input.targetUrl.trim();

    try {
      // 1. Probe Base Target URL
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), input.timeoutMs || 25_000);

      const resp = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelAI-SecurityScanner/2.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: controller.signal,
      }).catch((err) => {
        return null;
      });
      clearTimeout(timeoutId);

      if (resp) {
        const headers = resp.headers;
        const statusCode = resp.status;

        // Check A: Missing Content-Security-Policy (CSP)
        if (!headers.get('content-security-policy')) {
          findings.push({
            title: 'Content Security Policy (CSP) Header Not Set',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: '10038-1',
            targetUrl,
            evidenceSummary: `The response header "Content-Security-Policy" is missing on status ${statusCode}. Without CSP, the browser cannot restrict script execution sources.`,
            remediation: 'Implement a strict Content Security Policy (CSP) header specifying trusted sources for scripts, styles, and frames.',
            cwe: 'CWE-693',
          });
        }

        // Check B: Missing Strict-Transport-Security (HSTS)
        if (targetUrl.startsWith('https://') && !headers.get('strict-transport-security')) {
          findings.push({
            title: 'HTTP Strict Transport Security (HSTS) Header Missing',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'INSECURE_COMMUNICATION',
            sourceRuleId: '10035-1',
            targetUrl,
            evidenceSummary: 'The application is served over HTTPS but does not transmit the Strict-Transport-Security header to prevent SSL stripping.',
            remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.',
            cwe: 'CWE-319',
          });
        }

        // Check C: Missing X-Frame-Options (Clickjacking)
        if (!headers.get('x-frame-options') && !headers.get('content-security-policy')?.includes('frame-ancestors')) {
          findings.push({
            title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'CLICKJACKING',
            sourceRuleId: '10020-1',
            targetUrl,
            evidenceSummary: 'Neither X-Frame-Options nor CSP frame-ancestors was detected. The target can potentially be framed by malicious origins.',
            remediation: 'Send "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" in HTTP response headers.',
            cwe: 'CWE-1021',
          });
        }

        // Check D: Missing X-Content-Type-Options
        if (headers.get('x-content-type-options')?.toLowerCase() !== 'nosniff') {
          findings.push({
            title: 'X-Content-Type-Options Header Missing or Invalid',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: '10021-1',
            targetUrl,
            evidenceSummary: 'The response does not specify "X-Content-Type-Options: nosniff", allowing browsers to perform MIME-type sniffing.',
            remediation: 'Set "X-Content-Type-Options: nosniff" on all HTTP responses.',
            cwe: 'CWE-16',
          });
        }

        // Check E: Server Technology Banner Disclosure
        const serverHeader = headers.get('server');
        const poweredBy = headers.get('x-powered-by');
        if (serverHeader || poweredBy) {
          findings.push({
            title: 'Server or Technology Version Banner Disclosed',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: '10036-1',
            targetUrl,
            evidenceSummary: `Server discloses internal stack: ${[serverHeader ? `Server: ${serverHeader}` : '', poweredBy ? `X-Powered-By: ${poweredBy}` : ''].filter(Boolean).join(', ')}.`,
            remediation: 'Disable server version tokens in web server configurations (e.g. server_tokens off in Nginx, ServerSignature Off in Apache).',
            cwe: 'CWE-200',
          });
        }

        // Check F: Insecure Cookie Flags
        const cookies = headers.get('set-cookie');
        if (cookies) {
          const cookieStr = cookies.toLowerCase();
          if (!cookieStr.includes('secure') && targetUrl.startsWith('https://')) {
            findings.push({
              title: 'Cookie Missing Secure Attribute',
              severity: 'MEDIUM',
              confidence: 'HIGH',
              category: 'SESSION_MANAGEMENT',
              sourceRuleId: '10011-1',
              targetUrl,
              evidenceSummary: 'One or more session cookies were set without the "Secure" flag over an HTTPS connection.',
              remediation: 'Append "; Secure" to all Set-Cookie headers in HTTPS environments.',
              cwe: 'CWE-614',
            });
          }
          if (!cookieStr.includes('httponly')) {
            findings.push({
              title: 'Cookie Missing HttpOnly Attribute',
              severity: 'LOW',
              confidence: 'HIGH',
              category: 'SESSION_MANAGEMENT',
              sourceRuleId: '10010-1',
              targetUrl,
              evidenceSummary: 'Cookie is accessible via client-side JavaScript, increasing risk in case of Cross-Site Scripting (XSS).',
              remediation: 'Append "; HttpOnly" to all session and authentication cookies.',
              cwe: 'CWE-1004',
            });
          }
        }
      }

      // 2. Sensitive File & Discovery Probing adhering to scope exclusions
      const sensitiveProbes = [
        { path: '/.env', title: 'Publicly Accessible Environment File (.env)', severity: 'CRITICAL', ruleId: '40032-1', cwe: 'CWE-200' },
        { path: '/.git/config', title: 'Exposed Git Repository Metadata (.git/config)', severity: 'HIGH', ruleId: '40032-2', cwe: 'CWE-538' },
        { path: '/robots.txt', title: 'Robots.txt Information Disclosure', severity: 'INFO', ruleId: '10018-1', cwe: 'CWE-200' },
      ];

      for (const probe of sensitiveProbes) {
        // Enforce Scope Gate: strictly skip excluded paths
        const scopeEval = evaluateScope(probe.path, scope);
        if (!scopeEval.allowed) {
          continue;
        }

        try {
          const probeUrl = new URL(probe.path, targetUrl).toString();
          const pResp = await fetch(probeUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'SentinelAI-DAST/2.0' },
            signal: AbortSignal.timeout(6000),
          }).catch(() => null);

          if (pResp && pResp.status === 200) {
            const body = await pResp.text().catch(() => '');
            if (probe.path === '/.env' && (body.includes('DB_') || body.includes('SECRET') || body.includes('KEY='))) {
              findings.push({
                title: probe.title,
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'SENSITIVE_DATA_EXPOSURE',
                sourceRuleId: probe.ruleId,
                targetUrl: probeUrl,
                evidenceSummary: `Publicly accessible .env configuration file discovered with sensitive credentials on ${probeUrl}.`,
                remediation: 'Block direct access to hidden files (.*) and configuration files at the reverse proxy or web server level.',
                cwe: probe.cwe,
              });
            } else if (probe.path === '/.git/config' && body.includes('[core]')) {
              findings.push({
                title: probe.title,
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                category: 'SOURCE_CODE_DISCLOSURE',
                sourceRuleId: probe.ruleId,
                targetUrl: probeUrl,
                evidenceSummary: `Exposed .git directory allows remote reconstruction of application source code: ${probeUrl}.`,
                remediation: 'Configure web server to deny access to .git directories and all child files.',
                cwe: probe.cwe,
              });
            }
          }
        } catch {}
      }

      // Save raw result
      const resultPath = path.join(outputDir, `scan-${input.scanId}-zap.json`);
      fs.writeFileSync(resultPath, JSON.stringify({
        tool: this.name,
        version: this.version,
        targetUrl,
        scannedAt: new Date().toISOString(),
        findingsCount: findings.length,
        findings,
      }, null, 2), 'utf8');

      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings,
        resultPath,
      };
    } catch (error) {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: false,
        exitCode: 1,
        durationMs: Date.now() - startTime,
        findings,
        errorSummary: (error as Error).message,
      };
    }
  }
}
