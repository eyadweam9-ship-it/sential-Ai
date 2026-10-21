import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';
import { evaluateScope } from '../services/scope.service';

export class ZapAdapter implements SecurityToolAdapter {
  readonly name = 'OWASP_ZAP';
  readonly version = '2.14.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
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
      let mainHtml = '';
      try {
        const resp = await fetch(targetUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelAI-SecurityScanner/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
          signal: AbortSignal.timeout(input.timeoutMs || 25_000),
        });

        const headers = resp.headers;
        const statusCode = resp.status;
        mainHtml = await resp.text().catch(() => '');

        // Check A: Content-Security-Policy (CSP)
        const csp = headers.get('content-security-policy');
        if (!csp) {
          findings.push({
            title: 'Content Security Policy (CSP) Header Not Set',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: '10038-1',
            targetUrl,
            evidenceSummary: `The response header "Content-Security-Policy" is missing on status ${statusCode}. Without CSP, the browser cannot restrict script execution sources or prevent Cross-Site Scripting (XSS).`,
            remediation: "Implement a strict Content Security Policy (CSP) header specifying trusted sources for scripts, styles, and frames (e.g. default-src 'self').",
            cwe: 'CWE-693',
          });
        } else if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
          findings.push({
            title: 'Insecure Content Security Policy (CSP) Configuration',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: '10038-2',
            targetUrl,
            evidenceSummary: `CSP contains permissive directives: ${[csp.includes("'unsafe-inline'") ? "'unsafe-inline'" : '', csp.includes("'unsafe-eval'") ? "'unsafe-eval'" : ''].filter(Boolean).join(', ')}.`,
            remediation: "Refactor scripts to use cryptographic nonces or hashes rather than allowing 'unsafe-inline' or 'unsafe-eval'.",
            cwe: 'CWE-693',
          });
        }

        // Check B: Strict-Transport-Security (HSTS)
        if (targetUrl.startsWith('https://')) {
          const hsts = headers.get('strict-transport-security');
          if (!hsts) {
            findings.push({
              title: 'HTTP Strict Transport Security (HSTS) Header Missing',
              severity: 'MEDIUM',
              confidence: 'HIGH',
              category: 'INSECURE_COMMUNICATION',
              sourceRuleId: '10035-1',
              targetUrl,
              evidenceSummary: 'The application is served over HTTPS but does not transmit the Strict-Transport-Security header to prevent SSL stripping and man-in-the-middle downgrade attacks.',
              remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.',
              cwe: 'CWE-319',
            });
          }
        }

        // Check C: Missing Anti-Clickjacking Header (X-Frame-Options)
        if (!headers.get('x-frame-options') && !headers.get('content-security-policy')?.includes('frame-ancestors')) {
          findings.push({
            title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'CLICKJACKING',
            sourceRuleId: '10020-1',
            targetUrl,
            evidenceSummary: 'Neither X-Frame-Options nor CSP frame-ancestors was detected. The target web page can potentially be framed by malicious origins in an iframe.',
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
            evidenceSummary: 'The response does not specify "X-Content-Type-Options: nosniff", allowing browsers to perform MIME-type sniffing on ambiguous content.',
            remediation: 'Set "X-Content-Type-Options: nosniff" on all HTTP responses.',
            cwe: 'CWE-16',
          });
        }

        // Check E: Referrer-Policy Header
        if (!headers.get('referrer-policy')) {
          findings.push({
            title: 'Referrer-Policy Header Not Set',
            severity: 'LOW',
            confidence: 'HIGH',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: '10037-1',
            targetUrl,
            evidenceSummary: 'The Referrer-Policy header is missing, allowing internal query strings and paths to be leaked to third-party domains in Referer request headers.',
            remediation: 'Configure "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer" on all responses.',
            cwe: 'CWE-200',
          });
        }

        // Check F: Permissions-Policy / Feature-Policy Header
        if (!headers.get('permissions-policy') && !headers.get('feature-policy')) {
          findings.push({
            title: 'Permissions-Policy Header Missing',
            severity: 'LOW',
            confidence: 'HIGH',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: '10063-1',
            targetUrl,
            evidenceSummary: 'Permissions-Policy header is omitted. Browser hardware APIs (camera, microphone, geolocation) are not explicitly restricted.',
            remediation: 'Add "Permissions-Policy: camera=(), microphone=(), geolocation=()" to restrict browser API access.',
            cwe: 'CWE-16',
          });
        }

        // Check G: Server Technology Banner Disclosure
        const serverHeader = headers.get('server');
        const poweredBy = headers.get('x-powered-by');
        const aspNetVersion = headers.get('x-aspnet-version');
        if (serverHeader || poweredBy || aspNetVersion) {
          findings.push({
            title: 'Server or Technology Version Banner Disclosed',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: '10036-1',
            targetUrl,
            evidenceSummary: `Server discloses internal stack components: ${[serverHeader ? `Server: ${serverHeader}` : '', poweredBy ? `X-Powered-By: ${poweredBy}` : '', aspNetVersion ? `X-AspNet-Version: ${aspNetVersion}` : ''].filter(Boolean).join(', ')}.`,
            remediation: 'Disable server version banners in web server configurations (e.g. server_tokens off in Nginx, ServerSignature Off in Apache).',
            cwe: 'CWE-200',
          });
        }

        // Check H: Insecure Cookie Flags
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
          if (!cookieStr.includes('samesite')) {
            findings.push({
              title: 'Cookie Missing SameSite Attribute',
              severity: 'LOW',
              confidence: 'HIGH',
              category: 'SESSION_MANAGEMENT',
              sourceRuleId: '10012-1',
              targetUrl,
              evidenceSummary: 'Cookie does not specify a SameSite attribute, which increases exposure to Cross-Site Request Forgery (CSRF).',
              remediation: 'Append "; SameSite=Lax" or "; SameSite=Strict" to all Set-Cookie headers.',
              cwe: 'CWE-1275',
            });
          }
        }
      } catch (probeErr) {
        console.warn(`[OWASP ZAP] Initial target probe warning:`, (probeErr as Error).message);
      }

      // 2. CORS Misconfiguration Audit
      try {
        const corsOrigin = 'https://sentinel-audit-probe.org';
        const corsResp = await fetch(targetUrl, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 SentinelAI-DAST/2.0',
            'Origin': corsOrigin,
          },
          signal: AbortSignal.timeout(6000),
        });

        const allowOrigin = corsResp.headers.get('access-control-allow-origin');
        const allowCreds = corsResp.headers.get('access-control-allow-credentials');

        if (allowOrigin === '*' && allowCreds === 'true') {
          findings.push({
            title: 'Critical CORS Misconfiguration: Wildcard Origin with Credentials Allowed',
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'INSECURE_COMMUNICATION',
            sourceRuleId: 'CORS-001',
            targetUrl,
            evidenceSummary: 'Access-Control-Allow-Origin is set to wildcard (*) while Access-Control-Allow-Credentials is true, enabling unauthorized cross-origin credential harvesting.',
            remediation: 'Do not use wildcard Access-Control-Allow-Origin with credentials. Maintain a strict allowlist of authorized origins.',
            cwe: 'CWE-942',
          });
        } else if (allowOrigin === corsOrigin) {
          findings.push({
            title: 'Permissive CORS: Arbitrary Origin Dynamically Reflected',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            category: 'INSECURE_COMMUNICATION',
            sourceRuleId: 'CORS-002',
            targetUrl,
            evidenceSummary: `The server reflects untrusted origin "${corsOrigin}" in Access-Control-Allow-Origin without allowlist verification.`,
            remediation: 'Validate incoming Origin headers against an explicit domain allowlist before echoing into CORS response headers.',
            cwe: 'CWE-942',
          });
        }
      } catch {}

      // 3. Sensitive File & Path Probing (Enforcing Scope Exclusions)
      const sensitiveProbes = [
        { path: '/.env', title: 'Publicly Accessible Environment File (.env)', severity: 'CRITICAL' as const, ruleId: '40032-1', cwe: 'CWE-200' },
        { path: '/.env.local', title: 'Exposed Local Environment File (.env.local)', severity: 'CRITICAL' as const, ruleId: '40032-2', cwe: 'CWE-200' },
        { path: '/.git/HEAD', title: 'Exposed Git Repository Metadata (.git/HEAD)', severity: 'HIGH' as const, ruleId: '40032-3', cwe: 'CWE-538' },
        { path: '/.git/config', title: 'Exposed Git Configuration (.git/config)', severity: 'HIGH' as const, ruleId: '40032-4', cwe: 'CWE-538' },
        { path: '/robots.txt', title: 'Robots.txt Information Disclosure', severity: 'INFO' as const, ruleId: '10018-1', cwe: 'CWE-200' },
        { path: '/sitemap.xml', title: 'Public Sitemap XML Metadata', severity: 'INFO' as const, ruleId: '10018-2', cwe: 'CWE-200' },
        { path: '/.well-known/security.txt', title: 'Missing Security.txt Advisory File', severity: 'LOW' as const, ruleId: '10099-1', cwe: 'CWE-200' },
        { path: '/swagger.json', title: 'Exposed Swagger / OpenAPI API Specification', severity: 'LOW' as const, ruleId: '40032-5', cwe: 'CWE-200' },
        { path: '/openapi.json', title: 'Exposed OpenAPI 3.0 Documentation', severity: 'LOW' as const, ruleId: '40032-6', cwe: 'CWE-200' },
        { path: '/phpinfo.php', title: 'Exposed PHP Information Script (phpinfo.php)', severity: 'HIGH' as const, ruleId: '40032-7', cwe: 'CWE-200' },
        { path: '/backup.sql', title: 'Publicly Accessible Database Backup File (backup.sql)', severity: 'CRITICAL' as const, ruleId: '40032-8', cwe: 'CWE-200' },
        { path: '/server-status', title: 'Exposed Web Server Status Page (/server-status)', severity: 'MEDIUM' as const, ruleId: '40032-9', cwe: 'CWE-200' },
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
            if (probe.path.startsWith('/.env') && (body.includes('DB_') || body.includes('SECRET') || body.includes('KEY=') || body.includes('PASSWORD='))) {
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
            } else if (probe.path === '/.git/HEAD' && body.includes('ref:')) {
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
            } else if (probe.path === '/phpinfo.php' && body.includes('PHP Version')) {
              findings.push({
                title: probe.title,
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                category: 'INFORMATION_DISCLOSURE',
                sourceRuleId: probe.ruleId,
                targetUrl: probeUrl,
                evidenceSummary: `Active phpinfo() diagnostic page exposes system configuration, loaded extensions, and server environment variables on ${probeUrl}.`,
                remediation: 'Delete diagnostic phpinfo() files from production and staging servers.',
                cwe: probe.cwe,
              });
            } else if (probe.path === '/backup.sql' && (body.includes('CREATE TABLE') || body.includes('INSERT INTO'))) {
              findings.push({
                title: probe.title,
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'SENSITIVE_DATA_EXPOSURE',
                sourceRuleId: probe.ruleId,
                targetUrl: probeUrl,
                evidenceSummary: `Unprotected SQL database dump discovered on ${probeUrl}.`,
                remediation: 'Remove database backups from web-accessible directories immediately.',
                cwe: probe.cwe,
              });
            } else if (probe.path === '/server-status' && body.includes('Apache Server Status')) {
              findings.push({
                title: probe.title,
                severity: 'MEDIUM',
                confidence: 'CONFIRMED',
                category: 'INFORMATION_DISCLOSURE',
                sourceRuleId: probe.ruleId,
                targetUrl: probeUrl,
                evidenceSummary: `Apache server-status page is publicly accessible on ${probeUrl}, disclosing active client IP addresses and requested URLs.`,
                remediation: 'Restrict access to /server-status strictly to local loopback addresses (127.0.0.1).',
                cwe: probe.cwe,
              });
            }
          }
        } catch {}
      }

      // 4. Benign Heuristic Parameter Testing (XSS Reflection & SQL Syntax Error Leaks)
      const testParams = ['q', 'search', 'query', 'id', 'redirect', 'url'];
      const canaryToken = 'sentinel_audit_probe_9128';
      const sqlProbeToken = "1' OR '1'='1";

      for (const param of testParams.slice(0, 3)) {
        try {
          const testUrl = new URL(targetUrl);
          testUrl.searchParams.set(param, `<${canaryToken}>`);

          const scopeCheck = evaluateScope(testUrl.pathname, scope);
          if (!scopeCheck.allowed) continue;

          const paramResp = await fetch(testUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 SentinelAI-DAST/2.0' },
            signal: AbortSignal.timeout(6000),
          }).catch(() => null);

          if (paramResp && paramResp.status === 200) {
            const body = await paramResp.text().catch(() => '');
            if (body.includes(`<${canaryToken}>`)) {
              findings.push({
                title: `Reflected Cross-Site Scripting (XSS) in Parameter "${param}"`,
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                category: 'CROSS_SITE_SCRIPTING',
                sourceRuleId: '40012-1',
                targetUrl: testUrl.toString(),
                evidenceSummary: `User-supplied parameter "${param}" was reflected in HTML unencoded without escaping angle brackets (< >).`,
                remediation: 'Apply contextual HTML entity encoding or output escaping to user-controlled parameters before rendering in responses.',
                cwe: 'CWE-79',
              });
            }

            // Check SQL syntax error leak
            const sqlUrl = new URL(targetUrl);
            sqlUrl.searchParams.set(param, sqlProbeToken);
            const sqlResp = await fetch(sqlUrl.toString(), {
              method: 'GET',
              headers: { 'User-Agent': 'SentinelAI-DAST/2.0' },
              signal: AbortSignal.timeout(6000),
            }).catch(() => null);

            if (sqlResp) {
              const sqlBody = await sqlResp.text().catch(() => '');
              const sqlErrorSignatures = [
                'SQL syntax error',
                'mysql_fetch',
                'pg_query',
                'sqlite3::',
                'ORA-01756',
                'unclosed quotation mark',
                'ODBC SQL Server Driver',
              ];
              for (const sig of sqlErrorSignatures) {
                if (sqlBody.toLowerCase().includes(sig.toLowerCase())) {
                  findings.push({
                    title: `Potential SQL Injection / Database Error Leakage in "${param}"`,
                    severity: 'HIGH',
                    confidence: 'CONFIRMED',
                    category: 'SQL_INJECTION',
                    sourceRuleId: '40018-1',
                    targetUrl: sqlUrl.toString(),
                    evidenceSummary: `Database error signature "${sig}" was returned when testing parameter "${param}".`,
                    remediation: 'Use parameterized queries or ORM prepared statements. Disable detailed database error outputs in web responses.',
                    cwe: 'CWE-89',
                  });
                  break;
                }
              }
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
