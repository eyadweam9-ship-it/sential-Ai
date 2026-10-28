import fs from 'fs';
import path from 'path';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface AccessControlAuditResult {
  findings: RawToolFinding[];
  exposedFilesCount: number;
  unauthenticatedAdminRoutes: string[];
}

/**
 * Access Control, Admin Portal & Credential Exposure Auditor
 * 1. Probes for Unauthenticated Administrative Interfaces (CWE-306)
 * 2. Probes for Reverse Proxy & Normalization Authentication Bypasses (CWE-285)
 *    (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, path normalization)
 * 3. Probes for Exposed Stored Databases & Password Files (CWE-200 / CWE-530)
 *    (SQLite databases, SQL dumps, .env files, debug logs)
 * 4. Probes for Excessive Data Exposure in API Endpoints (CWE-213 / OWASP API3)
 *    (Detects leaked password hashes, salts, and secrets in JSON responses)
 */
export class AccessControlAuditorService {
  public static async audit(
    targetUrlStr: string,
    scanId: number,
    sessionCookie?: string,
    authHeader?: string
  ): Promise<AccessControlAuditResult> {
    const result: AccessControlAuditResult = {
      findings: [],
      exposedFilesCount: 0,
      unauthenticatedAdminRoutes: [],
    };

    let targetUrl: URL;
    try {
      targetUrl = new URL(targetUrlStr.trim());
    } catch {
      targetUrl = new URL(`https://${targetUrlStr.trim()}`);
    }

    const outputDir = path.join(process.cwd(), 'storage', 'extracted-sources', `scan-${scanId}`);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // =========================================================================
    // 1. Unauthenticated Administrative Console Hunter (CWE-306)
    // =========================================================================
    const adminCandidatePaths = [
      '/admin',
      '/admin/',
      '/administrator',
      '/admin/dashboard',
      '/admin/users',
      '/admin/settings',
      '/admin/panel',
      '/panel',
      '/cpanel',
      '/dashboard',
      '/manage',
      '/management',
      '/api/admin',
      '/api/admin/users',
      '/api/admin/settings',
      '/api/v1/admin',
    ];

    const restrictedPathsToTestBypass: string[] = [];

    await Promise.allSettled(
      adminCandidatePaths.map(async aPath => {
        try {
          const probeUrl = new URL(aPath, targetUrl);
          // Strictly unauthenticated request: no cookies, no auth headers
          const res = await fetch(probeUrl.toString(), {
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 SentinelAI-AccessControlAuditor/2.0',
              'Accept': 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
            },
            redirect: 'follow',
            signal: AbortSignal.timeout(5000),
          });

          const status = res.status;
          const body = await res.text();

          if (status === 401 || status === 403) {
            restrictedPathsToTestBypass.push(aPath);
            return;
          }

          if (status === 200) {
            const isLoginPage =
              /(?:type=["']password["']|name=["']password["']|<form[^>]*login|sign in to your account|please log in|login to your account)/i.test(body);
            const hasAdminControls =
              /(?:admin\s+dashboard|user\s+management|system\s+settings|delete\s+user|role\s+management|cpanel|administrator\s+console|all\s+users|tenant\s+management)/i.test(body) ||
              (aPath.includes('/api/admin') && (body.includes('"users"') || body.includes('"settings"') || body.includes('"roles"')));
            const isGeneric404 =
              /(?:404\s+Not\s+Found|Page\s+Not\s+Found|Cannot\s+GET|Oops!|Welcome\s+to\s+nginx)/i.test(body);

            if (hasAdminControls && !isLoginPage && !isGeneric404) {
              result.unauthenticatedAdminRoutes.push(aPath);
              result.findings.push({
                title: `Unauthenticated Administrative Console Access: ${aPath}`,
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'BROKEN_ACCESS_CONTROL',
                sourceRuleId: 'access-control.unauthenticated-admin-access',
                targetUrl: probeUrl.toString(),
                evidenceSummary: `Administrative portal at ${aPath} is publicly accessible without authentication. The server returned HTTP 200 OK containing active administrative interfaces and management controls.`,
                rawSnippet: body.slice(0, 350),
                remediation: `Implement mandatory server-side authentication middleware verifying session tokens and user roles ('role === admin') on all /admin/* endpoints before rendering administrative views.`,
                cwe: 'CWE-306',
              });
            }
          }
        } catch {}
      })
    );

    // =========================================================================
    // 2. Reverse Proxy & Normalization Authentication Bypass Hunter (CWE-285)
    // =========================================================================
    // For any path that responded with 401/403, test reverse proxy headers & path normalization
    const pathsToBypass = restrictedPathsToTestBypass.slice(0, 4);
    for (const bPath of pathsToBypass) {
      const bypassProbes: Array<{ name: string; url: URL; headers: Record<string, string> }> = [
        // A. Reverse Proxy Header Overrides
        { name: 'X-Original-URL Header', url: new URL('/', targetUrl), headers: { 'X-Original-URL': bPath } },
        { name: 'X-Rewrite-URL Header', url: new URL('/', targetUrl), headers: { 'X-Rewrite-URL': bPath } },
        { name: 'X-Forwarded-For IP Whitelist', url: new URL(bPath, targetUrl), headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1' } },
        { name: 'Custom IP Authorization Header', url: new URL(bPath, targetUrl), headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
        // B. Path Normalization Bypasses
        { name: 'Path Dot Normalization', url: new URL(`${bPath}/.`, targetUrl), headers: {} },
        { name: 'Path Semicolon Delimiter', url: new URL(`/${bPath.replace(/^\//, '')}/..;${bPath.replace(/^\//, '')}`, targetUrl), headers: {} },
      ];

      for (const bp of bypassProbes) {
        try {
          const bpRes = await fetch(bp.url.toString(), {
            method: 'GET',
            headers: {
              'User-Agent': 'Mozilla/5.0 SentinelAI-BypassAuditor/2.0',
              'Accept': 'text/html,application/json,*/*;q=0.8',
              ...bp.headers,
            },
            signal: AbortSignal.timeout(4000),
          });

          if (bpRes.status === 200) {
            const bpBody = await bpRes.text();
            const isLoginPage = /(?:type=["']password["']|name=["']password["']|<form[^>]*login)/i.test(bpBody);
            const hasAdminControls = /(?:admin|dashboard|management|cpanel|settings|users)/i.test(bpBody);

            if (hasAdminControls && !isLoginPage) {
              result.findings.push({
                title: `Authentication Bypass via ${bp.name} (${bPath})`,
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'AUTHENTICATION_BYPASS',
                sourceRuleId: 'access-control.proxy-header-bypass',
                targetUrl: bp.url.toString(),
                evidenceSummary: `Access control restriction on ${bPath} (HTTP 401/403) was bypassed using ${bp.name}, returning HTTP 200 with administrative content.`,
                rawSnippet: `Request: GET ${bp.url.pathname}\nHeaders: ${JSON.stringify(bp.headers)}\nResponse Status: 200 OK\nBody Preview: ${bpBody.slice(0, 200)}`,
                remediation: `Configure reverse proxies to drop incoming X-Original-URL, X-Rewrite-URL, and client-supplied X-Forwarded-For headers, and enforce centralized access control at the application layer.`,
                cwe: 'CWE-285',
              });
              break; // One confirmed bypass per path
            }
          }
        } catch {}
      }
    }

    // =========================================================================
    // 3. Exposed Database Dumps & Password File Hunter (CWE-200 / CWE-530)
    // =========================================================================
    const sensitiveStoredFiles = [
      { p: '/.env', sig: /DB_|PASSWORD|SECRET|KEY|APP_ENV/i, title: 'Exposed Live Environment File (.env)' },
      { p: '/.env.local', sig: /DB_|PASSWORD|SECRET|KEY/i, title: 'Exposed Local Environment File (.env.local)' },
      { p: '/.env.production', sig: /DB_|PASSWORD|SECRET|KEY/i, title: 'Exposed Production Environment File (.env.production)' },
      { p: '/.env.backup', sig: /DB_|PASSWORD|SECRET|KEY/i, title: 'Exposed Environment Backup (.env.backup)' },
      { p: '/dump.sql', sig: /CREATE\s+TABLE|INSERT\s+INTO/i, title: 'Exposed Database SQL Dump (dump.sql)' },
      { p: '/backup.sql', sig: /CREATE\s+TABLE|INSERT\s+INTO/i, title: 'Exposed Database Backup Dump (backup.sql)' },
      { p: '/users.sql', sig: /CREATE\s+TABLE|INSERT\s+INTO|users/i, title: 'Exposed Users Table SQL Dump (users.sql)' },
      { p: '/database.sqlite', sig: /SQLite format 3/i, title: 'Exposed Live SQLite Database File' },
      { p: '/data.db', sig: /SQLite format 3/i, title: 'Exposed Live SQLite Data File (data.db)' },
      { p: '/dev.db', sig: /SQLite format 3/i, title: 'Exposed Development Database (dev.db)' },
      { p: '/app.log', sig: /\[ERROR\]|\[INFO\]|at\s+\w+\s+\(|Stack trace/i, title: 'Exposed Application Debug Log (app.log)' },
      { p: '/debug.log', sig: /\[ERROR\]|\[DEBUG\]|SQL/i, title: 'Exposed System Debug Log (debug.log)' },
      { p: '/storage/logs/laravel.log', sig: /\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]|Stack trace/i, title: 'Exposed Laravel System Log (laravel.log)' },
      { p: '/actuator/heapdump', sig: /heap|azure|vault|token/i, title: 'Exposed Cloud Actuator Heapdump' },
      { p: '/actuator/env', sig: /propertySources|environment/i, title: 'Exposed Spring Actuator Environment Variables' },
      { p: '/phpinfo.php', sig: /PHP Version|Configuration File|phpinfo\(\)/i, title: 'Exposed PHP Information Telemetry (phpinfo.php)' },
    ];

    await Promise.allSettled(
      sensitiveStoredFiles.map(async item => {
        try {
          const itemUrl = new URL(item.p, targetUrl);
          const res = await fetch(itemUrl.toString(), {
            method: 'GET',
            headers: { 'User-Agent': 'Mozilla/5.0 SentinelAI-CredentialHunter/2.0' },
            signal: AbortSignal.timeout(3500),
          });

          if (res.status === 200) {
            const text = await res.text();
            if (item.sig.test(text) && (!text.includes('<!DOCTYPE html>') || item.p === '/phpinfo.php')) {
              const fileName = path.basename(item.p) || 'leaked_data.txt';
              const savePath = path.join(outputDir, fileName.startsWith('.') ? fileName : `leaked_${fileName}`);
              fs.writeFileSync(savePath, text, 'utf8');
              result.exposedFilesCount++;

              result.findings.push({
                title: item.title,
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'SENSITIVE_DATA_EXPOSURE',
                sourceRuleId: 'access-control.stored-credential-leak',
                targetUrl: itemUrl.toString(),
                evidenceSummary: `Publicly readable stored sensitive data file discovered at ${item.p}. File exposes active credentials, passwords, database dumps, or server telemetry.`,
                rawSnippet: text.slice(0, 300),
                remediation: `Immediately remove ${item.p} from public web directories and configure web server rules to deny access to hidden files and backup archives.`,
                cwe: 'CWE-200',
              });
            }
          }
        } catch {}
      })
    );

    // =========================================================================
    // 4. Excessive Data Exposure in API Responses (CWE-213 / OWASP API3:2023)
    // =========================================================================
    const apiEndpointsToProbe = [
      '/api/users',
      '/api/user',
      '/api/profile',
      '/api/v1/users',
      '/api/auth/me',
      '/api/account',
      '/api/v1/profile',
    ];

    const apiHeaders: Record<string, string> = {
      'User-Agent': 'Mozilla/5.0 SentinelAI-ApiAuditor/2.0',
      'Accept': 'application/json',
    };
    if (sessionCookie) apiHeaders['Cookie'] = sessionCookie;
    if (authHeader) apiHeaders['Authorization'] = authHeader;

    await Promise.allSettled(
      apiEndpointsToProbe.map(async ep => {
        try {
          const epUrl = new URL(ep, targetUrl);
          const res = await fetch(epUrl.toString(), {
            method: 'GET',
            headers: apiHeaders,
            signal: AbortSignal.timeout(4000),
          });

          if (res.status === 200) {
            const jsonText = await res.text();
            try {
              const parsed = JSON.parse(jsonText);
              const leakedFields: string[] = [];

              // Search JSON keys for leaked credential fields
              const searchKeys = (obj: any) => {
                if (!obj || typeof obj !== 'object') return;
                for (const k of Object.keys(obj)) {
                  const lowerK = k.toLowerCase();
                  if (
                    lowerK === 'password' ||
                    lowerK === 'password_hash' ||
                    lowerK === 'passwd' ||
                    lowerK === 'hash' ||
                    lowerK === 'salt' ||
                    lowerK === 'private_key' ||
                    lowerK === 'secret_key' ||
                    lowerK === 'ssn'
                  ) {
                    if (obj[k] && typeof obj[k] === 'string' && obj[k].length > 4) {
                      leakedFields.push(k);
                    }
                  }
                  if (typeof obj[k] === 'object') {
                    searchKeys(obj[k]);
                  }
                }
              };
              searchKeys(parsed);

              if (leakedFields.length > 0) {
                const uniqueFields = [...new Set(leakedFields)];
                result.findings.push({
                  title: `Excessive Data Exposure: Sensitive Credentials Returned in API (${ep})`,
                  severity: 'HIGH',
                  confidence: 'CONFIRMED',
                  category: 'SENSITIVE_DATA_EXPOSURE',
                  sourceRuleId: 'access-control.excessive-data-exposure',
                  targetUrl: epUrl.toString(),
                  evidenceSummary: `API endpoint ${ep} exposes sensitive internal credential fields in its JSON response: ${uniqueFields.join(', ')}.`,
                  rawSnippet: `Endpoint: ${ep}\nLeaked Fields: ${uniqueFields.join(', ')}\nSample Payload: ${jsonText.slice(0, 250)}`,
                  remediation: `Implement Data Transfer Object (DTO) filtering to explicitly exclude passwords, password hashes, and security tokens from API responses.`,
                  cwe: 'CWE-213',
                });
              }
            } catch {}
          }
        } catch {}
      })
    );

    return result;
  }
}
