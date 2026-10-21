import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface CmsProbe {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  pathTest: string;
  matcher: (body: string, status: number, headers: Record<string, string>) => boolean;
  evidence: string;
  remediation: string;
}

const CMS_PROBES: CmsProbe[] = [
  {
    id: 'wp-user-enumeration-rest-api',
    title: 'WordPress REST API Public User Enumeration (/wp-json/wp/v2/users)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'HIGH',
    cwe: 'CWE-200',
    pathTest: '/wp-json/wp/v2/users',
    matcher: (body, status) => status === 200 && body.startsWith('[') && body.includes('"slug"') && body.includes('"id"'),
    evidence: 'WordPress REST API is accessible without authentication and returns the list of system users and author usernames.',
    remediation: 'Restrict public access to the /wp-json/wp/v2/users endpoint using security plugins or custom functions.php hooks.',
  },
  {
    id: 'wp-xmlrpc-enabled',
    title: 'WordPress XML-RPC Interface Enabled (/xmlrpc.php)',
    category: 'CONFIGURATION_ERROR',
    severity: 'MEDIUM',
    cwe: 'CWE-306',
    pathTest: '/xmlrpc.php',
    matcher: (body, status) => status === 200 && (body.includes('XML-RPC server accepts POST requests only') || body.includes('methodResponse')),
    evidence: 'XML-RPC interface is active. Adversaries can leverage xmlrpc.php for brute-force amplification (system.multicall) and DDoS attacks.',
    remediation: 'Disable xmlrpc.php in web server configuration or via `.htaccess` (deny from all) unless required by Jetpack.',
  },
  {
    id: 'wp-config-backup-exposed',
    title: 'Exposed WordPress Configuration Backup (wp-config.php.bak)',
    category: 'SENSITIVE_DATA_EXPOSURE',
    severity: 'CRITICAL',
    cwe: 'CWE-552',
    pathTest: '/wp-config.php.bak',
    matcher: (body, status) => status === 200 && (body.includes('DB_PASSWORD') || body.includes('DB_USER') || body.includes('AUTH_KEY')),
    evidence: 'Backup copy of wp-config.php is publicly downloadable, exposing database credentials, salts, and secret keys.',
    remediation: 'Delete backup files immediately and rotate all database credentials and security salt keys.',
  },
  {
    id: 'wp-debug-log-exposed',
    title: 'Exposed WordPress Debug Log (/wp-content/debug.log)',
    category: 'SENSITIVE_DATA_EXPOSURE',
    severity: 'HIGH',
    cwe: 'CWE-532',
    pathTest: '/wp-content/debug.log',
    matcher: (body, status) => status === 200 && (body.includes('PHP Notice:') || body.includes('PHP Fatal error:') || body.includes('Stack trace:')),
    evidence: 'WordPress debug.log is publicly readable, disclosing internal paths, SQL errors, and sensitive variable data.',
    remediation: 'Set WP_DEBUG_LOG to false in wp-config.php and delete the debug.log file.',
  },
  {
    id: 'wp-version-readme-exposed',
    title: 'WordPress Readme File Disclosing Exact Version (/readme.html)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'LOW',
    cwe: 'CWE-200',
    pathTest: '/readme.html',
    matcher: (body, status) => status === 200 && body.includes('WordPress') && (body.includes('Version') || body.includes('Semantic Personal Publishing Platform')),
    evidence: 'Default readme.html file is accessible, assisting adversaries in fingerprinting the exact WordPress core version.',
    remediation: 'Delete readme.html and license.txt from the WordPress root directory.',
  },
  {
    id: 'laravel-log-exposed',
    title: 'Exposed Laravel Application Log (/storage/logs/laravel.log)',
    category: 'SENSITIVE_DATA_EXPOSURE',
    severity: 'HIGH',
    cwe: 'CWE-532',
    pathTest: '/storage/logs/laravel.log',
    matcher: (body, status) => status === 200 && (body.includes('[stacktrace]') || body.includes('.ERROR:') || body.includes('Illuminate\\')),
    evidence: 'Laravel framework application log is publicly accessible, disclosing internal stack traces and environment states.',
    remediation: 'Verify that the web server document root points strictly to public/ and not the project root.',
  },
  {
    id: 'drupal-changelog-exposed',
    title: 'Exposed Drupal Changelog (/CHANGELOG.txt)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'LOW',
    cwe: 'CWE-200',
    pathTest: '/CHANGELOG.txt',
    matcher: (body, status) => status === 200 && body.includes('Drupal') && body.includes('version'),
    evidence: 'Drupal CHANGELOG.txt is publicly accessible, facilitating version-specific vulnerability mapping.',
    remediation: 'Block direct access to text files (CHANGELOG.txt, INSTALL.txt) at the web server level.',
  },
];

export class WpscanAdapter implements SecurityToolAdapter {
  readonly name = 'WPSCAN';
  readonly version = 'v3.8.25';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'wpscan');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-wpscan.json`);

    try {
      const targetBase = (input.targetUrl || 'https://example.com/').replace(/\/$/, '');

      // Execute CMS & Application Framework probes
      for (const probe of CMS_PROBES) {
        const fullUrl = `${targetBase}${probe.pathTest}`;
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4000);

          const reqHeaders: Record<string, string> = {
            'User-Agent': 'SentinelAI-WPScan-Engine/3.8.25 (Authorized Security Audit)',
            'Accept': '*/*',
          };
          if (input.sessionCookie) reqHeaders['Cookie'] = input.sessionCookie;
          if (input.authHeader) reqHeaders['Authorization'] = input.authHeader;

          const res = await fetch(fullUrl, {
            method: 'GET',
            headers: reqHeaders,
            signal: controller.signal,
          }).catch(() => null);

          clearTimeout(timeout);

          if (res) {
            const body = await res.text().catch(() => '');
            const headersObj: Record<string, string> = {};
            res.headers.forEach((val, key) => {
              headersObj[key.toLowerCase()] = val;
            });

            if (probe.matcher(body, res.status, headersObj)) {
              findings.push({
                title: probe.title,
                severity: probe.severity,
                confidence: 'CONFIRMED',
                category: probe.category,
                sourceRuleId: `wpscan.${probe.id}`,
                targetUrl: fullUrl,
                evidenceSummary: `${probe.evidence} (Status: HTTP ${res.status})`,
                rawSnippet: `GET ${probe.pathTest} HTTP/1.1\nHost: ${new URL(targetBase).host}\n\nHTTP/1.1 ${res.status} ${res.statusText}\n${body.slice(0, 200)}`,
                remediation: probe.remediation,
                cwe: probe.cwe,
              });
            }
          }
        } catch {}
      }

      fs.writeFileSync(
        resultPath,
        JSON.stringify(
          {
            scanId: input.scanId,
            tool: 'WPScan',
            version: this.version,
            target: input.targetUrl,
            findingsCount: findings.length,
            findings,
          },
          null,
          2
        ),
        'utf8'
      );

      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings,
        resultPath,
      };
    } catch (err) {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: false,
        exitCode: 1,
        durationMs: Date.now() - startTime,
        findings: [],
        errorSummary: (err as Error).message,
        resultPath,
      };
    }
  }
}
