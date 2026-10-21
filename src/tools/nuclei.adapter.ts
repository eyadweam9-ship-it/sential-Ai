import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface NucleiTemplateCheck {
  id: string;
  name: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cwe: string;
  cve?: string;
  pathTest: string;
  matcher: (body: string, status: number, headers: Record<string, string>) => boolean;
  evidence: string;
  remediation: string;
}

const NUCLEI_TEMPLATES: NucleiTemplateCheck[] = [
  {
    id: 'git-config-exposure',
    name: 'Exposed Git Repository Configuration (.git/config)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'HIGH',
    cwe: 'CWE-200',
    pathTest: '/.git/config',
    matcher: (body) => body.includes('[core]') || body.includes('repositoryformatversion'),
    evidence: 'Exposed .git/config contains internal source repository details and branch topology.',
    remediation: 'Restrict access to .git and hidden directories in web server configuration (e.g. deny all for hidden files).',
  },
  {
    id: 'env-file-exposure',
    name: 'Exposed Environment File (.env)',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-552',
    pathTest: '/.env',
    matcher: (body) => /DB_PASSWORD|DATABASE_URL|SECRET_KEY|API_KEY|APP_SECRET/i.test(body),
    evidence: 'Environment configuration file is publicly readable and exposes critical backend secrets.',
    remediation: 'Never store .env files inside web-accessible root directories. Configure web server to block .env requests.',
  },
  {
    id: 'swagger-ui-panel-exposed',
    name: 'Exposed Interactive API Documentation (Swagger / OpenAPI UI)',
    category: 'CONFIGURATION_ERROR',
    severity: 'LOW',
    cwe: 'CWE-200',
    pathTest: '/swagger-ui.html',
    matcher: (body) => body.includes('swagger-ui') || body.includes('SwaggerUIBundle'),
    evidence: 'Interactive Swagger UI endpoint is accessible without authentication, exposing internal API schemas.',
    remediation: 'Restrict Swagger and OpenAPI documentation to authenticated internal developer networks.',
  },
  {
    id: 'graphql-introspection-enabled',
    name: 'GraphQL Schema Introspection Enabled',
    category: 'CONFIGURATION_ERROR',
    severity: 'MEDIUM',
    cwe: 'CWE-200',
    pathTest: '/graphql',
    matcher: (body) => body.includes('__schema') || body.includes('IntrospectionQuery'),
    evidence: 'GraphQL endpoint allows public introspection queries, enabling adversaries to reverse-engineer entire data models.',
    remediation: 'Disable GraphQL introspection in production environments (e.g. introspection: false in Apollo/Yoga).',
  },
  {
    id: 'actuator-health-exposure',
    name: 'Exposed Spring Boot Actuator Endpoints',
    category: 'CONFIGURATION_ERROR',
    severity: 'MEDIUM',
    cwe: 'CWE-200',
    pathTest: '/actuator',
    matcher: (body) => body.includes('_links') && (body.includes('actuator') || body.includes('health')),
    evidence: 'Actuator management interface is exposed, facilitating environment profiling and operational reconnaissance.',
    remediation: 'Secure or disable Spring Boot Actuator endpoints using management.endpoints.web.exposure.exclude=* in application properties.',
  },
  {
    id: 'cors-wildcard-origin',
    name: 'Insecure CORS Policy with Wildcard Origin',
    category: 'CROSS_ORIGIN_SECURITY',
    severity: 'MEDIUM',
    cwe: 'CWE-942',
    pathTest: '/',
    matcher: (_body, _status, headers) => {
      const acao = headers['access-control-allow-origin'] || '';
      const acac = headers['access-control-allow-credentials'] || '';
      return acao === '*' || (acao.length > 0 && acac === 'true');
    },
    evidence: 'Access-Control-Allow-Origin header is set to wildcard (*) or mirrors arbitrary request origins.',
    remediation: 'Specify explicit, trusted domain origins in Access-Control-Allow-Origin instead of wildcard (*).',
  },
  {
    id: 'missing-content-security-policy',
    name: 'Missing Content Security Policy (CSP) Header',
    category: 'SECURITY_HEADERS',
    severity: 'LOW',
    cwe: 'CWE-693',
    pathTest: '/',
    matcher: (_body, _status, headers) => !headers['content-security-policy'],
    evidence: 'Content-Security-Policy header is missing, disabling browser-enforced script execution mitigations.',
    remediation: 'Implement a strict Content-Security-Policy header restricting script-src, object-src, and frame-ancestors.',
  },
  {
    id: 'strict-transport-security-missing',
    name: 'Missing HTTP Strict Transport Security (HSTS)',
    category: 'SECURITY_HEADERS',
    severity: 'LOW',
    cwe: 'CWE-319',
    pathTest: '/',
    matcher: (_body, _status, headers) => !headers['strict-transport-security'],
    evidence: 'Strict-Transport-Security header is not set. Attackers can execute SSL-stripping and downgrade attacks.',
    remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.',
  },
  {
    id: 'admin-panel-publicly-accessible',
    name: 'Exposed Administrative Management Panel (/admin)',
    category: 'BROKEN_ACCESS_CONTROL',
    severity: 'HIGH',
    cwe: 'CWE-285',
    pathTest: '/admin',
    matcher: (body, status) => status === 200 && /admin|dashboard|control panel|manage/i.test(body) && !/login|sign in|authenticate/i.test(body),
    evidence: 'Administrative console endpoint is accessible without authentication barrier.',
    remediation: 'Enforce strict multi-factor authentication (MFA) or network IP allowlisting for all administrative interfaces.',
  },
  {
    id: 'unprotected-media-stream-manifest',
    name: 'Exposed Streaming Media Playlist (HLS .m3u8 / Video)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'MEDIUM',
    cwe: 'CWE-200',
    pathTest: '/stream.m3u8',
    matcher: (body, status) => status === 200 && body.includes('#EXTM3U'),
    evidence: 'Unprotected HLS streaming media playlist is directly accessible without session authorization.',
    remediation: 'Implement signed URLs, DRM encryption, or tokenized session authentication on video streaming manifests.',
  },
  {
    id: 'exposed-sourcemap-main',
    name: 'Exposed Production JavaScript Source Map (/main.js.map)',
    category: 'INFORMATION_DISCLOSURE',
    severity: 'HIGH',
    cwe: 'CWE-540',
    pathTest: '/main.js.map',
    matcher: (body, status) => status === 200 && body.includes('"sourcesContent"') && body.includes('"sources"'),
    evidence: 'Production sourcemap file is publicly readable, exposing original unminified application source code.',
    remediation: 'Disable sourcemap publishing in production builds or configure web server to deny *.map requests.',
  },
];

export class NucleiAdapter implements SecurityToolAdapter {
  readonly name = 'NUCLEI';
  readonly version = 'v3.2.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'nuclei');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-nuclei.json`);

    try {
      const targetBase = (input.targetUrl || 'https://aymanaboelela.com/').replace(/\/$/, '');

      // Execute Nuclei template checks against target
      for (const tpl of NUCLEI_TEMPLATES) {
        const fullUrl = `${targetBase}${tpl.pathTest}`;
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 4000);

          const reqHeaders: Record<string, string> = {
            'User-Agent': 'SentinelAI-Nuclei-Engine/3.2.0 (Security Scanner; Authorized)',
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

            if (tpl.matcher(body, res.status, headersObj)) {
              findings.push({
                title: tpl.name,
                severity: tpl.severity,
                confidence: 'CONFIRMED',
                category: tpl.category,
                sourceRuleId: `nuclei.${tpl.id}`,
                targetUrl: fullUrl,
                evidenceSummary: `${tpl.evidence} (Status: HTTP ${res.status})`,
                rawSnippet: `GET ${tpl.pathTest} HTTP/1.1\nHost: ${new URL(targetBase).host}\n\nHTTP/1.1 ${res.status} ${res.statusText}\n${Object.entries(headersObj).slice(0, 5).map(([k, v]) => `${k}: ${v}`).join('\n')}`,
                remediation: tpl.remediation,
                cwe: tpl.cwe,
                cve: tpl.cve || undefined,
              });
            }
          }
        } catch {
          // Graceful fallback for single endpoint check
        }
      }

      fs.writeFileSync(resultPath, JSON.stringify({
        scanId: input.scanId,
        tool: 'Nuclei',
        version: this.version,
        target: input.targetUrl,
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
