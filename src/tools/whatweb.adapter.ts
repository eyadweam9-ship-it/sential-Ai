import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface TechFingerprint {
  name: string;
  category: 'WAF' | 'WEB_SERVER' | 'FRAMEWORK' | 'CMS' | 'LANGUAGE';
  matcher: (headers: Record<string, string>, body: string) => boolean;
  versionExtractor?: (headers: Record<string, string>, body: string) => string | undefined;
}

const FINGERPRINTS: TechFingerprint[] = [
  // WAFs
  {
    name: 'Cloudflare WAF / CDN',
    category: 'WAF',
    matcher: (h, b) => Boolean(h['cf-ray'] || h['cf-cache-status'] || (h['server'] && h['server'].toLowerCase().includes('cloudflare')) || b.includes('challenges.cloudflare.com')),
  },
  {
    name: 'AWS CloudFront / WAF',
    category: 'WAF',
    matcher: (h) => Boolean(h['x-amz-cf-id'] || h['x-amz-cf-pop'] || (h['server'] && h['server'].toLowerCase().includes('cloudfront'))),
  },
  {
    name: 'Akamai Edge Security',
    category: 'WAF',
    matcher: (h) => Boolean(h['x-akamai-transformed'] || (h['server'] && h['server'].toLowerCase().includes('akamai'))),
  },

  // Web Servers
  {
    name: 'Nginx',
    category: 'WEB_SERVER',
    matcher: (h) => Boolean(h['server'] && h['server'].toLowerCase().includes('nginx')),
    versionExtractor: (h) => h['server']?.match(/nginx\/([0-9.]+)/i)?.[1],
  },
  {
    name: 'Apache HTTP Server',
    category: 'WEB_SERVER',
    matcher: (h) => Boolean(h['server'] && h['server'].toLowerCase().includes('apache')),
    versionExtractor: (h) => h['server']?.match(/apache\/([0-9.]+)/i)?.[1],
  },
  {
    name: 'Microsoft IIS',
    category: 'WEB_SERVER',
    matcher: (h) => Boolean(h['server'] && h['server'].toLowerCase().includes('microsoft-iis')),
    versionExtractor: (h) => h['server']?.match(/microsoft-iis\/([0-9.]+)/i)?.[1],
  },
  {
    name: 'LiteSpeed Web Server',
    category: 'WEB_SERVER',
    matcher: (h) => Boolean(h['server'] && h['server'].toLowerCase().includes('litespeed')),
  },

  // Frameworks & CMS
  {
    name: 'WordPress',
    category: 'CMS',
    matcher: (h, b) => b.includes('/wp-content/') || b.includes('/wp-includes/') || Boolean(h['x-pingback']),
  },
  {
    name: 'Next.js',
    category: 'FRAMEWORK',
    matcher: (h, b) => b.includes('/_next/static/') || b.includes('__NEXT_DATA__') || Boolean(h['x-nextjs-cache']),
  },
  {
    name: 'React',
    category: 'FRAMEWORK',
    matcher: (_h, b) => b.includes('react.production.min.js') || b.includes('_reactRootContainer') || b.includes('react-dom'),
  },
  {
    name: 'Vue.js',
    category: 'FRAMEWORK',
    matcher: (_h, b) => b.includes('vue.global.js') || b.includes('data-v-') || b.includes('__vue__'),
  },
  {
    name: 'Laravel',
    category: 'FRAMEWORK',
    matcher: (h, b) => Boolean(h['set-cookie'] && h['set-cookie'].toLowerCase().includes('laravel_session')) || b.includes('csrf-token'),
  },
  {
    name: 'PHP Engine',
    category: 'LANGUAGE',
    matcher: (h) => Boolean((h['x-powered-by'] && h['x-powered-by'].toLowerCase().includes('php')) || (h['set-cookie'] && h['set-cookie'].includes('PHPSESSID'))),
    versionExtractor: (h) => h['x-powered-by']?.match(/php\/([0-9.]+)/i)?.[1],
  },
  {
    name: 'Express / Node.js',
    category: 'FRAMEWORK',
    matcher: (h) => Boolean(h['x-powered-by'] && h['x-powered-by'].toLowerCase().includes('express')),
  },
];

export class WhatwebAdapter implements SecurityToolAdapter {
  readonly name = 'WHATWEB';
  readonly version = 'v0.5.5';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'whatweb');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-whatweb.json`);

    try {
      const targetUrl = input.targetUrl || 'https://example.com/';
      const reqHeaders: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelAI-WhatWeb/0.5.5',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      };
      if (input.sessionCookie) reqHeaders['Cookie'] = input.sessionCookie;
      if (input.authHeader) reqHeaders['Authorization'] = input.authHeader;

      const res = await fetch(targetUrl, {
        headers: reqHeaders,
        signal: AbortSignal.timeout(8000),
      }).catch(() => null);

      const detectedTechs: Array<{ name: string; category: string; version?: string }> = [];

      if (res) {
        const headersObj: Record<string, string> = {};
        res.headers.forEach((val, key) => {
          headersObj[key.toLowerCase()] = val;
        });

        const body = await res.text().catch(() => '');

        for (const fp of FINGERPRINTS) {
          if (fp.matcher(headersObj, body)) {
            const ver = fp.versionExtractor ? fp.versionExtractor(headersObj, body) : undefined;
            detectedTechs.push({
              name: fp.name,
              category: fp.category,
              version: ver,
            });
          }
        }

        // Check for Technology Version Information Disclosure
        if (headersObj['x-powered-by']) {
          findings.push({
            title: `Backend Engine Disclosed in HTTP Header (X-Powered-By: ${headersObj['x-powered-by']})`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: 'whatweb.x-powered-by-disclosure',
            targetUrl,
            evidenceSummary: `The response header "X-Powered-By" discloses backend technology runtime: ${headersObj['x-powered-by']}.`,
            rawSnippet: `X-Powered-By: ${headersObj['x-powered-by']}`,
            remediation: 'Disable the X-Powered-By header in web server or application middleware (e.g. app.disable("x-powered-by") in Express, or expose_php = Off in php.ini).',
            cwe: 'CWE-200',
          });
        }

        if (headersObj['server'] && /[0-9]+\.[0-9]+/.test(headersObj['server'])) {
          findings.push({
            title: `Granular Web Server Version Disclosed (Server: ${headersObj['server']})`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: 'whatweb.server-version-disclosure',
            targetUrl,
            evidenceSummary: `Server response header broadcasts explicit version numbers: ${headersObj['server']}, facilitating targeted CVE exploitation.`,
            rawSnippet: `Server: ${headersObj['server']}`,
            remediation: 'Configure the web server to omit granular version banners (e.g. server_tokens off in Nginx, ServerSignature Off and ServerTokens Prod in Apache).',
            cwe: 'CWE-200',
          });
        }
      }

      fs.writeFileSync(
        resultPath,
        JSON.stringify(
          {
            scanId: input.scanId,
            tool: 'WhatWeb',
            version: this.version,
            target: targetUrl,
            technologiesCount: detectedTechs.length,
            detectedTechnologies: detectedTechs,
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
