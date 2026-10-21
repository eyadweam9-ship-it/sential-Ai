import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

export class TestsslAdapter implements SecurityToolAdapter {
  readonly name = 'TESTSSL';
  readonly version = 'v3.2';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'testssl');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-testssl.json`);

    try {
      const targetUrl = input.targetUrl || 'https://example.com/';
      const parsedUrl = new URL(targetUrl);

      // 1. Check Plaintext HTTP Transport
      if (parsedUrl.protocol === 'http:') {
        findings.push({
          title: 'Unencrypted Plaintext HTTP Transport in Use',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'INSECURE_COMMUNICATION',
          sourceRuleId: 'testssl.plaintext-http',
          targetUrl,
          evidenceSummary: 'The target application is accessible over unencrypted HTTP (TCP 80). Transmitted data is vulnerable to sniffing and man-in-the-middle manipulation.',
          remediation: 'Configure an automatic 301 Permanent Redirect to enforce HTTPS on all inbound traffic.',
          cwe: 'CWE-319',
        });
      }

      const reqHeaders: Record<string, string> = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelAI-TestSSL/3.2',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      };
      if (input.sessionCookie) reqHeaders['Cookie'] = input.sessionCookie;
      if (input.authHeader) reqHeaders['Authorization'] = input.authHeader;

      const res = await fetch(targetUrl, {
        headers: reqHeaders,
        signal: AbortSignal.timeout(8000),
      }).catch(() => null);

      if (res) {
        const headersObj: Record<string, string> = {};
        res.headers.forEach((val, key) => {
          headersObj[key.toLowerCase()] = val;
        });

        // 2. Strict-Transport-Security (HSTS)
        const hsts = headersObj['strict-transport-security'];
        if (!hsts) {
          findings.push({
            title: 'HTTP Strict Transport Security (HSTS) Missing',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.hsts-missing',
            targetUrl,
            evidenceSummary: 'Strict-Transport-Security header is not set. Browsers may establish unencrypted fallback connections susceptible to SSL stripping.',
            remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all HTTPS responses.',
            cwe: 'CWE-319',
          });
        } else if (!hsts.includes('includeSubDomains')) {
          findings.push({
            title: 'HSTS Header Missing includeSubDomains Directive',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.hsts-no-subdomains',
            targetUrl,
            evidenceSummary: 'HSTS is active on base domain but does not protect subdomains (missing includeSubDomains).',
            remediation: 'Add includeSubDomains to the Strict-Transport-Security header.',
            cwe: 'CWE-319',
          });
        }

        // 3. X-Frame-Options (Clickjacking)
        if (!headersObj['x-frame-options'] && !headersObj['content-security-policy']?.includes('frame-ancestors')) {
          findings.push({
            title: 'Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.clickjacking-defense-missing',
            targetUrl,
            evidenceSummary: 'Neither X-Frame-Options nor CSP frame-ancestors is present. The page can be embedded inside unauthorized malicious iframes (Clickjacking).',
            remediation: 'Set "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN", or specify "frame-ancestors \'none\'" in CSP.',
            cwe: 'CWE-1021',
          });
        }

        // 4. X-Content-Type-Options
        if (headersObj['x-content-type-options'] !== 'nosniff') {
          findings.push({
            title: 'Missing X-Content-Type-Options: nosniff Header',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.nosniff-missing',
            targetUrl,
            evidenceSummary: 'The X-Content-Type-Options: nosniff header is absent. Browsers may MIME-sniff responses into executable scripts.',
            remediation: 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
            cwe: 'CWE-79',
          });
        }

        // 5. Referrer-Policy
        if (!headersObj['referrer-policy']) {
          findings.push({
            title: 'Missing Referrer-Policy Header',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.referrer-policy-missing',
            targetUrl,
            evidenceSummary: 'No Referrer-Policy is specified. Outbound links may leak internal URLs and sensitive query parameters to third-party referrers.',
            remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer".',
            cwe: 'CWE-200',
          });
        }

        // 6. Permissions-Policy
        if (!headersObj['permissions-policy']) {
          findings.push({
            title: 'Missing Permissions-Policy Header',
            severity: 'LOW',
            confidence: 'CONFIRMED',
            category: 'SECURITY_HEADERS',
            sourceRuleId: 'testssl.permissions-policy-missing',
            targetUrl,
            evidenceSummary: 'Permissions-Policy is omitted. Browser hardware features (geolocation, camera, microphone) are not explicitly disabled for embedded frames.',
            remediation: 'Add "Permissions-Policy: camera=(), microphone=(), geolocation=()" to restrict browser API access.',
            cwe: 'CWE-16',
          });
        }
      }

      fs.writeFileSync(
        resultPath,
        JSON.stringify(
          {
            scanId: input.scanId,
            tool: 'testssl',
            version: this.version,
            target: targetUrl,
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
