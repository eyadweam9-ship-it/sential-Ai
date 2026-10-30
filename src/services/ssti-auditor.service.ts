import { RawToolFinding } from '../tools/security-tool.interface';

/**
 * SstiAuditorService
 * Server-Side Template Injection (SSTI) Active Probe
 * Tests parameters and endpoints using template evaluation canaries across Jinja2, Twig, FreeMarker, ERB, and EJS.
 */
export class SstiAuditorService {
  private static readonly PROBES = [
    { payload: '{{7*7}}', result: '49', engine: 'Jinja2/Twig' },
    { payload: '${7*7}', result: '49', engine: 'Java EL/FreeMarker' },
    { payload: '<%= 7*7 %>', result: '49', engine: 'Ruby ERB/EJS' },
  ];

  public static async auditEndpoint(
    targetUrl: string,
    discoveredUrls: string[],
    sessionCookie?: string,
    authHeader?: string,
    isProd = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const testedEndpoints = new Set<string>();

    const headers: Record<string, string> = {
      'User-Agent': 'Sential-Security-Scanner/2.0 (SSTI-Auditor; Safe-Audit)',
    };
    if (sessionCookie) headers['Cookie'] = sessionCookie;
    if (authHeader) headers['Authorization'] = authHeader;
    if (isProd) headers['X-Sential-Security-Scan'] = 'Authorized-Audit-Engine';

    // 1. Collect target URLs with parameters
    const targets: Array<{ url: string; param: string }> = [];

    for (const u of [targetUrl, ...discoveredUrls]) {
      try {
        const parsed = new URL(u);
        for (const [key] of parsed.searchParams.entries()) {
          targets.push({ url: parsed.origin + parsed.pathname, param: key });
        }
      } catch {}
    }

    // Common template parameters if none extracted
    if (targets.length === 0) {
      const commonParams = ['template', 'page', 'view', 'name', 'msg', 'message', 'preview', 'render'];
      for (const p of commonParams) {
        targets.push({ url: targetUrl, param: p });
      }
    }

    const maxTargets = isProd ? 5 : 12;

    for (const target of targets.slice(0, maxTargets)) {
      const key = `${target.url}?${target.param}`;
      if (testedEndpoints.has(key)) continue;
      testedEndpoints.add(key);

      try {
        // Baseline check: verify '49' isn't already statically present in response
        const baseRes = await fetch(target.url, { headers, signal: AbortSignal.timeout(4000) });
        const baseText = await baseRes.text();
        const baseHadResult = baseText.includes('49');

        for (const probe of this.PROBES) {
          const testUrl = new URL(target.url);
          testUrl.searchParams.set(target.param, probe.payload);

          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            headers,
            signal: AbortSignal.timeout(5000),
          });

          const resText = await response.text();

          // Condition: The evaluated '49' must be present, the raw probe payload string is NOT literally reflected,
          // and the baseline response did not already have '49' in that position.
          if (resText.includes(probe.result) && !resText.includes(probe.payload) && !baseHadResult) {
            const idx = resText.indexOf(probe.result);
            const snippet = resText.substring(Math.max(0, idx - 30), Math.min(resText.length, idx + 40));

            findings.push({
              title: `Server-Side Template Injection (SSTI) in Parameter '${target.param}'`,
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              verificationStatus: 'VERIFIED',
              category: 'INJECTION',
              sourceRuleId: 'ssti.template-execution',
              targetUrl: testUrl.toString(),
              evidenceSummary: `Injected template expression '${probe.payload}' evaluated on server to '${probe.result}' (${probe.engine}). Response snippet: ${snippet.trim()}`,
              rawSnippet: `GET ${testUrl.toString()} HTTP/1.1\n\nEvaluation Result:\n${snippet}`,
              remediation: 'Never concatenate untrusted user input directly into template strings. Pass dynamic data via context variables and enforce sandboxed template rendering.',
              cwe: 'CWE-1336',
            });
            break; // Finding confirmed on this parameter
          }
        }
      } catch {
        // Timeout or fetch error
      }
    }

    return findings;
  }
}
