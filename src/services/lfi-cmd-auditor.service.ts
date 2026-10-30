import { RawToolFinding } from '../tools/security-tool.interface';

/**
 * LfiCmdAuditorService
 * Local File Inclusion (LFI / Path Traversal) & OS Command Injection Active Probe
 * Tests parameters against file path traversals and safe diagnostic shell echo canaries.
 */
export class LfiCmdAuditorService {
  private static readonly LFI_PROBES = [
    { payload: '../../../../etc/passwd', regex: /root:[^:]*:[0-9]+:[0-9]+:/i, title: 'Local File Inclusion (LFI) via Path Traversal' },
    { payload: '..%2F..%2F..%2F..%2Fetc%2Fpasswd', regex: /root:[^:]*:[0-9]+:[0-9]+:/i, title: 'URL-Encoded Path Traversal (/etc/passwd)' },
    { payload: 'C:\\Windows\\win.ini', regex: /(?:\[fonts\]|\[extensions\]|for 16-bit app support)/i, title: 'Windows File Disclosure (win.ini)' },
  ];

  private static readonly CMD_CANARY = 'sential_cmd_849204';
  private static readonly CMD_PROBES = [
    { payload: `; echo ${LfiCmdAuditorService.CMD_CANARY};`, title: 'OS Command Injection (Semicolon Separator)' },
    { payload: `| echo ${LfiCmdAuditorService.CMD_CANARY}`, title: 'OS Command Injection (Pipe Operator)' },
    { payload: `&& echo ${LfiCmdAuditorService.CMD_CANARY}`, title: 'OS Command Injection (AND Operator)' },
  ];

  public static async auditEndpoint(
    targetUrl: string,
    discoveredUrls: string[],
    sessionCookie?: string,
    authHeader?: string,
    isProd = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const testedKeys = new Set<string>();

    const headers: Record<string, string> = {
      'User-Agent': 'Sential-Security-Scanner/2.0 (LFI-CMD-Auditor; Safe-Audit)',
    };
    if (sessionCookie) headers['Cookie'] = sessionCookie;
    if (authHeader) headers['Authorization'] = authHeader;
    if (isProd) headers['X-Sential-Security-Scan'] = 'Authorized-Audit-Engine';

    // 1. Gather candidate endpoints and parameters
    const candidates: Array<{ url: string; param: string }> = [];

    for (const u of [targetUrl, ...discoveredUrls]) {
      try {
        const parsed = new URL(u);
        for (const [key] of parsed.searchParams.entries()) {
          candidates.push({ url: parsed.origin + parsed.pathname, param: key });
        }
      } catch {}
    }

    if (candidates.length === 0) {
      const common = ['file', 'path', 'page', 'doc', 'dir', 'cmd', 'exec', 'view', 'read'];
      for (const p of common) {
        candidates.push({ url: targetUrl, param: p });
      }
    }

    const maxTargets = isProd ? 6 : 14;

    for (const item of candidates.slice(0, maxTargets)) {
      const key = `${item.url}?${item.param}`;
      if (testedKeys.has(key)) continue;
      testedKeys.add(key);

      // A. Test LFI Probes
      for (const lfi of this.LFI_PROBES) {
        try {
          const u = new URL(item.url);
          u.searchParams.set(item.param, lfi.payload);

          const res = await fetch(u.toString(), { method: 'GET', headers, signal: AbortSignal.timeout(5000) });
          const text = await res.text();

          if (lfi.regex.test(text)) {
            const match = lfi.regex.exec(text);
            const snippet = match ? text.substring(Math.max(0, match.index - 20), Math.min(text.length, match.index + 80)) : '';

            findings.push({
              title: `${lfi.title} in Parameter '${item.param}'`,
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              verificationStatus: 'VERIFIED',
              category: 'PATH_TRAVERSAL',
              sourceRuleId: 'lfi.path-traversal',
              targetUrl: u.toString(),
              evidenceSummary: `Path traversal payload '${lfi.payload}' leaked system file contents: ${snippet.trim()}`,
              rawSnippet: `GET ${u.toString()} HTTP/1.1\n\nLeaked File Contents:\n${snippet}`,
              remediation: 'Use basename sanitization (path.basename), validate file paths against an explicit allowlist, and disallow absolute or relative traversal sequences (../).',
              cwe: 'CWE-22',
            });
            break;
          }
        } catch {}
      }

      // B. Test Command Injection Probes (Only in Staging or Non-Destructive Safe Echo in Prod)
      for (const cmd of this.CMD_PROBES) {
        try {
          const u = new URL(item.url);
          u.searchParams.set(item.param, cmd.payload);

          const res = await fetch(u.toString(), { method: 'GET', headers, signal: AbortSignal.timeout(5000) });
          const text = await res.text();

          // Condition: The raw canary output appears in response, without the 'echo' syntax
          if (text.includes(this.CMD_CANARY) && !text.includes(`echo ${this.CMD_CANARY}`)) {
            findings.push({
              title: `${cmd.title} in Parameter '${item.param}'`,
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              verificationStatus: 'VERIFIED',
              category: 'COMMAND_INJECTION',
              sourceRuleId: 'cmd.os-injection',
              targetUrl: u.toString(),
              evidenceSummary: `Shell command delimiter successfully executed echo probe: ${this.CMD_CANARY} was reflected from system stdout.`,
              rawSnippet: `GET ${u.toString()} HTTP/1.1\n\nCommand Output:\n${this.CMD_CANARY}`,
              remediation: 'Never pass user-supplied input to child_process.exec, system(), or shell interpreters. Use parameterized APIs like child_process.execFile with arguments array.',
              cwe: 'CWE-78',
            });
            break;
          }
        } catch {}
      }
    }

    return findings;
  }
}
