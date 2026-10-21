import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface SecretRule {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH';
  regex: RegExp;
  mask: (match: string) => string;
}

const GITLEAKS_RULES: SecretRule[] = [
  {
    id: 'gitleaks.aws-access-key-id',
    title: 'Hardcoded AWS Access Key ID',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    mask: (m) => m.slice(0, 4) + '****************',
  },
  {
    id: 'gitleaks.github-pat',
    title: 'Exposed GitHub Personal Access Token',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    regex: /\b(ghp_[A-Za-z0-9]{36})\b/,
    mask: (m) => 'ghp_' + '********************************',
  },
  {
    id: 'gitleaks.stripe-api-key',
    title: 'Hardcoded Stripe Live Secret Key',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    regex: /\b(sk_live_[0-9a-zA-Z]{24})\b/,
    mask: (m) => 'sk_live_' + '************************',
  },
  {
    id: 'gitleaks.firebase-api-key',
    title: 'Exposed Google / Firebase API Key in Client Code',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    mask: (m) => m.slice(0, 6) + '*****************************',
  },
  {
    id: 'gitleaks.private-key',
    title: 'Exposed Cryptographic Private Key',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    regex: /-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----/,
    mask: () => '-----BEGIN PRIVATE KEY----- [REDACTED SECRET BYTES] -----END PRIVATE KEY-----',
  },
  {
    id: 'gitleaks.db-connection-string',
    title: 'Database URI with Embedded Credentials',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-]+:([^@\s]+)@/i,
    mask: (m) => m.replace(/:([^@\s]+)@/, ':****@'),
  },
  {
    id: 'gitleaks.generic-api-key',
    title: 'Generic Hardcoded Secret / API Token',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    regex: /(?:api_?key|secret_?key|auth_?token|client_?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/i,
    mask: (m) => m.slice(0, 10) + '****************',
  },
];

export class GitleaksAdapter implements SecurityToolAdapter {
  readonly name = 'GITLEAKS';
  readonly version = '8.18.2';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];

    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'gitleaks');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      // 1. If Target is a live URL, crawl HTML and client JavaScript bundles for leaked secrets
      if (input.targetUrl) {
        await this.scanWebTarget(input.targetUrl, findings);
      }

      // 2. If source code path is provided or available, scan local filesystem
      const sourceDir = input.sourcePath || (input.targetType === 'FILE_ZIP' ? input.targetUrl : null);
      if (sourceDir && fs.existsSync(sourceDir)) {
        this.scanDirectory(sourceDir, findings);
      }

      const resultPath = path.join(outputDir, `scan-${input.scanId}-gitleaks.json`);
      fs.writeFileSync(resultPath, JSON.stringify({
        tool: this.name,
        version: this.version,
        targetUrl: input.targetUrl || null,
        sourceDir: sourceDir || null,
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

  private async scanWebTarget(targetUrl: string, findings: RawToolFinding[]): Promise<void> {
    try {
      const resp = await fetch(targetUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0 SentinelAI-Gitleaks/2.0' },
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) return;
      const html = await resp.text();

      // Scan HTML itself
      this.scanTextContent(html, targetUrl, 'HTML Source', findings);

      // Extract script src attributes
      const scriptRegex = /<script[^>]+src=["']([^"'>\s]+)["']/gi;
      const scriptUrls: string[] = [];
      let match: RegExpExecArray | null;
      while ((match = scriptRegex.exec(html)) !== null) {
        const raw = match[1].trim();
        try {
          const resolved = new URL(raw, targetUrl).toString();
          if (!scriptUrls.includes(resolved)) {
            scriptUrls.push(resolved);
          }
        } catch {}
      }

      // Fetch and inspect top external scripts (up to 8)
      for (const sUrl of scriptUrls.slice(0, 8)) {
        try {
          const sResp = await fetch(sUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'SentinelAI-Gitleaks/2.0' },
            signal: AbortSignal.timeout(6000),
          }).catch(() => null);

          if (sResp && sResp.ok) {
            const jsContent = await sResp.text().catch(() => '');
            if (jsContent && jsContent.length > 20 && jsContent.length < 3 * 1024 * 1024) {
              const scriptName = path.basename(new URL(sUrl).pathname) || 'bundle.js';
              this.scanTextContent(jsContent, sUrl, scriptName, findings);
            }
          }
        } catch {}
      }
    } catch (err) {
      console.warn('[Gitleaks] Web target scan warning:', (err as Error).message);
    }
  }

  private scanTextContent(content: string, sourceLocation: string, label: string, findings: RawToolFinding[]): void {
    const lines = content.split('\n');
    const maxLines = Math.min(lines.length, 5000);

    for (let i = 0; i < maxLines; i++) {
      const line = lines[i];
      if (line.length > 2000) continue; // Skip minified mega-lines to avoid catastrophic regex backtracking

      for (const rule of GITLEAKS_RULES) {
        const match = line.match(rule.regex);
        if (match) {
          const secretMatch = match[1] || match[0];
          const masked = rule.mask(secretMatch);

          findings.push({
            title: rule.title,
            severity: rule.severity,
            confidence: 'CONFIRMED',
            category: rule.category,
            sourceRuleId: rule.id,
            filePath: sourceLocation,
            lineStart: i + 1,
            lineEnd: i + 1,
            evidenceSummary: `Detected secret in ${label} at line ${i + 1}: ${masked}`,
            rawSnippet: line.replace(secretMatch, masked).trim().slice(0, 160),
            remediation: 'Immediately revoke and rotate the exposed credential. Store secrets strictly in backend environment variables or a secrets manager.',
            cwe: 'CWE-798',
          });
        }
      }
    }
  }

  private scanDirectory(dirPath: string, findings: RawToolFinding[], depth = 0): void {
    if (depth > 6 || !fs.existsSync(dirPath)) return;

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        if (['node_modules', 'dist', 'build', '.system_generated', '.git'].includes(entry.name)) {
          continue;
        }
        this.scanDirectory(fullPath, findings, depth + 1);
      } else if (entry.isFile()) {
        this.scanFile(fullPath, findings);
      }
    }
  }

  private scanFile(filePath: string, findings: RawToolFinding[]): void {
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > 2 * 1024 * 1024) return;

      const content = fs.readFileSync(filePath, 'utf8');
      const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
      this.scanTextContent(content, relPath, path.basename(filePath), findings);
    } catch {}
  }
}
