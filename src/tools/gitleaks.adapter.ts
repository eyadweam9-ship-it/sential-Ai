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
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];

    const sourceDir = input.sourcePath || (input.targetType === 'FILE_ZIP' ? input.targetUrl : null);

    if (!sourceDir && input.targetType === 'URL') {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings: [],
        skippedReason: 'Target is URL-only; Gitleaks requires source code files or a repository to inspect for secrets.',
      };
    }

    const resolvedDir = sourceDir && fs.existsSync(sourceDir) ? sourceDir : path.join(process.cwd(), 'src');
    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'gitleaks');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      this.scanDirectory(resolvedDir, findings);

      const resultPath = path.join(outputDir, `scan-${input.scanId}-gitleaks.json`);
      fs.writeFileSync(resultPath, JSON.stringify({
        tool: this.name,
        version: this.version,
        sourceDir: resolvedDir,
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

  private scanDirectory(dirPath: string, findings: RawToolFinding[], depth = 0): void {
    if (depth > 6 || !fs.existsSync(dirPath)) return;

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        if (['node_modules', 'dist', 'build', '.system_generated'].includes(entry.name)) {
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
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const rule of GITLEAKS_RULES) {
          const match = line.match(rule.regex);
          if (match) {
            const secretMatch = match[1] || match[0];
            const masked = rule.mask(secretMatch);
            const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');

            findings.push({
              title: rule.title,
              severity: rule.severity,
              confidence: 'CONFIRMED',
              category: rule.category,
              sourceRuleId: rule.id,
              filePath: relPath,
              lineStart: i + 1,
              lineEnd: i + 1,
              evidenceSummary: `Detected secret in ${path.basename(filePath)} line ${i + 1}: ${masked}`,
              rawSnippet: line.replace(secretMatch, masked).trim(),
              remediation: 'Immediately revoke and rotate the exposed credential. Store secrets strictly in environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).',
              cwe: 'CWE-798',
            });
          }
        }
      }
    } catch {}
  }
}
