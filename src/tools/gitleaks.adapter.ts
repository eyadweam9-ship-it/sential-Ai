import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface SecretRule {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string;
  regex: RegExp;
  mask: (match: string) => string;
  remediation?: string;
}

const GITLEAKS_RULES: SecretRule[] = [
  // 1. Passwords in Code & Object Properties
  {
    id: 'gitleaks.hardcoded-password',
    title: 'Hardcoded Plaintext Password in Source Code',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /(?:password|passwd|pwd|pass|secret_pass|admin_pass|user_pass|db_pass|root_pass|auth_pass|master_pass|super_password)\s*[:=]\s*['"]([^'"\r\n\s]{3,128})['"]/i,
    mask: (m) => m.slice(0, 1) + '***' + m.slice(-1),
    remediation: 'Remove plaintext passwords from source code immediately. Migrate authentication credentials to an environment variable or secure vault (e.g. AWS Secrets Manager, HashiCorp Vault).',
  },
  // 2. Uppercase / Environment Variable Passwords & Secrets (.env files)
  {
    id: 'gitleaks.env-password',
    title: 'Hardcoded Password in Environment / Config Definition',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /^\s*(?:export\s+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|PASS|SECRET|CREDENTIAL)[A-Z0-9_]*\s*=\s*['"]?([^'"\r\n\s]{3,128})['"]?/,
    mask: (m) => m.slice(0, 1) + '***' + m.slice(-1),
    remediation: 'Do not commit .env or configuration files containing plaintext passwords to source repositories. Add .env to .gitignore and inject values via runtime secret stores.',
  },
  // 3. User Credentials Pair (Username + Password)
  {
    id: 'gitleaks.auth-credentials-pair',
    title: 'Hardcoded Authentication Credentials Pair (Username & Password)',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /(?:username|user|email)\s*[:=]\s*['"]([^'"]+)['"]\s*[,;\n\r]\s*(?:password|pass|pwd)\s*[:=]\s*['"]([^'"]+)['"]/i,
    mask: () => 'user: ***, pass: ***',
    remediation: 'Revoke and rotate the exposed user credentials. Store hashed passwords using Argon2 or bcrypt and manage accounts in a database.',
  },
  // 4. Hardcoded Emails in Variables / Configuration
  {
    id: 'gitleaks.hardcoded-email-config',
    title: 'Hardcoded Administrative or User Email in Code Configuration',
    category: 'INFORMATION_EXPOSURE',
    severity: 'MEDIUM',
    cwe: 'CWE-200',
    regex: /(?:email|user_email|admin_email|contact_email|mail|login_email|account_email|owner_email)\s*[:=]\s*['"]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['"]/i,
    mask: (m) => m.replace(/^([^@]{2})[^@]+(@.*)$/, '$1***$2'),
    remediation: 'Avoid hardcoding administrative and user emails in source code. Inject contact and administrative recipients dynamically via runtime environment variables.',
  },
  // 5. Hardcoded Standalone Email Addresses (PII / Reconnaissance Surface)
  {
    id: 'gitleaks.exposed-email-pii',
    title: 'Exposed User or Corporate Email Address (PII Leak)',
    category: 'INFORMATION_EXPOSURE',
    severity: 'LOW',
    cwe: 'CWE-359',
    regex: /\b([a-zA-Z0-9_.+-]+@(?:admin\.[a-z]+|gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|proton\.me|[a-zA-Z0-9-]+\.(?:com|org|net|io|co|ai|edu|gov)))\b/i,
    mask: (m) => m.replace(/^([^@]{2})[^@]+(@.*)$/, '$1***$2'),
    remediation: 'Remove unnecessary email addresses from production code, comments, and client bundles to prevent automated harvesting for phishing campaigns.',
  },
  // 6. SMTP & Mail Server Credentials
  {
    id: 'gitleaks.smtp-credentials',
    title: 'Hardcoded SMTP / Mail Server Password or Access Token',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /(?:smtp_pass(?:word)?|mail_password|mail_pass|smtp_auth|sendgrid_api_key|mailgun_api_key)\s*[:=]\s*['"]([^'"\r\n]{3,128})['"]/i,
    mask: (m) => m.slice(0, 2) + '****************',
    remediation: 'Immediately rotate SMTP credentials. Configure mail server credentials using encrypted secret managers.',
  },
  // 7. JWT Tokens
  {
    id: 'gitleaks.jwt-token',
    title: 'Hardcoded JSON Web Token (JWT) Bearer Token',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,})\b/,
    mask: (m) => m.slice(0, 10) + '...' + m.slice(-6),
    remediation: 'Revoke and invalidate the exposed JWT token. Session tokens must be issued dynamically upon authentication and never embedded in static code.',
  },
  // 8. Basic Auth Header
  {
    id: 'gitleaks.basic-auth-header',
    title: 'Hardcoded HTTP Basic Authentication Credential',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /Authorization:\s*Basic\s+([A-Za-z0-9+/=]{12,})/i,
    mask: (m) => 'Basic ' + m.slice(0, 4) + '****************',
    remediation: 'Remove static Basic Auth headers from client-side code and scripts.',
  },
  // 9. AWS Access Key ID
  {
    id: 'gitleaks.aws-access-key-id',
    title: 'Hardcoded AWS Access Key ID',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    mask: (m) => m.slice(0, 4) + '****************',
    remediation: 'Immediately revoke the AWS Access Key in the AWS IAM Console and rotate credentials.',
  },
  // 10. GitHub Personal Access Token
  {
    id: 'gitleaks.github-pat',
    title: 'Exposed GitHub Personal Access Token',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /\b(ghp_[A-Za-z0-9]{36})\b/,
    mask: (m) => 'ghp_' + '********************************',
    remediation: 'Immediately revoke the personal access token in GitHub Developer Settings.',
  },
  // 11. Stripe Secret Key
  {
    id: 'gitleaks.stripe-api-key',
    title: 'Hardcoded Stripe Live Secret Key',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /\b(sk_live_[0-9a-zA-Z]{24})\b/,
    mask: (m) => 'sk_live_' + '************************',
    remediation: 'Rotate the compromised Stripe Secret Key in the Stripe Dashboard.',
  },
  // 12. Google / Firebase API Key
  {
    id: 'gitleaks.firebase-api-key',
    title: 'Exposed Google / Firebase API Key in Client Code',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/,
    mask: (m) => m.slice(0, 6) + '*****************************',
    remediation: 'Apply Google Cloud Console API Key restrictions by HTTP referrer and specific APIs.',
  },
  // 13. Cryptographic Private Key
  {
    id: 'gitleaks.private-key',
    title: 'Exposed Cryptographic Private Key',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    regex: /-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----/,
    mask: () => '-----BEGIN PRIVATE KEY----- [REDACTED SECRET BYTES] -----END PRIVATE KEY-----',
    remediation: 'Revoke and regenerate private key pairs. Ensure private keys are never committed to version control.',
  },
  // 14. Database Connection URI with Embedded Password
  {
    id: 'gitleaks.db-connection-string',
    title: 'Database URI with Embedded Credentials',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-\.]+:(?:[^@\s]+)@/i,
    mask: (m) => m.replace(/:([^@\s]+)@/, ':****@'),
    remediation: 'Separate database connection strings and passwords into environment variables.',
  },
  // 15. Generic API Key / Token (starting from 8 characters)
  {
    id: 'gitleaks.generic-api-key',
    title: 'Generic Hardcoded Secret / API Token',
    category: 'HARDCODED_SECRET',
    severity: 'HIGH',
    cwe: 'CWE-798',
    regex: /(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-!@#$%^&*]{8,})['"]/i,
    mask: (m) => m.slice(0, 4) + '****************',
    remediation: 'Store API tokens in environment variables or a secrets manager.',
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
        const stat = fs.statSync(sourceDir);
        if (stat.isDirectory()) {
          this.scanDirectory(sourceDir, findings, 0, sourceDir);
        } else if (stat.isFile()) {
          this.scanFile(sourceDir, findings, path.dirname(sourceDir));
        }
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

    const emailMatchesCount = new Map<string, number>();

    for (let i = 0; i < maxLines; i++) {
      const line = lines[i];
      if (line.length > 2000) continue; // Skip minified mega-lines to avoid catastrophic regex backtracking

      // A. Correlate adjacent Email + Password variable declarations (within 5 lines)
      const emailVarMatch = line.match(/(?:email|user_email|admin_email|login_email|account_email)\s*[:=]\s*['"]([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['"]/i);
      if (emailVarMatch && !line.includes('<input') && !line.includes('placeholder')) {
        const emailVal = emailVarMatch[1];
        if (!emailVal.includes('@example.') && !emailVal.includes('@test.') && !emailVal.includes('@domain.') && !emailVal.includes('@localhost')) {
          for (let j = i + 1; j < Math.min(i + 6, maxLines); j++) {
            const nextLine = lines[j];
            const passVarMatch = nextLine.match(/(?:password|passwd|pwd|pass|admin_pass|secret_pass)\s*[:=]\s*['"]([^'"\r\n\s]{3,128})['"]/i);
            if (passVarMatch && !nextLine.includes('<input') && !nextLine.includes('placeholder')) {
              const passVal = passVarMatch[1];
              findings.push({
                title: 'Hardcoded Account Authentication Credentials (Email & Password Pair)',
                severity: 'CRITICAL',
                confidence: 'CONFIRMED',
                category: 'HARDCODED_SECRET',
                sourceRuleId: 'gitleaks.correlated-credentials-pair',
                filePath: sourceLocation,
                lineStart: i + 1,
                lineEnd: j + 1,
                evidenceSummary: `Exposed Credentials: Email: "${emailVal}" | Password: "${passVal}" (Lines ${i + 1}-${j + 1})`,
                rawSnippet: `${line.trim()}\n${nextLine.trim()}`.slice(0, 240),
                remediation: 'Immediately revoke and rotate these exposed credentials. Do not commit plaintext credentials to source control.',
                cwe: 'CWE-798',
              });
              break;
            }
          }
        }
      }

      for (const rule of GITLEAKS_RULES) {
        // Prevent flooding findings catalog with thousands of identical standalone PII emails from a single file
        if (rule.id === 'gitleaks.exposed-email-pii') {
          const currentCount = emailMatchesCount.get(sourceLocation) || 0;
          if (currentCount >= 3) continue; // max 3 sample PII disclosures per file
        }

        const match = line.match(rule.regex);
        if (match) {
          const secretMatch = match[1] || match[0];
          const lower = secretMatch.toLowerCase();
          if (
            lower.includes('placeholder') ||
            lower === 'your_password' ||
            lower === 'changeme' ||
            lower === 'todo' ||
            lower === 'undefined' ||
            lower === 'null' ||
            lower === 'false' ||
            lower === 'true' ||
            line.includes('<input') ||
            line.includes('placeholder=') ||
            line.includes('type="email"') ||
            line.includes("type='email'") ||
            line.includes('htmlspecialchars') ||
            line.includes('filter_var') ||
            lower.includes('@example.') ||
            lower.includes('@test.') ||
            lower.includes('@domain.') ||
            lower.includes('@localhost')
          ) {
            continue;
          }

          if (rule.id === 'gitleaks.exposed-email-pii') {
            emailMatchesCount.set(sourceLocation, (emailMatchesCount.get(sourceLocation) || 0) + 1);
          }

          // If auth credentials pair matched on the same line, clearly show both Email/Username and Password
          if (rule.id === 'gitleaks.auth-credentials-pair' && match[1] && match[2]) {
            findings.push({
              title: rule.title,
              severity: rule.severity,
              confidence: 'CONFIRMED',
              category: rule.category,
              sourceRuleId: rule.id,
              filePath: sourceLocation,
              lineStart: i + 1,
              lineEnd: i + 1,
              evidenceSummary: `Exposed Credentials: Email/User: "${match[1]}" | Password: "${match[2]}"`,
              rawSnippet: line.trim().slice(0, 200),
              remediation: rule.remediation || 'Immediately revoke and rotate the exposed credential.',
              cwe: rule.cwe || 'CWE-798',
            });
            continue;
          }

          findings.push({
            title: rule.title,
            severity: rule.severity,
            confidence: 'CONFIRMED',
            category: rule.category,
            sourceRuleId: rule.id,
            filePath: sourceLocation,
            lineStart: i + 1,
            lineEnd: i + 1,
            evidenceSummary: rule.category === 'HARDCODED_SECRET'
              ? `Disclosed credential in ${label} at line ${i + 1}: ${secretMatch}`
              : `Detected in ${label} at line ${i + 1}: ${secretMatch}`,
            rawSnippet: line.trim().slice(0, 200),
            remediation: rule.remediation || 'Immediately revoke and rotate the exposed credential. Store secrets strictly in backend environment variables or a secrets manager.',
            cwe: rule.cwe || 'CWE-798',
          });
        }
      }
    }
  }

  private scanDirectory(dirPath: string, findings: RawToolFinding[], depth = 0, rootDir?: string): void {
    if (depth > 12 || !fs.existsSync(dirPath)) return;
    const base = rootDir || dirPath;

    const VENDOR_AND_EXCLUDED_DIRS = new Set([
      'node_modules', 'vendor', 'bower_components', 'third_party', 'thirdparty',
      'packages', 'libs', 'bundle', 'dist', 'build', 'coverage', '.next', '.nuxt',
      '.system_generated', '__pycache__', '.venv', 'venv', 'env', '.git', '.svn'
    ]);

    const MINIFIED_PATTERNS = [
      /\.min\.(js|css|mjs)$/i,
      /\.bundle\.(js|css)$/i,
      /\.pack\.js$/i,
      /\.map$/i,
      /jquery.*\.js$/i,
      /bootstrap.*\.js$/i,
      /react.*\.production\.min\.js$/i,
    ];

    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
          if (VENDOR_AND_EXCLUDED_DIRS.has(entry.name.toLowerCase())) {
            continue;
          }
          this.scanDirectory(fullPath, findings, depth + 1, base);
        } else if (entry.isFile()) {
          const nameLower = entry.name.toLowerCase();
          if (MINIFIED_PATTERNS.some(p => p.test(nameLower))) {
            continue;
          }
          this.scanFile(fullPath, findings, base);
        }
      }
    } catch {}
  }

  private scanFile(filePath: string, findings: RawToolFinding[], baseDir?: string): void {
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > 3 * 1024 * 1024) return;

      const content = fs.readFileSync(filePath, 'utf8');
      const relPath = baseDir ? path.relative(baseDir, filePath).replace(/\\/g, '/') : path.basename(filePath);
      this.scanTextContent(content, relPath, path.basename(filePath), findings);
    } catch {}
  }
}
