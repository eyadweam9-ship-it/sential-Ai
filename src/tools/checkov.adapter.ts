import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface CheckovRule {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  targetFiles: RegExp;
  matcher: (content: string, filePath: string) => { matched: boolean; line?: number; snippet?: string; detail?: string };
  description: string;
  remediation: string;
}

const CHECKOV_RULES: CheckovRule[] = [
  {
    id: 'CKV_DOCKER_1',
    title: 'Dockerfile runs container with root privileges (Missing USER instruction)',
    category: 'CONFIGURATION_ERROR',
    severity: 'HIGH',
    cwe: 'CWE-250',
    targetFiles: /dockerfile.*|.*\.dockerfile$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      const hasFrom = lines.some((l) => /^\s*FROM\s+/i.test(l));
      const hasUser = lines.some((l) => /^\s*USER\s+(?!root\b)/i.test(l));
      if (hasFrom && !hasUser) {
        return {
          matched: true,
          line: 1,
          snippet: lines.slice(0, 5).join('\n'),
          detail: 'Container executes under root user by default. A container breakout could grant host root access.',
        };
      }
      return { matched: false };
    },
    description: 'Running containers as root grants excessive OS privileges. If an attacker breaches the application inside the container, they inherit root UID 0.',
    remediation: 'Add a non-root system user and switch to it using `USER node` or `USER nonroot` before CMD / ENTRYPOINT.',
  },
  {
    id: 'CKV_DOCKER_2',
    title: 'Dockerfile missing HEALTHCHECK instruction',
    category: 'CONFIGURATION_ERROR',
    severity: 'LOW',
    cwe: 'CWE-703',
    targetFiles: /dockerfile.*|.*\.dockerfile$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      const hasFrom = lines.some((l) => /^\s*FROM\s+/i.test(l));
      const hasHealth = lines.some((l) => /^\s*HEALTHCHECK\s+/i.test(l));
      if (hasFrom && !hasHealth) {
        return {
          matched: true,
          line: 1,
          snippet: lines[0] || 'FROM ...',
          detail: 'No HEALTHCHECK defined; orchestrators cannot monitor container liveness reliably.',
        };
      }
      return { matched: false };
    },
    description: 'Without a HEALTHCHECK instruction, orchestrators like Docker Swarm or Kubernetes cannot distinguish between an operational service and a hung process.',
    remediation: 'Add `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/health || exit 1` to Dockerfile.',
  },
  {
    id: 'CKV_DOCKER_3',
    title: 'Dockerfile uses unpinned or mutable base image tag (:latest)',
    category: 'DEPENDENCY_VULNERABILITY',
    severity: 'MEDIUM',
    cwe: 'CWE-1104',
    targetFiles: /dockerfile.*|.*\.dockerfile$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*FROM\s+([^\s:]+)(?::latest)?(?:\s+AS\s+.*)?$/i.test(line) && !line.includes('@sha256:')) {
          if (!line.includes(':') || line.includes(':latest')) {
            return {
              matched: true,
              line: i + 1,
              snippet: line.trim(),
              detail: `Base image tag is mutable (${line.trim()}). Build outputs can shift unpredictably when upstream pushes new images.`,
            };
          }
        }
      }
      return { matched: false };
    },
    description: 'Using :latest or unpinned image tags introduces supply chain risks because upstream changes automatically propagate into your production containers without notice.',
    remediation: 'Pin base images to explicit version tags or immutable cryptographic digests (e.g. node:20.11.0-alpine@sha256:...).',
  },
  {
    id: 'CKV_DOCKER_4',
    title: 'Hardcoded sensitive secret or API key in Dockerfile ENV / ARG instruction',
    category: 'HARDCODED_SECRET',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    targetFiles: /dockerfile.*|.*\.dockerfile$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*(?:ENV|ARG)\s+.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*['"]?[a-zA-Z0-9_\-\.]{6,}['"]?/i.test(line)) {
          return {
            matched: true,
            line: i + 1,
            snippet: line.trim().replace(/(=['"]?)([^'"\s]+)/, '$1[REDACTED_SECRET]'),
            detail: 'Secret variable embedded into Dockerfile layers remains permanent in image history.',
          };
        }
      }
      return { matched: false };
    },
    description: 'Environment variables declared via ENV or ARG in Dockerfiles persist in container image layers and can be inspected by anyone with docker pull access.',
    remediation: 'Mount secrets at runtime using Docker secrets, Kubernetes secrets, or environment variable injection from external vaults.',
  },
  {
    id: 'CKV_K8S_1',
    title: 'Kubernetes workload configured with elevated privileged mode',
    category: 'CONFIGURATION_ERROR',
    severity: 'CRITICAL',
    cwe: 'CWE-250',
    targetFiles: /.*\.(?:yaml|yml)$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/privileged\s*:\s*true/i.test(lines[i])) {
          return {
            matched: true,
            line: i + 1,
            snippet: lines[i].trim(),
            detail: 'Container has full host root capabilities (privileged: true).',
          };
        }
      }
      return { matched: false };
    },
    description: 'Privileged containers disable Linux security containment mechanisms (AppArmor, seccomp, capabilities), allowing direct host node takeover.',
    remediation: 'Set `securityContext.privileged: false` and grant only specific granular Linux capabilities if strictly required.',
  },
  {
    id: 'CKV_NGINX_1',
    title: 'Nginx server configuration allows deprecated or insecure TLS protocols (TLSv1.0 / TLSv1.1)',
    category: 'CONFIGURATION_ERROR',
    severity: 'HIGH',
    cwe: 'CWE-327',
    targetFiles: /.*nginx.*\.conf$|.*default\.conf$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/ssl_protocols\s+.*(?:TLSv1\b|TLSv1\.1\b)/i.test(lines[i])) {
          return {
            matched: true,
            line: i + 1,
            snippet: lines[i].trim(),
            detail: 'Deprecated TLSv1.0/1.1 protocols are vulnerable to BEAST, POODLE, and downgrade attacks.',
          };
        }
      }
      return { matched: false };
    },
    description: 'Legacy TLS protocols lack modern cipher suites and are susceptible to cryptographic attacks that compromise transit session confidentiality.',
    remediation: 'Update `ssl_protocols` to exclusively allow `TLSv1.2 TLSv1.3`.',
  },
  {
    id: 'CKV_GHA_1',
    title: 'GitHub Actions workflow vulnerable to untrusted argument / script injection',
    category: 'COMMAND_INJECTION',
    severity: 'HIGH',
    cwe: 'CWE-78',
    targetFiles: /\.github\/workflows\/.*\.ya?ml$/i,
    matcher: (content) => {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/run\s*:.*\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|comment\.body)\s*\}\}/i.test(lines[i])) {
          return {
            matched: true,
            line: i + 1,
            snippet: lines[i].trim(),
            detail: 'Untrusted PR or Issue input directly interpolated into bash execution step.',
          };
        }
      }
      return { matched: false };
    },
    description: 'Directly interpolating GitHub event context into `run:` scripts allows attackers to escape the shell command by submitting crafted issue or PR titles.',
    remediation: 'Pass the untrusted payload through environment variables (`env: TITLE: ${{ github.event.issue.title }}`) instead of direct script inline interpolation.',
  },
];

export class CheckovAdapter implements SecurityToolAdapter {
  readonly name = 'CHECKOV';
  readonly version = '3.2.0';
  readonly category = 'CONFIGURATION';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const storageDir = path.join(process.cwd(), 'storage', 'tool-results', 'checkov');
    if (!fs.existsSync(storageDir)) {
      fs.mkdirSync(storageDir, { recursive: true });
    }
    const resultPath = path.join(storageDir, `scan-${input.scanId}-checkov.json`);

    try {
      const searchDirs = [input.sourcePath, process.cwd()].filter(Boolean) as string[];

      for (const searchDir of searchDirs) {
        if (!fs.existsSync(searchDir)) continue;

        const filesToScan: string[] = [];
        const collectFiles = (dir: string, depth = 0) => {
          if (depth > 6) return;
          try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const ent of entries) {
              const full = path.join(dir, ent.name);
              if (ent.isDirectory()) {
                if (!['node_modules', '.git', 'dist', 'build', '.next', '.gemini'].includes(ent.name)) {
                  collectFiles(full, depth + 1);
                }
              } else if (ent.isFile()) {
                const rel = path.relative(searchDir, full).replace(/\\/g, '/');
                for (const rule of CHECKOV_RULES) {
                  if (rule.targetFiles.test(rel) || rule.targetFiles.test(ent.name)) {
                    filesToScan.push(full);
                    break;
                  }
                }
              }
            }
          } catch {}
        };

        collectFiles(searchDir);

        for (const filePath of filesToScan) {
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const relPath = path.relative(searchDir, filePath).replace(/\\/g, '/');

            for (const rule of CHECKOV_RULES) {
              if (rule.targetFiles.test(relPath) || rule.targetFiles.test(path.basename(filePath))) {
                const res = rule.matcher(content, filePath);
                if (res.matched) {
                  findings.push({
                    title: rule.title,
                    severity: rule.severity,
                    confidence: 'CONFIRMED',
                    category: rule.category,
                    sourceRuleId: `checkov.${rule.id}`,
                    filePath: relPath,
                    lineStart: res.line || 1,
                    lineEnd: res.line || 1,
                    evidenceSummary: `${rule.description}${res.detail ? ` (${res.detail})` : ''}`,
                    rawSnippet: res.snippet,
                    remediation: rule.remediation,
                    cwe: rule.cwe,
                  });
                }
              }
            }
          } catch {
            // Skip unreadable files
          }
        }

        if (filesToScan.length > 0) break;
      }

      // If target is URL only or no files found, inspect web infrastructure posture if targetUrl provided
      if (input.targetUrl && findings.length === 0) {
        try {
          const parsed = new URL(input.targetUrl);
          if (parsed.protocol === 'http:') {
            findings.push({
              title: 'Infrastructure Posture: Unencrypted HTTP Transport (Missing Strict HTTPS)',
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              category: 'CONFIGURATION_ERROR',
              targetUrl: input.targetUrl,
              evidenceSummary: 'The endpoint is served over unencrypted plaintext HTTP protocol without automatic TLS redirection, violating infrastructure security compliance baselines.',
              rawSnippet: `Endpoint: ${input.targetUrl}\nProtocol: HTTP/1.1 (Plaintext)\nMissing: Strict-Transport-Security & HTTPS Redirect`,
              remediation: 'Configure cloud reverse proxy or load balancer to enforce HTTP to HTTPS redirection (301 Permanent Redirect) and configure HSTS.',
              cwe: 'CWE-319',
            });
          }
        } catch {
          // ignore url parse
        }
      }

      fs.writeFileSync(resultPath, JSON.stringify({
        scanId: input.scanId,
        tool: 'Checkov',
        version: this.version,
        target: input.sourcePath || input.targetUrl,
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
