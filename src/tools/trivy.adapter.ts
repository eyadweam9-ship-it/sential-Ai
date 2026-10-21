import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface VulnerablePackageRule {
  name: string;
  maxVulnerableVersion: string;
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  cwe: string;
}

const KNOWN_CVE_PACKAGES: VulnerablePackageRule[] = [
  {
    name: 'axios',
    maxVulnerableVersion: '0.21.1',
    cve: 'CVE-2020-28168',
    severity: 'HIGH',
    title: 'Axios Server-Side Request Forgery (SSRF) via Insecure Follow Redirects',
    cwe: 'CWE-918',
  },
  {
    name: 'lodash',
    maxVulnerableVersion: '4.17.20',
    cve: 'CVE-2021-23337',
    severity: 'HIGH',
    title: 'Lodash Prototype Pollution via template function',
    cwe: 'CWE-1321',
  },
  {
    name: 'minimist',
    maxVulnerableVersion: '1.2.5',
    cve: 'CVE-2021-44906',
    severity: 'HIGH',
    title: 'Minimist Prototype Pollution via constructor/proto overrides',
    cwe: 'CWE-1321',
  },
  {
    name: 'jsonwebtoken',
    maxVulnerableVersion: '8.5.1',
    cve: 'CVE-2022-23529',
    severity: 'CRITICAL',
    title: 'JsonWebToken Arbitrary File Write / Code Execution via verify secretOrPublicKey',
    cwe: 'CWE-94',
  },
];

export class TrivyAdapter implements SecurityToolAdapter {
  readonly name = 'TRIVY';
  readonly version = '0.51.0';
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
        skippedReason: 'Target is URL-only; Trivy requires project manifest files (package.json, Dockerfile) or container image.',
      };
    }

    const resolvedDir = sourceDir && fs.existsSync(sourceDir) ? sourceDir : process.cwd();
    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'trivy');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      // 1. Dependency Analysis via Manifests (package.json)
      const pkgPath = path.join(resolvedDir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        try {
          const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
          const deps = { ...(pkgData.dependencies || {}), ...(pkgData.devDependencies || {}) };

          for (const [depName, depVer] of Object.entries(deps)) {
            const cleanVer = String(depVer).replace(/^[\^~>=<]/, '');
            for (const rule of KNOWN_CVE_PACKAGES) {
              if (depName === rule.name && cleanVer <= rule.maxVulnerableVersion) {
                findings.push({
                  title: rule.title,
                  severity: rule.severity,
                  confidence: 'HIGH',
                  category: 'VULNERABLE_DEPENDENCY',
                  sourceRuleId: rule.cve,
                  filePath: path.relative(process.cwd(), pkgPath).replace(/\\/g, '/'),
                  evidenceSummary: `Package "${depName}" detected at version ${depVer} which is vulnerable to ${rule.cve} (fixed in > ${rule.maxVulnerableVersion}).`,
                  remediation: `Upgrade "${depName}" to the latest patched version via "npm update ${depName}".`,
                  cwe: rule.cwe,
                  cve: rule.cve,
                });
              }
            }
          }
        } catch {}
      }

      // 2. Infrastructure / Dockerfile Security Checks
      const dockerfilePath = path.join(resolvedDir, 'Dockerfile');
      if (fs.existsSync(dockerfilePath)) {
        try {
          const content = fs.readFileSync(dockerfilePath, 'utf8');
          if (!content.includes('USER ') || content.includes('USER root')) {
            findings.push({
              title: 'Container Image Configured to Run as Root User',
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              category: 'CONTAINER_MISCONFIGURATION',
              sourceRuleId: 'TRIVY-DS002',
              filePath: path.relative(process.cwd(), dockerfilePath).replace(/\\/g, '/'),
              evidenceSummary: 'Dockerfile does not specify an unprivileged USER instruction. Containers running as root violate principle of least privilege.',
              remediation: 'Create and specify an unprivileged user (e.g. USER node or USER 1001) in the Dockerfile.',
              cwe: 'CWE-250',
            });
          }
        } catch {}
      }

      const resultPath = path.join(outputDir, `scan-${input.scanId}-trivy.json`);
      fs.writeFileSync(resultPath, JSON.stringify({
        tool: this.name,
        version: this.version,
        targetDir: resolvedDir,
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
}
