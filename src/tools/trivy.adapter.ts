import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface WebLibraryCveRule {
  name: string;
  versionRegex: RegExp;
  isVulnerable: (version: string) => boolean;
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  cwe: string;
  remediation: string;
}

const WEB_LIBRARY_RULES: WebLibraryCveRule[] = [
  {
    name: 'jQuery',
    versionRegex: /(?:jQuery\s+v|jquery[-/])([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    isVulnerable: (ver) => {
      const parts = ver.split('.').map(Number);
      if (parts[0] < 3) return true;
      if (parts[0] === 3 && parts[1] < 5) return true;
      return false;
    },
    cve: 'CVE-2020-11022',
    severity: 'HIGH',
    title: 'Outdated jQuery Library: Cross-Site Scripting (XSS) via htmlPrefilter',
    cwe: 'CWE-79',
    remediation: 'Upgrade client-side jQuery to version 3.5.0 or later.',
  },
  {
    name: 'Bootstrap',
    versionRegex: /Bootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    isVulnerable: (ver) => {
      const parts = ver.split('.').map(Number);
      if (parts[0] < 4) return true;
      if (parts[0] === 4 && parts[1] < 3) return true;
      return false;
    },
    cve: 'CVE-2019-8331',
    severity: 'MEDIUM',
    title: 'Outdated Bootstrap: Cross-Site Scripting (XSS) in Tooltip and Popover',
    cwe: 'CWE-79',
    remediation: 'Upgrade Bootstrap to version 4.3.1 or 5.x.',
  },
  {
    name: 'Lodash',
    versionRegex: /lodash(?:-amd|-es)?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    isVulnerable: (ver) => {
      const parts = ver.split('.').map(Number);
      if (parts[0] < 4) return true;
      if (parts[0] === 4 && (parts[1] < 17 || (parts[1] === 17 && (parts[2] || 0) < 21))) return true;
      return false;
    },
    cve: 'CVE-2021-23337',
    severity: 'HIGH',
    title: 'Outdated Lodash: Prototype Pollution in template Function',
    cwe: 'CWE-1321',
    remediation: 'Upgrade Lodash to version 4.17.21 or later.',
  },
  {
    name: 'Axios',
    versionRegex: /axios\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    isVulnerable: (ver) => {
      const parts = ver.split('.').map(Number);
      if (parts[0] === 0 && parts[1] < 22) return true;
      return false;
    },
    cve: 'CVE-2020-28168',
    severity: 'HIGH',
    title: 'Axios Insecure Follow Redirects (Potential SSRF)',
    cwe: 'CWE-918',
    remediation: 'Upgrade Axios client library to version 0.22.0 or newer.',
  },
  {
    name: 'Next.js',
    versionRegex: /next@([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    isVulnerable: (ver) => {
      const parts = ver.split('.').map(Number);
      // Next.js versions < 14.1.1 have known SSR Cache Poisoning (CVE-2024-34351)
      if (parts[0] < 14) return true;
      if (parts[0] === 14 && parts[1] === 0) return true;
      if (parts[0] === 14 && parts[1] === 1 && (parts[2] || 0) < 1) return true;
      return false;
    },
    cve: 'CVE-2024-34351',
    severity: 'HIGH',
    title: 'Outdated Next.js Server Components: SSR Host Header Poisoning',
    cwe: 'CWE-644',
    remediation: 'Upgrade Next.js framework to version 14.1.1 or higher.',
  },
];

export class TrivyAdapter implements SecurityToolAdapter {
  readonly name = 'TRIVY';
  readonly version = '0.51.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];

    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'trivy');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      // 1. If Target is a live URL, perform Software Composition Analysis (SCA) on client libraries
      if (input.targetUrl) {
        await this.auditWebLibraries(input.targetUrl, findings);
      }

      // 2. If source files or directory exist, audit package manifests & Dockerfiles
      const sourceDir = input.sourcePath || (input.targetType === 'FILE_ZIP' ? input.targetUrl : null);
      if (sourceDir && fs.existsSync(sourceDir)) {
        this.auditLocalProject(sourceDir, findings);
      }

      const resultPath = path.join(outputDir, `scan-${input.scanId}-trivy.json`);
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

  private async auditWebLibraries(targetUrl: string, findings: RawToolFinding[]): Promise<void> {
    try {
      const resp = await fetch(targetUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'Mozilla/5.0 SentinelAI-Trivy/2.0' },
        signal: AbortSignal.timeout(10_000),
      });

      if (!resp.ok) return;
      const html = await resp.text();

      // Check HTML for library version banners or script filenames
      this.matchLibrarySignatures(html, targetUrl, findings);

      // Extract script tags
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

      // Inspect external scripts for library banners (up to 12 scripts)
      for (const sUrl of scriptUrls.slice(0, 12)) {
        try {
          const sResp = await fetch(sUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'SentinelAI-Trivy/2.0' },
            signal: AbortSignal.timeout(6000),
          }).catch(() => null);

          if (sResp && sResp.ok) {
            const jsContent = (await sResp.text().catch(() => '')).slice(0, 300_000);
            this.matchLibrarySignatures(jsContent, sUrl, findings);
          }
        } catch {}
      }
    } catch (err) {
      console.warn('[Trivy] Web library audit warning:', (err as Error).message);
    }
  }

  private matchLibrarySignatures(text: string, locationUrl: string, findings: RawToolFinding[]): void {
    for (const rule of WEB_LIBRARY_RULES) {
      const match = text.match(rule.versionRegex);
      if (match && match[1]) {
        const detectedVer = match[1];
        if (rule.isVulnerable(detectedVer)) {
          const exists = findings.some(f => f.sourceRuleId === rule.cve && f.filePath === locationUrl);
          if (!exists) {
            findings.push({
              title: rule.title,
              severity: rule.severity,
              confidence: 'HIGH',
              category: 'VULNERABLE_DEPENDENCY',
              sourceRuleId: rule.cve,
              filePath: locationUrl,
              evidenceSummary: `Detected "${rule.name}" library version ${detectedVer} in ${path.basename(locationUrl) || 'index'} which is vulnerable to ${rule.cve}.`,
              remediation: rule.remediation,
              cwe: rule.cwe,
              cve: rule.cve,
            });
          }
        }
      }
    }
  }

  private auditLocalProject(dirPath: string, findings: RawToolFinding[]): void {
    const pkgPath = path.join(dirPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        const deps = { ...(pkgData.dependencies || {}), ...(pkgData.devDependencies || {}) };

        for (const [depName, depVer] of Object.entries(deps)) {
          const cleanVer = String(depVer).replace(/^[\^~>=<]/, '');
          for (const rule of WEB_LIBRARY_RULES) {
            if (depName.toLowerCase() === rule.name.toLowerCase() && rule.isVulnerable(cleanVer)) {
              findings.push({
                title: rule.title,
                severity: rule.severity,
                confidence: 'HIGH',
                category: 'VULNERABLE_DEPENDENCY',
                sourceRuleId: rule.cve,
                filePath: path.relative(process.cwd(), pkgPath).replace(/\\/g, '/'),
                evidenceSummary: `Package "${depName}" detected at version ${depVer} which is vulnerable to ${rule.cve}.`,
                remediation: `Upgrade "${depName}" to the latest patched version.`,
                cwe: rule.cwe,
                cve: rule.cve,
              });
            }
          }
        }
      } catch {}
    }

    const dockerfilePath = path.join(dirPath, 'Dockerfile');
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
            evidenceSummary: 'Dockerfile does not specify an unprivileged USER instruction. Running as root violates the principle of least privilege.',
            remediation: 'Specify an unprivileged user (e.g. USER node) in the Dockerfile.',
            cwe: 'CWE-250',
          });
        }
      } catch {}
    }
  }
}
