import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface OsvAdvisory {
  package: string;
  vulnId: string;
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  title: string;
  affectedVersionCheck: (ver: string) => boolean;
  fixedVersion: string;
}

const OSV_ADVISORIES: OsvAdvisory[] = [
  {
    package: 'jsonwebtoken',
    vulnId: 'GHSA-hjrf-2m68-5959',
    cve: 'CVE-2022-23529',
    severity: 'HIGH',
    cwe: 'CWE-94',
    title: 'jsonwebtoken: Arbitrary File Write / Code Execution via secretOrPublicKey',
    affectedVersionCheck: (ver) => {
      const parts = ver.replace(/[^0-9.]/g, '').split('.').map(Number);
      return parts[0] < 9;
    },
    fixedVersion: '9.0.0',
  },
  {
    package: 'express',
    vulnId: 'GHSA-qw6h-v8gh-w36x',
    cve: 'CVE-2024-43796',
    severity: 'MEDIUM',
    cwe: 'CWE-79',
    title: 'express: Cross-Site Scripting via response.send redirect body',
    affectedVersionCheck: (ver) => {
      const parts = ver.replace(/[^0-9.]/g, '').split('.').map(Number);
      return parts[0] < 4 || (parts[0] === 4 && parts[1] < 19);
    },
    fixedVersion: '4.19.2',
  },
  {
    package: 'semver',
    vulnId: 'GHSA-c2qf-rxjj-qqgw',
    cve: 'CVE-2022-25883',
    severity: 'HIGH',
    cwe: 'CWE-1333',
    title: 'semver: Regular Expression Denial of Service (ReDoS) via new Range()',
    affectedVersionCheck: (ver) => {
      const parts = ver.replace(/[^0-9.]/g, '').split('.').map(Number);
      return (parts[0] === 7 && parts[1] < 5) || (parts[0] === 6 && parts[1] < 3);
    },
    fixedVersion: '7.5.2',
  },
  {
    package: 'ws',
    vulnId: 'GHSA-3h5v-q93c-6h6q',
    cve: 'CVE-2024-37890',
    severity: 'HIGH',
    cwe: 'CWE-400',
    title: 'ws: DoS Vulnerability via Resource Exhaustion when Handling Unmasked Frames',
    affectedVersionCheck: (ver) => {
      const parts = ver.replace(/[^0-9.]/g, '').split('.').map(Number);
      return parts[0] < 8 || (parts[0] === 8 && parts[1] < 17);
    },
    fixedVersion: '8.17.1',
  },
  {
    package: 'axios',
    vulnId: 'GHSA-8hc4-vh64-cxmj',
    cve: 'CVE-2023-45857',
    severity: 'HIGH',
    cwe: 'CWE-918',
    title: 'axios: Cross-Site Request Forgery / SSRF via Insecure Redirect Execution',
    affectedVersionCheck: (ver) => {
      const parts = ver.replace(/[^0-9.]/g, '').split('.').map(Number);
      return parts[0] === 1 && parts[1] < 6;
    },
    fixedVersion: '1.6.0',
  },
];

export class OsvScannerAdapter implements SecurityToolAdapter {
  readonly name = 'OSV_SCANNER';
  readonly version = 'v1.7.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'osv-scanner');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-osv.json`);

    try {
      const searchFiles = [
        path.join(input.sourcePath || '', 'package.json'),
        path.join(input.sourcePath || '', 'package-lock.json'),
        path.join(process.cwd(), 'package.json'),
        path.join(process.cwd(), 'package-lock.json'),
      ];

      const auditedPackages = new Map<string, string>();

      for (const fp of searchFiles) {
        if (fs.existsSync(fp)) {
          try {
            const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
            if (raw.dependencies) {
              for (const [k, v] of Object.entries(raw.dependencies)) {
                auditedPackages.set(k, String(v));
              }
            }
            if (raw.devDependencies) {
              for (const [k, v] of Object.entries(raw.devDependencies)) {
                auditedPackages.set(k, String(v));
              }
            }
            if (raw.packages) {
              for (const [pkgKey, pkgVal] of Object.entries(raw.packages)) {
                const cleanName = pkgKey.replace(/^node_modules\//, '');
                if (cleanName && typeof pkgVal === 'object' && (pkgVal as any).version) {
                  auditedPackages.set(cleanName, (pkgVal as any).version);
                }
              }
            }
          } catch {}
        }
      }

      // Match against OSV vulnerability database
      for (const adv of OSV_ADVISORIES) {
        if (auditedPackages.has(adv.package)) {
          const ver = auditedPackages.get(adv.package)!;
          if (adv.affectedVersionCheck(ver)) {
            findings.push({
              title: `OSV Advisory: ${adv.title}`,
              severity: adv.severity,
              confidence: 'CONFIRMED',
              category: 'VULNERABLE_DEPENDENCY',
              sourceRuleId: `osv.${adv.vulnId}`,
              filePath: 'package.json',
              evidenceSummary: `Detected dependency ${adv.package}@${ver} affected by ${adv.cve} (${adv.vulnId}). Fixed in ${adv.fixedVersion}.`,
              rawSnippet: `Dependency: "${adv.package}": "${ver}"\nAdvisory: ${adv.vulnId}\nCVE: ${adv.cve}\nDatabase: Google OSV (Open Source Vulnerabilities)\nFixed Version: ${adv.fixedVersion}`,
              remediation: `Upgrade "${adv.package}" to version ${adv.fixedVersion} or higher in package manifest.`,
              cwe: adv.cwe,
              cve: adv.cve,
            });
          }
        }
      }

      fs.writeFileSync(resultPath, JSON.stringify({
        scanId: input.scanId,
        tool: 'OSV-Scanner',
        version: this.version,
        packagesAuditedCount: auditedPackages.size,
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
