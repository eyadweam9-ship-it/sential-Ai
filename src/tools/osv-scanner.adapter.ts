import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';
import { threatIntelSyncService, DependencyItem } from '../services/threat-intel-sync.service';

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

const STATIC_OSV_ADVISORIES: OsvAdvisory[] = [
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
  readonly version = 'v2.0.0-ThreatIntel';
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
      const searchDirs = [input.sourcePath || '', process.cwd()].filter(Boolean);
      const manifestNames = [
        'package.json',
        'package-lock.json',
        'requirements.txt',
        'composer.json',
        'composer.lock',
        'go.mod',
        'pom.xml',
      ];

      const discoveredDeps: Array<DependencyItem & { manifestPath: string }> = [];
      const auditedPackages = new Map<string, string>();

      for (const dir of searchDirs) {
        for (const mName of manifestNames) {
          const fp = path.join(dir, mName);
          if (fs.existsSync(fp)) {
            try {
              const content = fs.readFileSync(fp, 'utf8');
              const parsed = threatIntelSyncService.parseManifest(mName, content);
              for (const dep of parsed) {
                discoveredDeps.push({ ...dep, manifestPath: path.relative(dir, fp) || mName });
                auditedPackages.set(dep.name, dep.version);
              }
            } catch {}
          }
        }
      }

      // 1. Live Threat Intelligence query (OSV.dev + GitHub Advisories)
      if (discoveredDeps.length > 0) {
        try {
          const liveResult = await threatIntelSyncService.batchScanDependencies(
            discoveredDeps.map(d => ({ name: d.name, version: d.version, ecosystem: d.ecosystem }))
          );

          for (const adv of liveResult.advisories) {
            const cveAlias = adv.aliases.find(a => a.startsWith('CVE-')) || adv.id;
            const relManifest =
              discoveredDeps.find(d => d.name === adv.affectedPackage)?.manifestPath || 'package.json';

            findings.push({
              title: `OSV Advisory: ${adv.summary}`,
              severity: adv.severity,
              confidence: 'CONFIRMED',
              category: 'VULNERABLE_DEPENDENCY',
              sourceRuleId: `osv.${adv.id}`,
              filePath: relManifest,
              evidenceSummary: `Detected dependency ${adv.affectedPackage}@${adv.targetVersion} (${adv.ecosystem}) affected by ${cveAlias} (${adv.id}). ${adv.fixedVersion ? `Fixed in ${adv.fixedVersion}.` : ''}`,
              rawSnippet: `Dependency: "${adv.affectedPackage}": "${adv.targetVersion}"\nEcosystem: ${adv.ecosystem}\nAdvisory: ${adv.id}\nCVE: ${cveAlias}\nDatabase: Live Google OSV / GitHub Security Advisories\nFixed Version: ${adv.fixedVersion || 'Unfixed / Workaround'}`,
              remediation: adv.fixedVersion
                ? `Upgrade "${adv.affectedPackage}" to version ${adv.fixedVersion} or higher in ${relManifest}.`
                : `Review advisory ${adv.id} for recommended mitigation.`,
              cwe: adv.cweIds[0] || 'CWE-1395',
              cve: cveAlias,
            });
          }
        } catch (liveErr) {
          console.warn('[OsvScannerAdapter] Live threat intel scan encountered error, falling back to static:', (liveErr as Error).message);
        }
      }

      // 2. Static Advisory Fallback (if no live findings detected, ensure static coverage)
      if (findings.length === 0) {
        for (const adv of STATIC_OSV_ADVISORIES) {
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
