import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding, SeverityLevel } from './security-tool.interface';

const execFileAsync = promisify(execFile);

export class NpmAuditAdapter implements SecurityToolAdapter {
  readonly name = 'NPM_AUDIT';
  readonly version = '10.8.2';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];

    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'npm-audit');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      // 1. If Target is a remote URL, probe for exposed package manifest
      let remoteManifestData: any = null;
      if (input.targetUrl) {
        try {
          const pkgUrl = new URL('/package.json', input.targetUrl).toString();
          const pkgResp = await fetch(pkgUrl, {
            method: 'GET',
            headers: { 'User-Agent': 'SentinelAI-NpmAudit/2.0' },
            signal: AbortSignal.timeout(6000),
          }).catch(() => null);

          if (pkgResp && pkgResp.status === 200) {
            const body = await pkgResp.text().catch(() => '');
            if (body.startsWith('{') && body.includes('"dependencies"')) {
              remoteManifestData = JSON.parse(body);
              findings.push({
                title: 'Exposed package.json File Disclosing Dependency Manifest',
                severity: 'MEDIUM',
                confidence: 'CONFIRMED',
                category: 'INFORMATION_DISCLOSURE',
                sourceRuleId: 'NPM-EXP-PKG',
                filePath: pkgUrl,
                evidenceSummary: `Publicly accessible /package.json discovered on ${pkgUrl}, disclosing exact versions of internal packages.`,
                remediation: 'Block direct web access to package.json, package-lock.json, and all configuration files at the reverse proxy level.',
                cwe: 'CWE-200',
              });
            }
          }
        } catch {}
      }

      // 2. Audit local project packages or resolve directory
      const sourceDir = input.sourcePath || (input.targetType === 'FILE_ZIP' ? input.targetUrl : null);
      const resolvedDir = sourceDir && fs.existsSync(sourceDir) ? sourceDir : process.cwd();
      const pkgPath = path.join(resolvedDir, 'package.json');

      let auditJson: any = null;
      if (fs.existsSync(pkgPath)) {
        try {
          const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
          const { stdout, stderr } = await execFileAsync(npmCmd, ['audit', '--json'], {
            cwd: resolvedDir,
            timeout: input.timeoutMs || 45_000,
            maxBuffer: 10 * 1024 * 1024,
          });
          const raw = stdout || stderr;
          auditJson = JSON.parse(raw);
        } catch (execErr: any) {
          if (execErr.stdout) {
            try {
              auditJson = JSON.parse(execErr.stdout);
            } catch {}
          }
        }
      }

      if (auditJson && auditJson.vulnerabilities) {
        for (const [pkgName, vulnData] of Object.entries<any>(auditJson.vulnerabilities)) {
          const sev = String(vulnData.severity || 'moderate').toUpperCase();
          let mappedSev: SeverityLevel = 'MEDIUM';
          if (sev === 'CRITICAL') mappedSev = 'CRITICAL';
          else if (sev === 'HIGH') mappedSev = 'HIGH';
          else if (sev === 'LOW') mappedSev = 'LOW';
          else if (sev === 'INFO') mappedSev = 'INFO';

          const via = Array.isArray(vulnData.via) ? vulnData.via : [];
          const advisory = via.find((v: any) => typeof v === 'object') || {};

          findings.push({
            title: advisory.title || `Vulnerable Dependency: ${pkgName}`,
            severity: mappedSev,
            confidence: 'CONFIRMED',
            category: 'DEPENDENCY_VULNERABILITY',
            sourceRuleId: advisory.source ? String(advisory.source) : `npm-${pkgName}`,
            filePath: path.relative(process.cwd(), pkgPath).replace(/\\/g, '/'),
            evidenceSummary: `Direct/transitive dependency "${pkgName}" has known ${mappedSev.toLowerCase()} severity issues (range: ${vulnData.range || 'N/A'}). Advisory: ${advisory.url || 'https://www.npmjs.com'}`,
            remediation: vulnData.fixAvailable
              ? `Update package: ${typeof vulnData.fixAvailable === 'object' ? `npm install ${vulnData.fixAvailable.name}@${vulnData.fixAvailable.version}` : 'npm audit fix'}`
              : 'Review package dependencies and consider updating major versions or switching to supported alternatives.',
            cwe: advisory.cwe && advisory.cwe[0] ? advisory.cwe[0] : 'CWE-1395',
            cve: advisory.cve && advisory.cve[0] ? advisory.cve[0] : undefined,
          });
        }
      }

      const resultPath = path.join(outputDir, `scan-${input.scanId}-npm-audit.json`);
      fs.writeFileSync(resultPath, JSON.stringify({
        tool: this.name,
        version: this.version,
        targetDir: resolvedDir,
        targetUrl: input.targetUrl || null,
        scannedAt: new Date().toISOString(),
        findingsCount: findings.length,
        findings,
        rawJsonSummary: auditJson?.metadata || null,
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
