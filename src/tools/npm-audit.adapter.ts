import fs from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding, SeverityLevel } from './security-tool.interface';

const execFileAsync = promisify(execFile);

export class NpmAuditAdapter implements SecurityToolAdapter {
  readonly name = 'NPM_AUDIT';
  readonly version = '10.8.2';
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
        skippedReason: 'Target is URL-only; npm audit requires a directory containing package.json and a lockfile.',
      };
    }

    const resolvedDir = sourceDir && fs.existsSync(sourceDir) ? sourceDir : process.cwd();
    const pkgPath = path.join(resolvedDir, 'package.json');

    if (!fs.existsSync(pkgPath)) {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings: [],
        skippedReason: 'No package.json file found in the target directory.',
      };
    }

    const outputDir = path.join(process.cwd(), 'storage', 'tool-results', 'npm-audit');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
      let auditJson: any = null;
      let rawOutput = '';

      // Run real npm audit --json on resolved directory
      try {
        const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
        const { stdout, stderr } = await execFileAsync(npmCmd, ['audit', '--json'], {
          cwd: resolvedDir,
          timeout: input.timeoutMs || 45_000,
          maxBuffer: 10 * 1024 * 1024,
        });
        rawOutput = stdout || stderr;
        auditJson = JSON.parse(rawOutput);
      } catch (execErr: any) {
        // npm audit exits with code 1 if vulnerabilities are found
        if (execErr.stdout) {
          try {
            auditJson = JSON.parse(execErr.stdout);
            rawOutput = execErr.stdout;
          } catch {}
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
              : 'Review package dependencies and consider alternative packages or updating major versions.',
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
