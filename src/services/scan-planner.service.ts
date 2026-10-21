import { prisma } from '../config/db';

export interface PlannedTask {
  toolName: string;
  status: 'PENDING' | 'SKIPPED';
  reason?: string;
}

export interface ScanPlan {
  scanId: number;
  scanProfile: 'URL_BASED_DAST' | 'PURE_SAST' | 'HYBRID_DAST_SAST';
  tasks: PlannedTask[];
}

export async function planScanExecution(options: {
  scanId: number;
  targetType: 'URL' | 'FILE_ZIP' | 'HYBRID';
  environment: string;
  hasUrl: boolean;
  hasSourceCode: boolean;
}): Promise<ScanPlan> {
  const { scanId, hasUrl, hasSourceCode } = options;

  let scanProfile: 'URL_BASED_DAST' | 'PURE_SAST' | 'HYBRID_DAST_SAST' = 'URL_BASED_DAST';
  if (hasUrl && hasSourceCode) {
    scanProfile = 'HYBRID_DAST_SAST';
  } else if (!hasUrl && hasSourceCode) {
    scanProfile = 'PURE_SAST';
  } else {
    scanProfile = 'URL_BASED_DAST';
  }

  const plannedTasks: PlannedTask[] = [];

  // 1. OWASP ZAP (DAST) - Dynamic vulnerability inspection & HTTP security checks
  if (hasUrl) {
    plannedTasks.push({ toolName: 'OWASP_ZAP', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'OWASP_ZAP',
      status: 'SKIPPED',
      reason: 'DAST requires an active target URL. Source code only provided.',
    });
  }

  // 2. Nuclei (DAST) - Template-based vulnerability scanner for live endpoints & misconfigurations
  if (hasUrl) {
    plannedTasks.push({ toolName: 'NUCLEI', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'NUCLEI',
      status: 'SKIPPED',
      reason: 'Nuclei template scanning requires an active HTTP/HTTPS endpoint.',
    });
  }

  // 3. Semgrep (SAST) - Static AST code taint & pattern analysis on source code & client-side scripts
  plannedTasks.push({ toolName: 'SEMGREP', status: 'PENDING' });

  // 4. CodeQL (SAST) - Advanced data-flow & taint-tracking analysis (Source -> Sanitizer -> Sink)
  plannedTasks.push({ toolName: 'CODEQL', status: 'PENDING' });

  // 5. Gitleaks (Secrets) - Scans source code, repositories & web bundles for exposed API keys and tokens
  plannedTasks.push({ toolName: 'GITLEAKS', status: 'PENDING' });

  // 6. Trivy (Component / Dependency CVE Analysis) - Audits package manifests & container configurations
  plannedTasks.push({ toolName: 'TRIVY', status: 'PENDING' });

  // 7. OSV-Scanner (Supply Chain Intelligence) - Validates dependencies against Google OSV advisory database
  plannedTasks.push({ toolName: 'OSV_SCANNER', status: 'PENDING' });

  // 8. Checkov (IaC & Security Posture) - Scans Dockerfile, Kubernetes manifests & infrastructure configuration
  plannedTasks.push({ toolName: 'CHECKOV', status: 'PENDING' });

  // 9. npm audit (Dependencies) - Validates npm dependency tree against known vulnerability advisories
  plannedTasks.push({ toolName: 'NPM_AUDIT', status: 'PENDING' });

  // Persist planned tasks in database
  for (const task of plannedTasks) {
    await prisma.scanTask.create({
      data: {
        scanId,
        toolName: task.toolName,
        status: task.status,
        errorMessage: task.reason || null,
      },
    });
  }

  return {
    scanId,
    scanProfile,
    tasks: plannedTasks,
  };
}
