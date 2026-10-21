import { prisma } from '../config/db';
import { TOOL_ADAPTERS } from '../tools';

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
  const { scanId, targetType, hasUrl, hasSourceCode } = options;

  let scanProfile: 'URL_BASED_DAST' | 'PURE_SAST' | 'HYBRID_DAST_SAST' = 'URL_BASED_DAST';
  if (hasUrl && hasSourceCode) {
    scanProfile = 'HYBRID_DAST_SAST';
  } else if (!hasUrl && hasSourceCode) {
    scanProfile = 'PURE_SAST';
  } else {
    scanProfile = 'URL_BASED_DAST';
  }

  const plannedTasks: PlannedTask[] = [];

  // 1. OWASP ZAP (DAST) - Runs active web application security checks
  if (hasUrl) {
    plannedTasks.push({ toolName: 'OWASP_ZAP', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'OWASP_ZAP',
      status: 'SKIPPED',
      reason: 'DAST requires a running target URL. Source code only provided.',
    });
  }

  // 2. Semgrep (SAST) - Analyzes server source code or client-side JavaScript AST / DOM sinks
  plannedTasks.push({ toolName: 'SEMGREP', status: 'PENDING' });

  // 3. Gitleaks (Secrets) - Inspects source code files or client-side bundles & HTML for leaked credentials
  plannedTasks.push({ toolName: 'GITLEAKS', status: 'PENDING' });

  // 4. Trivy (Component / Dependency CVE Analysis) - Audits project manifests or client-side libraries
  plannedTasks.push({ toolName: 'TRIVY', status: 'PENDING' });

  // 5. npm audit (Dependencies) - Validates dependency vulnerabilities against the advisory database
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
