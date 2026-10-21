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

  // 1. OWASP ZAP (DAST)
  if (hasUrl) {
    plannedTasks.push({ toolName: 'OWASP_ZAP', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'OWASP_ZAP',
      status: 'SKIPPED',
      reason: 'DAST requires a running target URL. Source code only provided.',
    });
  }

  // 2. Semgrep (SAST)
  if (hasSourceCode) {
    plannedTasks.push({ toolName: 'SEMGREP', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'SEMGREP',
      status: 'SKIPPED',
      reason: 'SAST requires repository source code or uploaded archive.',
    });
  }

  // 3. Gitleaks (Secrets)
  if (hasSourceCode) {
    plannedTasks.push({ toolName: 'GITLEAKS', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'GITLEAKS',
      status: 'SKIPPED',
      reason: 'Secret detection requires source code files or git repository history.',
    });
  }

  // 4. Trivy (Config / Dependencies)
  if (hasSourceCode) {
    plannedTasks.push({ toolName: 'TRIVY', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'TRIVY',
      status: 'SKIPPED',
      reason: 'Trivy requires project dependency manifests (package.json, requirements.txt) or container files.',
    });
  }

  // 5. npm audit (Dependencies)
  if (hasSourceCode) {
    plannedTasks.push({ toolName: 'NPM_AUDIT', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'NPM_AUDIT',
      status: 'SKIPPED',
      reason: 'npm audit requires package.json and lockfile within the project.',
    });
  }

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
