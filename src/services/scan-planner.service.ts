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
  const { scanId, targetType, environment, hasUrl, hasSourceCode } = options;
  const isDevelopment = (environment || '').toUpperCase() === 'DEVELOPMENT' || targetType === 'FILE_ZIP';

  let scanProfile: 'URL_BASED_DAST' | 'PURE_SAST' | 'HYBRID_DAST_SAST' = 'URL_BASED_DAST';
  if (isDevelopment) {
    scanProfile = 'PURE_SAST';
  } else if (hasUrl && hasSourceCode) {
    scanProfile = 'HYBRID_DAST_SAST';
  } else if (!hasUrl && hasSourceCode) {
    scanProfile = 'PURE_SAST';
  } else {
    scanProfile = 'URL_BASED_DAST';
  }

  const plannedTasks: PlannedTask[] = [];

  // DAST tools (OWASP ZAP, Nuclei, WPScan, WhatWeb, TestSSL) are ONLY added when inspecting a live URL in Production/Staging.
  // In Development Mode (or when uploading source code), link tools do NOT run and are NOT added (omitted completely).
  const liveUrlApplicable = hasUrl && !isDevelopment;
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'OWASP_ZAP', status: 'PENDING' });
    plannedTasks.push({ toolName: 'NUCLEI', status: 'PENDING' });
    plannedTasks.push({ toolName: 'WPSCAN', status: 'PENDING' });
    plannedTasks.push({ toolName: 'WHATWEB', status: 'PENDING' });
    plannedTasks.push({ toolName: 'TESTSSL', status: 'PENDING' });
  }

  // Source Code, Secret, Dependency, and IaC tools (Applicable to code repositories and hybrid targets)
  plannedTasks.push({ toolName: 'SEMGREP', status: 'PENDING' });
  plannedTasks.push({ toolName: 'CODEQL', status: 'PENDING' });
  plannedTasks.push({ toolName: 'GITLEAKS', status: 'PENDING' });
  plannedTasks.push({ toolName: 'TRIVY', status: 'PENDING' });
  plannedTasks.push({ toolName: 'OSV_SCANNER', status: 'PENDING' });
  plannedTasks.push({ toolName: 'CHECKOV', status: 'PENDING' });
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
