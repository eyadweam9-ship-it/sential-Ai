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

  // DAST tools are ONLY applicable when inspecting a live external web URL in Staging/Production.
  // In Development Mode (or when uploading source code), link tools are strictly bypassed.
  const liveUrlApplicable = hasUrl && !isDevelopment;
  const dastSkipReason = isDevelopment
    ? 'DAST tool skipped: Target is local source code (Development Mode). Live link inspection requires an active HTTP/HTTPS endpoint.'
    : 'DAST tool skipped: No target URL specified.';

  const plannedTasks: PlannedTask[] = [];

  // 1. OWASP ZAP (DAST) - Dynamic vulnerability inspection & HTTP security checks
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'OWASP_ZAP', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'OWASP_ZAP',
      status: 'SKIPPED',
      reason: dastSkipReason,
    });
  }

  // 2. Nuclei (DAST) - Template-based vulnerability scanner for live endpoints & misconfigurations
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'NUCLEI', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'NUCLEI',
      status: 'SKIPPED',
      reason: dastSkipReason,
    });
  }

  // 3. WPScan (CMS & Application Frameworks) - Audits WordPress, Joomla, Drupal, and framework endpoints
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'WPSCAN', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'WPSCAN',
      status: 'SKIPPED',
      reason: dastSkipReason,
    });
  }

  // 4. WhatWeb (Reconnaissance & WAF) - Identifies technologies, WAFs, and information disclosures
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'WHATWEB', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'WHATWEB',
      status: 'SKIPPED',
      reason: dastSkipReason,
    });
  }

  // 5. TestSSL (Transport & Security Headers) - Audits TLS encryption, HSTS, and defense headers
  if (liveUrlApplicable) {
    plannedTasks.push({ toolName: 'TESTSSL', status: 'PENDING' });
  } else {
    plannedTasks.push({
      toolName: 'TESTSSL',
      status: 'SKIPPED',
      reason: dastSkipReason,
    });
  }

  // 6. Semgrep (SAST) - Static AST code taint & pattern analysis on source code & client-side scripts
  plannedTasks.push({ toolName: 'SEMGREP', status: 'PENDING' });

  // 7. CodeQL (SAST) - Advanced data-flow & taint-tracking analysis (Source -> Sanitizer -> Sink)
  plannedTasks.push({ toolName: 'CODEQL', status: 'PENDING' });

  // 8. Gitleaks (Secrets) - Scans source code, repositories & web bundles for exposed API keys and tokens
  plannedTasks.push({ toolName: 'GITLEAKS', status: 'PENDING' });

  // 9. Trivy (Component / Dependency CVE Analysis) - Audits package manifests & container configurations
  plannedTasks.push({ toolName: 'TRIVY', status: 'PENDING' });

  // 10. OSV-Scanner (Supply Chain Intelligence) - Validates dependencies against Google OSV advisory database
  plannedTasks.push({ toolName: 'OSV_SCANNER', status: 'PENDING' });

  // 11. Checkov (IaC & Security Posture) - Scans Dockerfile, Kubernetes manifests & infrastructure configuration
  plannedTasks.push({ toolName: 'CHECKOV', status: 'PENDING' });

  // 12. npm audit (Dependencies) - Validates npm dependency tree against known vulnerability advisories
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
