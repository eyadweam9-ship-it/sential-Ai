import fs from 'fs';
import path from 'path';
import AdmZip from 'adm-zip';
import { prisma } from '../config/db';
import { planScanExecution } from './scan-planner.service';
import { getToolAdapter } from '../tools';
import { normalizeAndSaveFindings } from './findings-normalizer.service';
import { deduplicateScanFindings } from './findings-deduplication.service';
import { analyzeFindingWithAI, generateScanExecutiveSummary } from './ai-analysis.service';
import { generateScanReport } from './report.service';
import { extractSourcesFromTarget } from './source-extractor.service';
import { ToolInput } from '../tools/security-tool.interface';
import { classifyProjectFiles, ProjectClassificationReport } from './file-classifier.service';

export const activeScanState = new Map<number, { activeTool: string; activeMessage: string; progress: number }>();

async function updateScanProgress(scanId: number, progress: number, activeTool: string, activeMessage: string) {
  activeScanState.set(scanId, { activeTool, activeMessage, progress });
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      progress,
      summaryJson: JSON.stringify({ activeTool, activeMessage }),
    },
  }).catch(() => null);
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

export async function orchestrateScan(scanId: number): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: { target: true },
  });

  if (!scan) {
    throw new Error(`Scan #${scanId} does not exist.`);
  }

  try {
    // 1. Mark scan as RUNNING
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'RUNNING',
        progress: 15,
        startedAt: new Date(),
      },
    });

    const target = scan.target;
    const isUrl = target.targetType === 'URL' || Boolean(target.url && target.url.startsWith('http'));
    let effectiveSourcePath = target.filePath || undefined;

    // Safety guard: Never scan SentinelAI's own backend source code tree ('src')
    if (effectiveSourcePath) {
      const normalized = path.normalize(effectiveSourcePath).replace(/\\/g, '/').toLowerCase();
      if (normalized === 'src' || normalized === './src' || normalized.startsWith('src/') || normalized.endsWith('/src')) {
        effectiveSourcePath = undefined;
      }
    }

    let hasSource = Boolean(effectiveSourcePath || target.targetType === 'FILE_ZIP' || !isUrl);

    // If source path points to a ZIP file, unpack it automatically so individual files and lines are exposed
    if (effectiveSourcePath && fs.existsSync(effectiveSourcePath)) {
      try {
        const stat = fs.statSync(effectiveSourcePath);
        if (!stat.isDirectory()) {
          const lower = effectiveSourcePath.toLowerCase();
          const isZip = lower.endsWith('.zip') || (() => {
            try {
              const buf = Buffer.alloc(4);
              const fd = fs.openSync(effectiveSourcePath, 'r');
              fs.readSync(fd, buf, 0, 4, 0);
              fs.closeSync(fd);
              return buf.toString('hex') === '504b0304';
            } catch {
              return false;
            }
          })();

          if (isZip) {
            const zip = new AdmZip(effectiveSourcePath);
            const extractDir = path.join(process.cwd(), 'uploads', 'extracted', `scan-${scanId}-${Date.now()}`);
            fs.mkdirSync(extractDir, { recursive: true });
            zip.extractAllTo(extractDir, true);
            effectiveSourcePath = extractDir;
            hasSource = true;
          } else {
            hasSource = true;
          }
        } else {
          hasSource = true;
        }
      } catch (zipErr) {
        console.warn('Orchestrator unpack notice:', (zipErr as Error).message);
      }
    }

    // 2. Intelligent File Classification & Inventory Layer
    const isDev = (target.environment || '').toUpperCase() === 'DEVELOPMENT' || target.targetType === 'FILE_ZIP' || (!isUrl && hasSource);

    let classification: ProjectClassificationReport | null = null;
    let totalSourceFiles = 0;
    let totalSourceLines = 0;

    if (effectiveSourcePath && fs.existsSync(effectiveSourcePath)) {
      classification = await classifyProjectFiles(effectiveSourcePath);
      totalSourceFiles = classification.totalFilesIndexed;
      totalSourceLines = classification.totalLinesOfCode;
      console.log(`[ScanOrchestrator] Auditing ${totalSourceFiles} classified source files (${totalSourceLines.toLocaleString()} lines of code) in ${effectiveSourcePath}`);

      // Handle suspicious binaries or webshells discovered by the File Classifier
      if (classification.suspiciousFiles.length > 0) {
        for (const sus of classification.suspiciousFiles) {
          await normalizeAndSaveFindings(scanId, 'FILE_INSPECTOR', [{
            title: 'Potentially Malicious / Hidden Binary Artifact in Web Repository',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            category: 'MALICIOUS_ARTIFACT',
            sourceRuleId: 'file-inspector.hidden-executable',
            filePath: sus.path,
            evidenceSummary: sus.reason,
            remediation: 'Inspect and remove unexpected compiled binaries or camouflaged scripts from web assets.',
            cwe: 'CWE-506',
          }]);
        }
      }
    }

    // 3. Parse Scope, Boundaries & Optional Authenticated Session Credentials
    let parsedScope = { includedPaths: ['/*'], excludedPaths: [] as string[] };
    let sessionCookie: string | undefined;
    let authHeader: string | undefined;

    try {
      if (target.scope) {
        const s = typeof target.scope === 'string' ? JSON.parse(target.scope) : target.scope;
        if (s.includedPaths) parsedScope.includedPaths = Array.isArray(s.includedPaths) ? s.includedPaths : [s.includedPaths];
        if (s.excludedPaths) parsedScope.excludedPaths = Array.isArray(s.excludedPaths) ? s.excludedPaths : [s.excludedPaths];
        if (s.sessionCookie) sessionCookie = String(s.sessionCookie).trim();
        if (s.authHeader) authHeader = String(s.authHeader).trim();
      }
    } catch {}

    // 4. Proactive Source Extraction from Target URL (Source Maps, .git, and Backup Archives)
    if (isUrl && !isDev && !hasSource) {
      try {
        const extractRes = await extractSourcesFromTarget(target.url, scanId);
        if (extractRes.extractedDir && extractRes.extractedFilesCount > 0) {
          effectiveSourcePath = extractRes.extractedDir;
          hasSource = true;
          classification = await classifyProjectFiles(effectiveSourcePath);
          totalSourceFiles = classification.totalFilesIndexed;
          totalSourceLines = classification.totalLinesOfCode;
          console.log(`[ScanOrchestrator] Successfully extracted ${extractRes.extractedFilesCount} source files from target URL for SAST auditing.`);
        }
        if (extractRes.findings && extractRes.findings.length > 0) {
          await normalizeAndSaveFindings(scanId, 'RECON_DISCOVERY', extractRes.findings);
        }
      } catch (extractErr) {
        console.warn('[ScanOrchestrator] Source extraction notice:', (extractErr as Error).message);
      }
    }

    // 5. Plan Tasks
    let tasks = await prisma.scanTask.findMany({ where: { scanId } });
    if (tasks.length === 0 || (tasks.length > 0 && tasks.every(t => t.status === 'SKIPPED' || t.status === 'FAILED'))) {
      await prisma.scanTask.deleteMany({ where: { scanId } });
      await planScanExecution({
        scanId,
        targetType: target.targetType as any,
        environment: target.environment,
        hasUrl: isUrl && !isDev,
        hasSourceCode: hasSource,
      });
      tasks = await prisma.scanTask.findMany({ where: { scanId } });
    }

    // In Development Mode: Enforce strict bypassing of link/URL DAST tools
    if (isDev) {
      const dastTools = ['OWASP_ZAP', 'NUCLEI', 'WPSCAN', 'WHATWEB', 'TESTSSL'];
      await prisma.scanTask.updateMany({
        where: {
          scanId,
          toolName: { in: dastTools },
        },
        data: {
          status: 'SKIPPED',
          errorMessage: 'DAST tool skipped: Target is local source code (Development Mode). Live link inspection requires an active HTTP/HTTPS endpoint.',
        },
      });
    }

    const eligibleTasks = await prisma.scanTask.findMany({
      where: {
        scanId,
        status: { in: ['PENDING', 'QUEUED'] },
      },
    });

    const isProd = target.environment.toUpperCase() === 'PRODUCTION';
    const rateLimitRps = isProd ? 10 : 25;

    const toolInput: ToolInput = {
      scanId,
      targetId: target.id,
      targetUrl: target.url,
      targetType: target.targetType as any,
      environment: target.environment as any,
      sourcePath: effectiveSourcePath,
      scope: parsedScope,
      rateLimitRps,
      timeoutMs: 60_000,
      sessionCookie,
      authHeader,
    };

    // Helper to execute an individual security tool and record its execution & findings
    async function executeTool(toolName: string): Promise<boolean> {
      const task = eligibleTasks.find(t => t.toolName === toolName);
      if (!task) return false;
      const adapter = getToolAdapter(toolName);
      if (!adapter) {
        await prisma.scanTask.update({
          where: { id: task.id },
          data: { status: 'FAILED', errorMessage: `No adapter found for ${toolName}` },
        });
        return false;
      }

      await prisma.scanTask.update({
        where: { id: task.id },
        data: { status: 'RUNNING', startedAt: new Date() },
      });

      try {
        const result = await adapter.run(toolInput);
        const finishedAt = new Date();

        await prisma.toolExecution.create({
          data: {
            scanTaskId: task.id,
            toolName: adapter.name,
            toolVersion: adapter.version,
            exitCode: result.exitCode,
            resultPath: result.resultPath || null,
            errorSummary: result.errorSummary || null,
            durationMs: result.durationMs,
          },
        });

        if (result.findings && result.findings.length > 0) {
          await normalizeAndSaveFindings(scanId, adapter.name, result.findings);
        }

        if (result.success) {
          await prisma.scanTask.update({
            where: { id: task.id },
            data: { status: 'COMPLETED', finishedAt },
          });
          return true;
        } else {
          await prisma.scanTask.update({
            where: { id: task.id },
            data: { status: 'FAILED', errorMessage: result.errorSummary || 'Tool exited with error', finishedAt },
          });
          return false;
        }
      } catch (err) {
        await prisma.scanTask.update({
          where: { id: task.id },
          data: { status: 'FAILED', errorMessage: (err as Error).message, finishedAt: new Date() },
        });
        return false;
      }
    }

    // 6. Phased Execution
    if (isDev) {
      // PURE SAST (DEVELOPMENT SOURCE CODE SCAN):
      // Step A: Semgrep Static AST Pattern & Line-by-Line Scan
      await updateScanProgress(
        scanId,
        25,
        'Semgrep',
        `Semgrep: Indexing ${totalSourceFiles} source files (${totalSourceLines.toLocaleString()} lines) & inspecting AST syntax...`
      );
      await executeTool('SEMGREP');
      await sleep(1500);

      // Step B: CodeQL Inter-Procedural Taint Tracking
      await updateScanProgress(
        scanId,
        45,
        'CodeQL',
        `CodeQL: Tracing inter-procedural taint flows (Source -> Sanitizer -> Sink) across ${totalSourceFiles} files...`
      );
      await executeTool('CODEQL');
      await sleep(1500);

      // Step C: Gitleaks High-Entropy Secret Hunter
      await updateScanProgress(
        scanId,
        65,
        'Gitleaks',
        `Gitleaks: Scanning ${totalSourceLines.toLocaleString()} lines for exposed API keys, private tokens & credentials...`
      );
      await executeTool('GITLEAKS');
      await sleep(1500);

      // Step D: Checkov Infrastructure & Configuration Posture
      if (classification && classification.iacFiles.length === 0) {
        await prisma.scanTask.updateMany({
          where: { scanId, toolName: 'CHECKOV' },
          data: { status: 'SKIPPED', errorMessage: 'No IaC manifests (Dockerfile, Kubernetes, Terraform) detected in repository.' },
        });
      } else {
        await updateScanProgress(
          scanId,
          78,
          'Checkov',
          `Checkov: Auditing Dockerfiles, manifests, and container security postures...`
        );
        await executeTool('CHECKOV');
        await sleep(1200);
      }

      // Step E: Supply Chain & Dependencies (Trivy, OSV, npm audit)
      if (classification && classification.manifests.length === 0) {
        await prisma.scanTask.updateMany({
          where: { scanId, toolName: { in: ['TRIVY', 'OSV_SCANNER', 'NPM_AUDIT'] } },
          data: { status: 'SKIPPED', errorMessage: 'No dependency manifests found in repository.' },
        });
      } else {
        await updateScanProgress(
          scanId,
          88,
          'Trivy & OSV-Scanner',
          `Supply Chain: Verifying dependency manifests against Google OSV and National Vulnerability Databases...`
        );
        await Promise.all([
          executeTool('TRIVY'),
          executeTool('OSV_SCANNER'),
          executeTool('NPM_AUDIT'),
        ]);
        await sleep(1500);
      }
    } else {
      // DAST / HYBRID PIPELINE (STAGING / PRODUCTION URL SCAN):
      const phases = [
        ['OWASP_ZAP', 'NUCLEI'],
        ['WPSCAN', 'WHATWEB', 'TESTSSL'],
        ['SEMGREP', 'CODEQL', 'GITLEAKS'],
        ['TRIVY', 'OSV_SCANNER', 'CHECKOV', 'NPM_AUDIT'],
      ];

      let currentProg = 20;
      for (const group of phases) {
        const activeGroup = eligibleTasks.filter(t => group.includes(t.toolName));
        if (activeGroup.length > 0) {
          await updateScanProgress(
            scanId,
            currentProg,
            group.join(' & '),
            `Running ${group.join(', ')} inspection on ${target.url}...`
          );
          await Promise.all(activeGroup.map(t => executeTool(t.toolName)));
          currentProg += 18;
          await sleep(1500);
        }
      }
    }

    // 7. Findings Deduplication & Normalization
    await updateScanProgress(
      scanId,
      94,
      'Threat Intelligence',
      'Cross-tool correlation, deduplication & AI risk scoring...'
    );
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'ANALYZING' },
    });
    await deduplicateScanFindings(scanId);
    await sleep(1200);

    // 8. AI Intelligence on findings
    const findings = await prisma.finding.findMany({ where: { scanId } });
    for (const f of findings.slice(0, 10)) {
      await analyzeFindingWithAI(scanId, f.id).catch(() => null);
    }

    // 9. Generate Final Security Assessment Report
    await generateScanReport(scanId);

    // 10. Determine final Scan Status
    const allTasks = await prisma.scanTask.findMany({ where: { scanId } });
    const executedTasks = allTasks.filter(t => t.status !== 'SKIPPED');
    const hasFailures = executedTasks.some(t => t.status === 'FAILED' || t.status === 'TIMED_OUT');
    const hasSuccess = executedTasks.some(t => t.status === 'COMPLETED');

    let finalStatus = 'COMPLETED';
    if (!hasSuccess && hasFailures) {
      finalStatus = 'FAILED';
    } else if (hasFailures) {
      finalStatus = 'PARTIAL';
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: finalStatus,
        progress: 100,
        finishedAt: new Date(),
        endedAt: new Date(),
      },
    });

    activeScanState.delete(scanId);
    console.log(`[ScanOrchestrator] Scan #${scanId} completed with status: ${finalStatus}. Total findings: ${findings.length}`);
  } catch (error) {
    console.error(`[ScanOrchestrator] Fatal error during scan #${scanId}:`, error);
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'FAILED',
        progress: 100,
        endedAt: new Date(),
      },
    });
    activeScanState.delete(scanId);
  }
}
