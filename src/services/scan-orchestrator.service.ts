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
import { countFilesAndLines } from '../utils/file-counter';

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
    let hasSource = Boolean(target.filePath || target.targetType === 'FILE_ZIP' || !isUrl);

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

    // Index files and calculate real lines of code
    let totalSourceFiles = 0;
    let totalSourceLines = 0;
    if (effectiveSourcePath && fs.existsSync(effectiveSourcePath)) {
      const stats = countFilesAndLines(effectiveSourcePath);
      totalSourceFiles = stats.files;
      totalSourceLines = stats.lines;
      console.log(`[ScanOrchestrator] Auditing ${totalSourceFiles} source files (${totalSourceLines.toLocaleString()} lines of code) in ${effectiveSourcePath}`);
    }

    // 2. Parse Scope, Boundaries & Optional Authenticated Session Credentials
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

    // 3. Proactive Source Extraction from Target URL (Source Maps, .git, and Backup Archives)
    if (isUrl && !hasSource) {
      try {
        const extractRes = await extractSourcesFromTarget(target.url, scanId);
        if (extractRes.extractedDir && extractRes.extractedFilesCount > 0) {
          effectiveSourcePath = extractRes.extractedDir;
          hasSource = true;
          const stats = countFilesAndLines(effectiveSourcePath);
          totalSourceFiles = stats.files;
          totalSourceLines = stats.lines;
          console.log(`[ScanOrchestrator] Successfully extracted ${extractRes.extractedFilesCount} source files from target URL for SAST auditing.`);
        }
        if (extractRes.findings && extractRes.findings.length > 0) {
          await normalizeAndSaveFindings(scanId, 'RECON_DISCOVERY', extractRes.findings);
        }
      } catch (extractErr) {
        console.warn('[ScanOrchestrator] Source extraction notice:', (extractErr as Error).message);
      }
    }

    // 4. Plan Tasks (ZAP, Nuclei, WPScan, WhatWeb, TestSSL, Semgrep, CodeQL, Gitleaks, Trivy, OSV, Checkov, npm audit)
    let tasks = await prisma.scanTask.findMany({ where: { scanId } });
    if (tasks.length === 0 || (tasks.length > 0 && tasks.every(t => t.status === 'SKIPPED' || t.status === 'FAILED'))) {
      await prisma.scanTask.deleteMany({ where: { scanId } });
      await planScanExecution({
        scanId,
        targetType: target.targetType as any,
        environment: target.environment,
        hasUrl: isUrl,
        hasSourceCode: hasSource,
      });
      tasks = await prisma.scanTask.findMany({ where: { scanId } });
    }

    const eligibleTasks = tasks.filter(t => t.status === 'PENDING' || t.status === 'QUEUED');

    // Rate limit configuration based on environment
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

    // 5. Realistic Phased Execution Tied to Actual Scanning
    if (!isUrl && hasSource) {
      // PURE SAST (DEVELOPMENT CODE SCAN):
      // Step A: Semgrep Static AST Pattern & Line-by-Line Scan
      await updateScanProgress(
        scanId,
        25,
        'Semgrep',
        `Semgrep: Indexing ${totalSourceFiles} source files (${totalSourceLines.toLocaleString()} lines) & inspecting AST syntax...`
      );
      await executeTool('SEMGREP');
      await sleep(2200);

      // Step B: CodeQL Inter-Procedural Taint Tracking
      await updateScanProgress(
        scanId,
        45,
        'CodeQL',
        `CodeQL: Tracing inter-procedural taint flows (Source -> Sanitizer -> Sink) across ${totalSourceFiles} files...`
      );
      await executeTool('CODEQL');
      await sleep(2400);

      // Step C: Gitleaks High-Entropy Secret Hunter
      await updateScanProgress(
        scanId,
        65,
        'Gitleaks',
        `Gitleaks: Scanning ${totalSourceLines.toLocaleString()} lines for exposed API keys, private tokens & credentials...`
      );
      await executeTool('GITLEAKS');
      await sleep(2000);

      // Step D: Checkov Infrastructure & Configuration Posture
      await updateScanProgress(
        scanId,
        78,
        'Checkov',
        `Checkov: Auditing Dockerfiles, manifests, and container security postures...`
      );
      await executeTool('CHECKOV');
      await sleep(1800);

      // Step E: Supply Chain & Dependencies (Trivy, OSV, npm audit)
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
      await sleep(2000);
    } else {
      // DAST / HYBRID PIPELINE:
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

    // 6. Findings Deduplication
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

    // 7. AI Intelligence on findings
    const findings = await prisma.finding.findMany({ where: { scanId } });
    for (const f of findings.slice(0, 10)) {
      await analyzeFindingWithAI(scanId, f.id).catch(() => null);
    }

    // 8. Generate Final Security Assessment Report
    await generateScanReport(scanId);

    // 9. Determine final Scan Status
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
        endedAt: new Date(),
        finishedAt: new Date(),
        summaryJson: JSON.stringify({
          activeTool: 'All Tools',
          activeMessage: `Assessment complete. ${findings.length} verified findings recorded across ${totalSourceFiles ? `${totalSourceFiles} source files` : 'all routes'}.`,
        }),
      },
    });

    console.log(`[ScanOrchestrator] Scan #${scanId} completed with status: ${finalStatus}. Total findings: ${findings.length}`);
  } catch (error) {
    console.error(`[ScanOrchestrator] Scan #${scanId} orchestration error:`, error);
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'FAILED',
        progress: 100,
        endedAt: new Date(),
      },
    }).catch(() => null);
  }
}
