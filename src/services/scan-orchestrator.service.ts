import { prisma } from '../config/db';
import { planScanExecution } from './scan-planner.service';
import { getToolAdapter } from '../tools';
import { normalizeAndSaveFindings } from './findings-normalizer.service';
import { deduplicateScanFindings } from './findings-deduplication.service';
import { analyzeFindingWithAI, generateScanExecutiveSummary } from './ai-analysis.service';
import { generateScanReport } from './report.service';
import { ToolInput } from '../tools/security-tool.interface';

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
    const isUrl = target.targetType === 'URL' || Boolean(target.url);
    const hasSource = Boolean(target.filePath || target.targetType === 'FILE_ZIP');

    // 2. Parse Scope & Boundaries
    let parsedScope = { includedPaths: ['/*'], excludedPaths: [] as string[] };
    try {
      if (target.scope) {
        const s = typeof target.scope === 'string' ? JSON.parse(target.scope) : target.scope;
        if (s.includedPaths) parsedScope.includedPaths = Array.isArray(s.includedPaths) ? s.includedPaths : [s.includedPaths];
        if (s.excludedPaths) parsedScope.excludedPaths = Array.isArray(s.excludedPaths) ? s.excludedPaths : [s.excludedPaths];
      }
    } catch {}

    // 3. Plan Tasks (ZAP, Semgrep, Gitleaks, Trivy, npm audit)
    // Check if tasks already exist in database or were previously skipped
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
    const totalEligible = eligibleTasks.length;

    // Rate limit configuration based on environment
    const isProd = target.environment.toUpperCase() === 'PRODUCTION';
    const rateLimitRps = isProd ? 10 : 25;

    const toolInput: ToolInput = {
      scanId,
      targetId: target.id,
      targetUrl: target.url,
      targetType: target.targetType as any,
      environment: target.environment as any,
      sourcePath: target.filePath || undefined,
      scope: parsedScope,
      rateLimitRps,
      timeoutMs: 60_000,
    };

    let completedCount = 0;
    let failedCount = 0;

    // 4. Execute Eligible Tools Concurrently
    await Promise.all(
      eligibleTasks.map(async (task) => {
        const adapter = getToolAdapter(task.toolName);
        if (!adapter) {
          await prisma.scanTask.update({
            where: { id: task.id },
            data: { status: 'FAILED', errorMessage: `No adapter found for ${task.toolName}` },
          });
          failedCount++;
          return;
        }

        // Mark task RUNNING
        await prisma.scanTask.update({
          where: { id: task.id },
          data: { status: 'RUNNING', startedAt: new Date() },
        });

        try {
          const result = await adapter.run(toolInput);
          const finishedAt = new Date();

          // Record Tool Execution
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

          // Save and normalize findings
          if (result.findings && result.findings.length > 0) {
            await normalizeAndSaveFindings(scanId, adapter.name, result.findings);
          }

          if (result.success) {
            await prisma.scanTask.update({
              where: { id: task.id },
              data: { status: 'COMPLETED', finishedAt },
            });
            completedCount++;
          } else {
            await prisma.scanTask.update({
              where: { id: task.id },
              data: { status: 'FAILED', errorMessage: result.errorSummary || 'Tool exited with error', finishedAt },
            });
            failedCount++;
          }
        } catch (toolErr) {
          await prisma.scanTask.update({
            where: { id: task.id },
            data: {
              status: 'FAILED',
              errorMessage: (toolErr as Error).message,
              finishedAt: new Date(),
            },
          });
          failedCount++;
        }

        // Increment scan progress incrementally
        const progressVal = Math.round(15 + ((completedCount + failedCount) / (totalEligible || 1)) * 60);
        await prisma.scan.update({
          where: { id: scanId },
          data: { progress: Math.min(75, progressVal) },
        }).catch(() => null);
      })
    );

    // 5. Findings Deduplication
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: 'ANALYZING', progress: 80 },
    });
    await deduplicateScanFindings(scanId);

    // 6. AI Intelligence on findings
    const findings = await prisma.finding.findMany({ where: { scanId } });
    for (const f of findings.slice(0, 10)) { // Deep AI analysis on up to top 10 prioritized findings
      await analyzeFindingWithAI(scanId, f.id).catch(() => null);
    }

    // 7. Generate Final Security Assessment Report
    await generateScanReport(scanId);

    // 8. Determine final Scan Status (COMPLETED vs PARTIAL vs FAILED)
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
