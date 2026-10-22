import { Router, Request, Response } from 'express';
import { prisma } from '../config/db';
import { analyzeFindingWithAI } from '../services/ai-analysis.service';

export const findingsRouter = Router();

/**
 * GET /api/findings/list
 * Filter unified findings by severity, toolName, status, or scanId
 */
findingsRouter.get('/list', async (req: Request, res: Response): Promise<void> => {
  try {
    const rawScanId = req.query.scanId || req.query.scan_id;
    const { toolName, severity, status } = req.query;

    let targetScanId: number | null = rawScanId ? Number(rawScanId) : null;
    if (!targetScanId || isNaN(targetScanId)) {
      const latestScan = await prisma.scan.findFirst({ orderBy: { id: 'desc' } });
      targetScanId = latestScan ? latestScan.id : null;
    }

    if (!targetScanId) {
      res.status(200).json({
        success: true,
        count: 0,
        findings: [],
        summary: { security_score: 100, critical: 0, high: 0, medium: 0, low: 0, resolved: 0 },
      });
      return;
    }

    const whereClause: any = { scanId: targetScanId };
    if (toolName) whereClause.toolName = String(toolName).toUpperCase();
    if (severity) whereClause.severity = String(severity).toUpperCase();
    if (status) whereClause.status = String(status).toUpperCase();

    const findings = await prisma.finding.findMany({
      where: whereClause,
      include: {
        evidences: true,
        aiAnalyses: true,
      },
      orderBy: { id: 'desc' },
    });

    const criticalCount = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity.toUpperCase() === 'HIGH').length;
    const mediumCount = findings.filter((f) => f.severity.toUpperCase() === 'MEDIUM').length;
    const lowCount = findings.filter((f) => f.severity.toUpperCase() === 'LOW').length;
    const resolvedCount = findings.filter((f) => f.status.toUpperCase() === 'FIXED').length;

    let calcScore = 100 - (criticalCount * 25 + highCount * 15 + mediumCount * 8 + lowCount * 3);
    calcScore = Math.max(15, Math.min(100, calcScore));

    res.status(200).json({
      success: true,
      count: findings.length,
      findings,
      summary: {
        security_score: calcScore,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        resolved: resolvedCount,
      },
    });
  } catch (error) {
    console.error('List findings error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/findings/export-csv
 * Export CSV strictly isolated to the specified or latest scan
 */
findingsRouter.get('/export-csv', async (req: Request, res: Response): Promise<void> => {
  try {
    const rawScanId = req.query.scan_id || req.query.scanId;
    let targetScanId: number | null = rawScanId ? Number(rawScanId) : null;
    if (!targetScanId || isNaN(targetScanId)) {
      const latestScan = await prisma.scan.findFirst({ orderBy: { id: 'desc' } });
      targetScanId = latestScan ? latestScan.id : null;
    }

    let items: any[] = [];
    if (targetScanId) {
      const dbFindings = await prisma.finding.findMany({
        where: { scanId: targetScanId },
        include: { evidences: true },
        orderBy: { id: 'desc' },
      });
      if (dbFindings.length > 0) {
        items = dbFindings.map((f) => ({
          id: f.id,
          title: f.title,
          cwe_id: f.cwe || 'CWE-200',
          filePath: f.evidences[0]?.filePath || f.evidences[0]?.url || '/api/endpoint',
          severity: f.severity,
          status: 'Detected',
          createdAt: f.createdAt,
        }));
      } else {
        const dbVulns = await prisma.vulnerability.findMany({
          where: { scanId: targetScanId },
          orderBy: { id: 'desc' },
        });
        items = dbVulns.map((v) => ({
          id: v.id,
          title: v.title,
          cwe_id: 'CWE-200',
          filePath: v.filePath || '/api/endpoint',
          severity: v.severity,
          status: v.status || 'OPEN',
          createdAt: v.createdAt,
        }));
      }
    }

    let csv = 'ID,Finding Title,CWE Identifier,Endpoint / File,Severity Level,Status,Created At\n';
    items.forEach((item: any) => {
      const title = `"${(item.title || '').replace(/"/g, '""')}"`;
      const cwe = `"${(item.cwe_id || 'CWE-89').replace(/"/g, '""')}"`;
      const endpoint = `"${(item.filePath || item.endpoint || '').replace(/"/g, '""')}"`;
      const severity = item.severity || 'HIGH';
      const status = item.status || 'OPEN';
      const date = item.createdAt ? new Date(item.createdAt).toISOString() : new Date().toISOString();
      csv += `${item.id},${title},${cwe},${endpoint},${severity},${status},${date}\n`;
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="SentinelAI_Findings_${Date.now()}.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Export CSV error:', error);
    res.status(500).send('Failed to export CSV');
  }
});

/**
 * GET /api/findings/detail or GET /api/findings/:id
 * Retrieve single finding with attached evidence and AI threat intelligence
 */
findingsRouter.get('/detail', async (req: Request, res: Response): Promise<void> => {
  try {
    const findingId = Number(req.query.id || req.query.finding_id);
    if (!findingId || isNaN(findingId)) {
      res.status(400).json({ success: false, error: 'Valid finding ID required.' });
      return;
    }

    let finding: any = await prisma.finding.findUnique({
      where: { id: findingId },
      include: {
        evidences: true,
        aiAnalyses: true,
        scan: {
          include: { target: true },
        },
      },
    });

    if (!finding) {
      const dbVuln: any = await prisma.vulnerability.findUnique({
        where: { id: findingId },
        include: { scan: { include: { target: true } } },
      });
      if (dbVuln) {
        finding = {
          id: dbVuln.id,
          scanId: dbVuln.scanId,
          toolName: dbVuln.toolName || 'SAST',
          sourceRuleId: dbVuln.ruleId || 'CODE-RULE',
          title: dbVuln.title,
          description: dbVuln.description,
          severity: dbVuln.severity,
          confidence: 'HIGH',
          category: 'CODE_SECURITY',
          status: dbVuln.status,
          remediation: dbVuln.remediation || 'Remediation advised.',
          cwe: dbVuln.cwe_id || 'CWE-89',
          createdAt: dbVuln.createdAt,
          evidences: [{
            id: dbVuln.id,
            url: null,
            filePath: dbVuln.filePath,
            lineStart: dbVuln.lineStart,
            evidenceSummary: dbVuln.description,
            rawSnippet: dbVuln.snippet || null,
          }],
          aiAnalyses: [{
            summary: dbVuln.description,
            technicalDetails: dbVuln.description,
            impact: 'Application code security vulnerability.',
            evidenceExplanation: dbVuln.description,
            severityRationale: `Classified as ${dbVuln.severity}`,
            recommendedRemediation: dbVuln.remediation || 'Remediation advised.',
          }],
          scan: dbVuln.scan,
        };
      }
    }

    if (!finding) {
      res.status(404).json({ success: false, error: 'Finding not found.' });
      return;
    }

    res.status(200).json({
      success: true,
      finding,
    });
  } catch (error) {
    console.error('Get finding detail error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

findingsRouter.get('/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const idParam = req.params.id;
    const findingId = idParam === 'detail' ? Number(req.query.id) : Number(idParam);
    if (!findingId || isNaN(findingId)) {
      res.status(400).json({ success: false, error: 'Valid finding ID required.' });
      return;
    }

    let finding: any = await prisma.finding.findUnique({
      where: { id: findingId },
      include: {
        evidences: true,
        aiAnalyses: true,
        scan: {
          include: { target: true },
        },
      },
    });

    if (!finding) {
      const dbVuln: any = await prisma.vulnerability.findUnique({
        where: { id: findingId },
        include: { scan: { include: { target: true } } },
      });
      if (dbVuln) {
        finding = {
          id: dbVuln.id,
          scanId: dbVuln.scanId,
          toolName: dbVuln.toolName || 'SAST',
          sourceRuleId: dbVuln.ruleId || 'CODE-RULE',
          title: dbVuln.title,
          description: dbVuln.description,
          severity: dbVuln.severity,
          confidence: 'HIGH',
          category: 'CODE_SECURITY',
          status: dbVuln.status,
          remediation: dbVuln.remediation || 'Remediation advised.',
          cwe: dbVuln.cwe_id || 'CWE-89',
          createdAt: dbVuln.createdAt,
          evidences: [{
            id: dbVuln.id,
            url: null,
            filePath: dbVuln.filePath,
            lineStart: dbVuln.lineStart,
            evidenceSummary: dbVuln.description,
            rawSnippet: dbVuln.snippet || null,
          }],
          aiAnalyses: [{
            summary: dbVuln.description,
            technicalDetails: dbVuln.description,
            impact: 'Application code security vulnerability.',
            evidenceExplanation: dbVuln.description,
            severityRationale: `Classified as ${dbVuln.severity}`,
            recommendedRemediation: dbVuln.remediation || 'Remediation advised.',
          }],
          scan: dbVuln.scan,
        };
      }
    }

    if (!finding) {
      res.status(404).json({ success: false, error: 'Finding not found.' });
      return;
    }

    res.status(200).json({
      success: true,
      finding,
    });
  } catch (error) {
    console.error('Get finding error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/findings/:id/ai-analyze
 * Run or regenerate AI Threat Intelligence for a specific finding
 */
findingsRouter.post('/:id/ai-analyze', async (req: Request, res: Response): Promise<void> => {
  try {
    const findingId = Number(req.params.id);
    const finding = await prisma.finding.findUnique({ where: { id: findingId } });
    if (!finding) {
      res.status(404).json({ success: false, error: 'Finding not found.' });
      return;
    }

    const aiAnalysis = await analyzeFindingWithAI(finding.scanId, findingId);
    res.status(200).json({
      success: true,
      message: 'AI threat intelligence generated successfully.',
      analysis: aiAnalysis,
    });
  } catch (error) {
    console.error('AI analyze finding error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/findings/:id/status
 * Update status of finding (OPEN, FIXED, FALSE_POSITIVE, MUTED)
 */
findingsRouter.post('/:id/status', async (req: Request, res: Response): Promise<void> => {
  try {
    const findingId = Number(req.params.id);
    const { status } = req.body;

    if (!['OPEN', 'FIXED', 'FALSE_POSITIVE', 'MUTED'].includes(status)) {
      res.status(400).json({ success: false, error: 'Invalid status. Must be OPEN, FIXED, FALSE_POSITIVE, or MUTED.' });
      return;
    }

    const updated = await prisma.finding.update({
      where: { id: findingId },
      data: { status },
    });

    res.status(200).json({
      success: true,
      message: `Finding #${findingId} status updated to ${status}.`,
      finding: updated,
    });
  } catch (error) {
    console.error('Update finding status error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});
