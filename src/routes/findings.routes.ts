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
    const { scanId, toolName, severity, status } = req.query;

    const whereClause: any = {};
    if (scanId) whereClause.scanId = Number(scanId);
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

    res.status(200).json({
      success: true,
      count: findings.length,
      findings,
    });
  } catch (error) {
    console.error('List findings error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
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
