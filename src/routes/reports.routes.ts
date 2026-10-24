import { Router, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { prisma } from '../config/db';
import { generateScanReport } from '../services/report.service';
import { optionalAuth, AuthenticatedRequest } from '../middlewares/auth.middleware';

export const reportsRouter = Router();

// Apply optionalAuth to resolve JWT tokens and req.user for tenant-safe filtering
reportsRouter.use(optionalAuth);

/**
 * GET /api/reports/scan/:scanId
 * Get generated report data for a specific scan
 */
reportsRouter.get('/scan/:scanId', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const scanId = Number(req.params.scanId);
    const user = req.user;
    const isAdmin = user && user.role && user.role.toUpperCase() === 'ADMIN';

    let report = await prisma.report.findFirst({
      where: { scanId },
      include: {
        scan: {
          include: {
            target: { include: { project: true } },
            tasks: { include: { executions: true } },
            findings: { include: { evidences: true, aiAnalyses: true } },
          },
        },
      },
    });

    if (!report) {
      // Generate on demand if scan exists
      const scanExists = await prisma.scan.findUnique({
        where: { id: scanId },
        include: { target: { include: { project: true } } },
      });
      if (!scanExists) {
        res.status(404).json({ success: false, error: `Scan #${scanId} not found.` });
        return;
      }

      // Check tenant ownership
      if (user && !isAdmin && scanExists.target?.project?.userId && scanExists.target.project.userId !== user.id) {
        res.status(403).json({ success: false, error: 'Access denied: You do not have permission to access reports for this scan.' });
        return;
      }

      const generated = await generateScanReport(scanId);
      report = await prisma.report.findFirst({
        where: { id: generated.reportId },
        include: {
          scan: {
            include: {
              target: { include: { project: true } },
              tasks: { include: { executions: true } },
              findings: { include: { evidences: true, aiAnalyses: true } },
            },
          },
        },
      });
    }

    if (report && user && !isAdmin && report.scan?.target?.project?.userId && report.scan.target.project.userId !== user.id) {
      res.status(403).json({ success: false, error: 'Access denied: You do not have permission to access reports for this scan.' });
      return;
    }

    res.status(200).json({
      success: true,
      report,
    });
  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/reports/export/:scanId
 * Generate or re-generate and export printable HTML/JSON report
 */
reportsRouter.post('/export/:scanId', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const scanId = Number(req.params.scanId);
    const user = req.user;
    const isAdmin = user && user.role && user.role.toUpperCase() === 'ADMIN';

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { target: { include: { project: true } } },
    });

    if (!scan) {
      res.status(404).json({ success: false, error: `Scan #${scanId} not found.` });
      return;
    }

    if (user && !isAdmin && scan.target?.project?.userId && scan.target.project.userId !== user.id) {
      res.status(403).json({ success: false, error: 'Access denied: You do not have permission to export reports for this scan.' });
      return;
    }

    const reportData = await generateScanReport(scanId);

    res.status(200).json({
      success: true,
      message: 'Report generated and exported successfully.',
      reportId: reportData.reportId,
      htmlReportUrl: reportData.htmlReportPath,
      jsonReportUrl: reportData.jsonReportPath,
      summary: reportData.executiveSummary,
    });
  } catch (error) {
    console.error('Export report error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/reports/download/:id
 * Direct file download for HTML or JSON report
 */
reportsRouter.get('/download/:id', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const reportId = Number(req.params.id);
    const user = req.user;
    const isAdmin = user && user.role && user.role.toUpperCase() === 'ADMIN';

    const report = await prisma.report.findUnique({
      where: { id: reportId },
      include: { scan: { include: { target: { include: { project: true } } } } },
    });

    if (!report || !report.storagePath || !fs.existsSync(report.storagePath)) {
      res.status(404).json({ success: false, error: 'Report file not found on disk.' });
      return;
    }

    if (user && !isAdmin && report.scan?.target?.project?.userId && report.scan.target.project.userId !== user.id) {
      res.status(403).json({ success: false, error: 'Access denied: You do not have permission to download this report.' });
      return;
    }

    res.download(report.storagePath);
  } catch (error) {
    console.error('Download report error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});
