import { Router, Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { prisma } from '../config/db';
import { generateScanReport } from '../services/report.service';

export const reportsRouter = Router();

/**
 * GET /api/reports/scan/:scanId
 * Get generated report data for a specific scan
 */
reportsRouter.get('/scan/:scanId', async (req: Request, res: Response): Promise<void> => {
  try {
    const scanId = Number(req.params.scanId);
    let report = await prisma.report.findFirst({
      where: { scanId },
      include: {
        scan: {
          include: {
            target: true,
            tasks: { include: { executions: true } },
            findings: { include: { evidences: true, aiAnalyses: true } },
          },
        },
      },
    });

    if (!report) {
      // Generate on demand if scan exists
      const scanExists = await prisma.scan.findUnique({ where: { id: scanId } });
      if (!scanExists) {
        res.status(404).json({ success: false, error: `Scan #${scanId} not found.` });
        return;
      }
      const generated = await generateScanReport(scanId);
      report = await prisma.report.findFirst({
        where: { id: generated.reportId },
        include: {
          scan: {
            include: {
              target: true,
              tasks: { include: { executions: true } },
              findings: { include: { evidences: true, aiAnalyses: true } },
            },
          },
        },
      });
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
reportsRouter.post('/export/:scanId', async (req: Request, res: Response): Promise<void> => {
  try {
    const scanId = Number(req.params.scanId);
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
reportsRouter.get('/download/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const reportId = Number(req.params.id);
    const report = await prisma.report.findUnique({ where: { id: reportId } });

    if (!report || !report.storagePath || !fs.existsSync(report.storagePath)) {
      res.status(404).json({ success: false, error: 'Report file not found on disk.' });
      return;
    }

    res.download(report.storagePath);
  } catch (error) {
    console.error('Download report error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});
