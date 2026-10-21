import { Router, Request, Response } from 'express';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import {
  createDnsChallenge,
  verifyDnsChallenge,
  createFileChallenge,
  verifyFileChallenge,
  submitWrittenAuthorization,
  reviewAuthorizationRequest,
  getAdminAuthorizationRequests,
  checkAuthorizationGate,
  generatePrintableAuthorizationTemplateHtml,
  extractHostname,
} from '../services/authorization.service';
import { prisma } from '../config/db';

export const authorizationRouter = Router();

// Ensure upload directory exists
const uploadDir = path.join(process.cwd(), 'uploads', 'authorizations');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage for signed letters (PDF, PNG, JPG, DOCX)
const letterStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `letter-${unique}-${sanitized}`);
  },
});

const letterUpload = multer({
  storage: letterStorage,
  limits: { fileSize: 25 * 1024 * 1024 }, // 25MB max
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.pdf', '.png', '.jpg', '.jpeg', '.docx', '.doc'];
    if (allowed.includes(ext) || file.mimetype.includes('pdf') || file.mimetype.includes('image')) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${ext} is not allowed. Please upload a signed PDF, PNG, or JPG.`));
    }
  },
});

/**
 * Helper to resolve targetId from targetUrl or ID
 */
async function resolveTargetId(targetId?: any, targetUrl?: string): Promise<number | null> {
  if (targetId && !isNaN(Number(targetId))) {
    return Number(targetId);
  }
  if (targetUrl) {
    const host = extractHostname(targetUrl);
    const target = await prisma.target.findFirst({
      where: { url: { contains: host } },
      orderBy: { id: 'desc' },
    });
    if (target) return target.id;
  }
  return null;
}

// ==========================================
// 1. DNS Verification Endpoints
// ==========================================

/**
 * POST /api/authorization/dns/challenge
 * Generate a unique DNS challenge token & expected TXT record
 */
authorizationRouter.post('/dns/challenge', async (req: Request, res: Response): Promise<void> => {
  try {
    const { targetUrl, userId } = req.body;
    if (!targetUrl || typeof targetUrl !== 'string') {
      res.status(400).json({ success: false, error: 'Target URL is required.' });
      return;
    }

    const challenge = await createDnsChallenge(targetUrl.trim(), userId ? Number(userId) : undefined);
    res.status(200).json(challenge);
  } catch (error) {
    console.error('DNS challenge creation error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/authorization/dns/verify
 * Query DNS TXT record and verify challenge token
 */
authorizationRouter.post('/dns/verify', async (req: Request, res: Response): Promise<void> => {
  try {
    const { targetId, targetUrl, customToken } = req.body;
    const resolvedId = await resolveTargetId(targetId, targetUrl);

    if (!resolvedId) {
      res.status(400).json({
        success: false,
        verified: false,
        error: 'Target ID or valid target URL is required to verify DNS.',
      });
      return;
    }

    const result = await verifyDnsChallenge(resolvedId, customToken);
    res.status(200).json(result);
  } catch (error) {
    console.error('DNS verify error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

// ==========================================
// 2. Upload Verification File Endpoints
// ==========================================

/**
 * POST /api/authorization/file/challenge
 * Generate a unique verification file and challenge token
 */
authorizationRouter.post('/file/challenge', async (req: Request, res: Response): Promise<void> => {
  try {
    const { targetUrl, userId } = req.body;
    if (!targetUrl || typeof targetUrl !== 'string') {
      res.status(400).json({ success: false, error: 'Target URL is required.' });
      return;
    }

    const challenge = await createFileChallenge(targetUrl.trim(), userId ? Number(userId) : undefined);
    res.status(200).json(challenge);
  } catch (error) {
    console.error('File challenge creation error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/authorization/file/download/:id
 * Direct download of the verification challenge file
 */
authorizationRouter.get('/file/download/:id', async (req: Request, res: Response): Promise<void> => {
  try {
    const verificationId = Number(req.params.id);
    const verification = await prisma.authorizationVerification.findUnique({
      where: { id: verificationId },
    });

    if (!verification || !verification.fileName || !verification.fileContent) {
      res.status(404).send('Verification file not found or expired.');
      return;
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${verification.fileName}"`);
    res.send(verification.fileContent);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).send('Failed to download verification file.');
  }
});

/**
 * POST /api/authorization/file/verify
 * Probe target server with SSRF protections and verify file content
 */
authorizationRouter.post('/file/verify', async (req: Request, res: Response): Promise<void> => {
  try {
    const { targetId, targetUrl } = req.body;
    const resolvedId = await resolveTargetId(targetId, targetUrl);

    if (!resolvedId) {
      res.status(400).json({
        success: false,
        verified: false,
        error: 'Target ID or valid target URL is required to verify file.',
      });
      return;
    }

    const result = await verifyFileChallenge(resolvedId);
    res.status(200).json(result);
  } catch (error) {
    console.error('File probe verify error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

// ==========================================
// 3. Written Authorization Endpoints
// ==========================================

/**
 * GET /api/authorization/template
 * Generate printable 2-page HTML template matching user's exact specification
 */
authorizationRouter.get('/template', (req: Request, res: Response): void => {
  const targetUrl = (req.query.targetUrl as string) || 'https://example.com';
  const operatorName = (req.query.operatorName as string) || 'Security Assessor';
  const orgName = (req.query.orgName as string) || 'Authorized Organization';

  const html = generatePrintableAuthorizationTemplateHtml(targetUrl, operatorName, orgName);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

/**
 * POST /api/authorization/letter/submit
 * Upload signed authorization letter document & metadata for admin review
 */
authorizationRouter.post(
  '/letter/submit',
  letterUpload.single('letterFile'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { targetId, targetUrl, ownerName, ownerTitle, scopeJson, userId } = req.body;

      if (!req.file) {
        res.status(400).json({
          success: false,
          error: 'A signed authorization document file (PDF, PNG, JPG) is required.',
        });
        return;
      }

      if (!targetUrl && !targetId) {
        res.status(400).json({
          success: false,
          error: 'Target URL is required.',
        });
        return;
      }

      const relativeUrl = `/uploads/authorizations/${req.file.filename}`;
      const resolvedId = (await resolveTargetId(targetId, targetUrl)) || 0;

      const result = await submitWrittenAuthorization({
        targetId: resolvedId,
        targetUrl: targetUrl || '',
        userId: userId ? Number(userId) : undefined,
        ownerName: (ownerName && ownerName.trim()) || 'Authorized Property Owner',
        ownerTitle: (ownerTitle && ownerTitle.trim()) || 'Authorized Signatory',
        letterFileUrl: relativeUrl,
        scopeJson: typeof scopeJson === 'string' ? scopeJson : JSON.stringify(scopeJson || {}),
      });

      res.status(200).json(result);
    } catch (error) {
      console.error('Submit written authorization error:', error);
      res.status(500).json({ success: false, error: (error as Error).message });
    }
  }
);

/**
 * GET /api/authorization/status/:targetId
 * Retrieve authorization status for a specific target
 */
authorizationRouter.get('/status/:targetId', async (req: Request, res: Response): Promise<void> => {
  try {
    const targetId = Number(req.params.targetId);
    const target = await prisma.target.findUnique({
      where: { id: targetId },
      include: {
        authorizations: {
          orderBy: { id: 'desc' },
          take: 5,
        },
      },
    });

    if (!target) {
      res.status(404).json({ success: false, error: 'Target not found.' });
      return;
    }

    res.status(200).json({
      success: true,
      targetId: target.id,
      url: target.url,
      environment: target.environment,
      isAuthorized: target.isAuthorized,
      authorizationMethod: target.authorizationMethod,
      authorizationStatus: target.authorizationStatus,
      authorizedAt: target.authorizedAt,
      authorizations: target.authorizations,
    });
  } catch (error) {
    console.error('Get authorization status error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/authorization/check-gate
 * Check if target is permitted through Authorization & Scope Gate
 */
authorizationRouter.post('/check-gate', async (req: Request, res: Response): Promise<void> => {
  try {
    const { targetUrl, environment = 'PRODUCTION' } = req.body;
    const normEnv = String(environment || '').toUpperCase();

    // Development environment (local source code SAST) always bypasses domain authorization gate
    if (normEnv === 'DEVELOPMENT' || !targetUrl) {
      res.status(200).json({
        success: true,
        allowed: true,
        status: 'APPROVED',
        reason: 'Development environment uses sandboxed static analysis on local uploaded files.',
      });
      return;
    }

    const check = await checkAuthorizationGate(targetUrl, environment);
    res.status(200).json({ success: true, ...check });
  } catch (error) {
    console.error('Check authorization gate error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

// ==========================================
// 4. Admin Management Endpoints
// ==========================================

/**
 * GET /api/admin/authorizations
 * List written authorization requests for Admin Review
 */
authorizationRouter.get('/admin/list', async (req: Request, res: Response): Promise<void> => {
  try {
    const status = req.query.status as string;
    const requests = await getAdminAuthorizationRequests(status);
    res.status(200).json({
      success: true,
      count: requests.length,
      requests,
    });
  } catch (error) {
    console.error('Admin list authorizations error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * PATCH /api/admin/authorizations/:id/review
 * Admin action: APPROVED, REJECTED, NEEDS_CHANGES
 */
authorizationRouter.patch('/admin/:id/review', async (req: Request, res: Response): Promise<void> => {
  try {
    const requestId = Number(req.params.id);
    const { decision, reason, adminName } = req.body;

    if (!['APPROVED', 'REJECTED', 'NEEDS_CHANGES'].includes(decision)) {
      res.status(400).json({
        success: false,
        error: 'Invalid decision. Must be APPROVED, REJECTED, or NEEDS_CHANGES.',
      });
      return;
    }

    const result = await reviewAuthorizationRequest({
      requestId,
      decision,
      reason,
      adminName: adminName || 'Security Administrator',
    });

    res.status(200).json(result);
  } catch (error) {
    console.error('Admin review authorization error:', error);
    res.status(400).json({ success: false, error: (error as Error).message });
  }
});
