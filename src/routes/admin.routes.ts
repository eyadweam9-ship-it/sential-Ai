import { Router, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '../config/db';
import { requireAdminAuth, AuthenticatedRequest } from '../middlewares/auth.middleware';

export const adminRouter = Router();

const JWT_SECRET = process.env.JWT_SECRET || 'vuln_scanner_admin_super_secret_jwt_key_2026';

/**
 * POST /api/admin/login
 * Admin Login Endpoint
 */
adminRouter.post('/login', async (req, res): Promise<void> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ success: false, error: 'Email and password are required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      res.status(401).json({ success: false, error: 'Invalid administrator credentials.' });
      return;
    }

    let isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch && typeof password === 'string' && password.trim() !== password) {
      isMatch = await bcrypt.compare(password.trim(), user.passwordHash);
    }
    if (!isMatch) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'ADMIN_LOGIN_FAILED',
          details: `Failed admin login attempt for ${normalizedEmail}.`,
        },
      });
      res.status(401).json({ success: false, error: 'Invalid administrator credentials.' });
      return;
    }

    if (!user.isActive) {
      res.status(403).json({ success: false, error: 'Account is deactivated. Contact system admin.' });
      return;
    }

    if (user.role.toUpperCase() !== 'ADMIN') {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'ADMIN_ACCESS_DENIED',
          details: `User ${user.email} attempted admin login with role: ${user.role}.`,
        },
      });
      res.status(403).json({ success: false, error: 'Access denied. You do not have administrator privileges.' });
      return;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'ADMIN_LOGIN_SUCCESS',
        details: `Administrator ${user.email} logged in successfully.`,
      },
    });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      success: true,
      message: 'Admin authenticated successfully.',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Admin Login Error:', error);
    res.status(500).json({ success: false, error: 'Internal server error during authentication.' });
  }
});

/**
 * GET /api/admin/me
 */
adminRouter.get('/me', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });

    if (!user) {
      res.status(404).json({ success: false, error: 'User not found in database.' });
      return;
    }

    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to retrieve profile.' });
  }
});

/**
 * GET /api/admin/stats
 */
adminRouter.get('/stats', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const [userCount, projectCount, targetCount, scanCount, vulnCount] = await Promise.all([
      prisma.user.count(),
      prisma.project.count(),
      prisma.target.count(),
      prisma.scan.count(),
      prisma.vulnerability.count(),
    ]);

    res.json({
      success: true,
      stats: {
        totalUsers: userCount,
        totalAdmin: await prisma.user.count({ where: { role: 'ADMIN' } }),
        totalProjects: projectCount,
        totalTargets: targetCount,
        totalScans: scanCount,
        totalVulnerabilities: vulnCount,
        database: 'SQLite (prisma/dev.db)',
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch admin stats.' });
  }
});

/**
 * GET /api/admin/users
 */
adminRouter.get('/users', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const users = await prisma.user.findMany({
      where: { role: 'ADMIN' },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
      },
      orderBy: { id: 'asc' },
    });

    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch admin list.' });
  }
});

/**
 * PATCH /api/admin/users/:id/status
 */
adminRouter.patch(
  '/users/:id/status',
  requireAdminAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userId = Number(req.params.id);
      const { isActive } = req.body;
      const currentAdminId = req.user?.id;

      if (!Number.isSafeInteger(userId) || userId <= 0) {
        res.status(400).json({ success: false, error: 'Invalid user ID.' });
        return;
      }

      if (typeof isActive !== 'boolean') {
        res.status(400).json({ success: false, error: 'isActive must be true or false.' });
        return;
      }

      if (userId === currentAdminId && !isActive) {
        res.status(400).json({ success: false, error: 'You cannot deactivate your own account.' });
        return;
      }

      const targetUser = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!targetUser) {
        res.status(404).json({ success: false, error: 'User not found.' });
        return;
      }

      await prisma.$transaction([
        prisma.user.update({
          where: { id: userId },
          data: { isActive, updatedAt: new Date() },
        }),
        prisma.auditLog.create({
          data: {
            userId: currentAdminId!,
            action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
            details: `Administrator changed account status for user ID ${userId} (${targetUser.name}) to ${isActive ? 'Active' : 'Inactive'}.`,
          },
        }),
      ]);

      res.json({ success: true, message: 'User status updated successfully.' });
    } catch (error) {
      console.error('Update user status error:', error);
      res.status(500).json({ success: false, error: 'Failed to update user status.' });
    }
  }
);

/**
 * POST /api/admin/toggle-status
 */
adminRouter.post('/toggle-status', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const rawId = req.body.userId ?? req.body.user_id;
    const userId = Number(rawId);
    const rawActive = req.body.isActive ?? req.body.is_active;
    const isActive = Boolean(rawActive);
    const currentAdminId = req.user?.id;

    if (!Number.isSafeInteger(userId) || userId <= 0) {
      res.status(400).json({ success: false, error: 'Invalid user ID.' });
      return;
    }

    if (userId === currentAdminId && !isActive) {
      res.status(400).json({ success: false, error: 'You cannot deactivate your own account.' });
      return;
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      res.status(404).json({ success: false, error: 'User not found.' });
      return;
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { isActive, updatedAt: new Date() },
      }),
      prisma.auditLog.create({
        data: {
          userId: currentAdminId!,
          action: isActive ? 'USER_ACTIVATED' : 'USER_DEACTIVATED',
          details: `Administrator changed account status for user ID ${userId} (${targetUser.name}) to ${isActive ? 'Active' : 'Inactive'}.`,
        },
      }),
    ]);

    res.json({ success: true, message: 'User status updated successfully.' });
  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).json({ success: false, error: 'Failed to update user status.' });
  }
});

/**
 * GET /api/admin/audit-logs
 */
adminRouter.get('/audit-logs', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const logs = await prisma.auditLog.findMany({
      take: 20,
      orderBy: { createdAt: 'desc' },
      include: {
        user: {
          select: { name: true, email: true, role: true },
        },
      },
    });

    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch audit logs.' });
  }
});

/**
 * POST /api/admin/create-admin
 */
adminRouter.post('/create-admin', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password) {
      res.status(400).json({ success: false, error: 'Name, email, and password are required.' });
      return;
    }

    if (password.length < 8) {
      res.status(400).json({ success: false, error: 'Password must be at least 8 characters.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (existingUser) {
      res.status(409).json({ success: false, error: 'This email is already registered.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newAdmin = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        role: 'ADMIN',
        updatedAt: new Date(),
      },
      select: { id: true, name: true, email: true, role: true },
    });

    res.status(201).json({ success: true, message: 'Admin created successfully.', user: newAdmin });
  } catch (error) {
    console.error('Create Admin Error:', error);
    res.status(500).json({ success: false, error: 'Failed to create admin account.' });
  }
});

/**
 * POST /api/admin/logout
 */
adminRouter.post('/logout', requireAdminAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    if (req.user?.id) {
      await prisma.auditLog.create({
        data: {
          userId: req.user.id,
          action: 'ADMIN_LOGOUT',
          details: `Admin ${req.user.name} logged out.`,
        },
      });
    }
    res.json({ success: true, message: 'Logged out successfully.' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Logout failed.' });
  }
});
