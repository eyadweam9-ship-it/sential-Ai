import dotenv from 'dotenv';
dotenv.config();
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
});

import express, { Request, Response } from 'express';
import path from 'path';
import { prisma } from './config/db';
import { adminRouter } from './routes/admin.routes';
import { authRouter } from './routes/auth.routes';
import { scanRouter } from './routes/scan.routes';
import { authorizationRouter } from './routes/authorization.routes';
import { findingsRouter } from './routes/findings.routes';
import { reportsRouter } from './routes/reports.routes';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
const rootDir = process.cwd();
app.use(express.static(rootDir));
if (require('fs').existsSync(path.join(rootDir, 'public'))) {
  app.use(express.static(path.join(rootDir, 'public')));
}

app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(rootDir, 'index.html'));
});

app.get('/admin', (req: Request, res: Response) => {
  res.redirect('/admin/login');
});

app.get('/admin/login', (req: Request, res: Response) => {
  if (require('fs').existsSync(path.join(rootDir, 'admin', 'login.html'))) {
    res.sendFile(path.join(rootDir, 'admin', 'login.html'));
  } else {
    res.sendFile(path.join(rootDir, 'public', 'admin', 'login.html'));
  }
});

app.get('/admin/dashboard', (req: Request, res: Response) => {
  if (require('fs').existsSync(path.join(rootDir, 'admin', 'dashboard.html'))) {
    res.sendFile(path.join(rootDir, 'admin', 'dashboard.html'));
  } else {
    res.sendFile(path.join(rootDir, 'public', 'admin', 'dashboard.html'));
  }
});

app.get('/admin/add-admin', (req: Request, res: Response) => {
  if (require('fs').existsSync(path.join(rootDir, 'admin', 'add-admin.html'))) {
    res.sendFile(path.join(rootDir, 'admin', 'add-admin.html'));
  } else {
    res.sendFile(path.join(rootDir, 'public', 'admin', 'add-admin.html'));
  }
});

app.get(['/admin/Admin-management', '/admin/admin-management'], (req: Request, res: Response) => {
  if (require('fs').existsSync(path.join(rootDir, 'admin', 'Admin-management.html'))) {
    res.sendFile(path.join(rootDir, 'admin', 'Admin-management.html'));
  } else {
    res.sendFile(path.join(rootDir, 'public', 'admin', 'Admin-management.html'));
  }
});

app.get(['/login', '/login.html'], (req: Request, res: Response) => {
  res.sendFile(path.join(rootDir, 'login.html'));
});

app.get(['/signup', '/signup.html'], (req: Request, res: Response) => {
  res.sendFile(path.join(rootDir, 'signup.html'));
});

app.get(['/dashboard', '/dashboard.html'], (req: Request, res: Response) => {
  res.sendFile(path.join(rootDir, 'dashboard.html'));
});

app.use('/api/admin', adminRouter);
app.use('/api/auth', authRouter);
app.use('/api/authorization', authorizationRouter);
app.use('/api/scans', scanRouter);
app.use('/api/findings', findingsRouter);
app.use('/api/reports', reportsRouter);
app.use('/api', scanRouter);

app.get('/api/health', async (req: Request, res: Response) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({
      status: 'success',
      database: 'SQLite (prisma/dev.db)',
      message: 'Backend is connected to SQLite Database successfully!',
      timestamp: new Date(),
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      database: 'SQLite (prisma/dev.db)',
      message: 'Database connection failed',
      error: (error as Error).message,
    });
  }
});

app.post('/api/users', async (req: Request, res: Response) => {
  try {
    const { name, email, passwordHash, role } = req.body;
    const user = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash,
        role: role || 'USER',
        updatedAt: new Date(),
      },
    });
    res.status(201).json({
      message: 'User created successfully!',
      user,
    });
  } catch (error) {
    res.status(400).json({
      error: 'Failed to create user',
      details: (error as Error).message,
    });
  }
});

app.post('/api/scans/start', async (req: Request, res: Response) => {
  try {
    const { targetId } = req.body;
    const scan = await prisma.scan.create({
      data: {
        targetId: Number(targetId),
        status: 'RUNNING',
        startedAt: new Date(),
        updatedAt: new Date(),
      },
    });
    res.status(201).json({
      message: 'Scan started!',
      scan,
    });
  } catch (error) {
    res.status(400).json({
      error: 'Failed to start scan',
      details: (error as Error).message,
    });
  }
});

app.listen(port, () => {
  console.log('\n======================================================');
  console.log(`🚀 Vulnerability Scanner Server running on http://localhost:${port}`);
  console.log(`🔐 Admin Login Page: http://localhost:${port}/admin/login`);
  console.log(`📊 Admin Dashboard: http://localhost:${port}/admin/dashboard`);
  console.log(`👤 User Signup: http://localhost:${port}/signup.html`);
  console.log(`🔑 User Login: http://localhost:${port}/login.html`);
  console.log(`🩺 Database Health Check: http://localhost:${port}/api/health`);
  console.log('📦 Database Engine: SQLite (prisma/dev.db)');
  console.log('======================================================\n');
});
