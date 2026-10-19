import dotenv from 'dotenv';
dotenv.config();
import bcrypt from 'bcryptjs';
import { prisma } from './config/db';

async function main() {
  console.log('🌱 Starting Database Seeding on SQLite (prisma/dev.db)...');

  // Clear existing demo data cleanly if desired
  await prisma.auditLog.deleteMany({});
  await prisma.vulnerability.deleteMany({});
  await prisma.report.deleteMany({});
  await prisma.scanConfiguration.deleteMany({});
  await prisma.scan.deleteMany({});
  await prisma.target.deleteMany({});
  await prisma.project.deleteMany({});
  await prisma.user.deleteMany({});

  // 1. Create Hashed Passwords
  const adminPasswordHash = await bcrypt.hash('graduationProject77@1', 10);
  const userPasswordHash = await bcrypt.hash('User@123456', 10);

  // 2. Create Admin Account (role = "ADMIN")
  const admin = await prisma.user.create({
    data: {
      name: 'Super Admin',
      email: 'admin@scanner.local',
      passwordHash: adminPasswordHash,
      role: 'ADMIN',
      isActive: true,
      lastLoginAt: new Date(),
    },
  });

  console.log(`✅ Admin user seeded: ${admin.email} (Role: ${admin.role})`);

  // 3. Create Normal User (role = "USER") - to test role access denial
  const regularUser = await prisma.user.create({
    data: {
      name: 'Normal Analyst',
      email: 'analyst@scanner.local',
      passwordHash: userPasswordHash,
      role: 'USER',
      isActive: true,
    },
  });

  console.log(`✅ Normal user seeded: ${regularUser.email} (Role: ${regularUser.role})`);

  // 4. Create Sample Project & Scans for testing
  const sampleProject = await prisma.project.create({
    data: {
      userId: admin.id,
      name: 'E-Commerce Security Audit',
      description: 'Comprehensive vulnerability assessment for core web application',
      status: 'ACTIVE',
    },
  });

  const sampleTarget = await prisma.target.create({
    data: {
      projectId: sampleProject.id,
      url: 'https://demo-ecommerce.example.com',
      status: 'ACTIVE',
    },
  });

  const sampleScan = await prisma.scan.create({
    data: {
      targetId: sampleTarget.id,
      status: 'COMPLETED',
      startedAt: new Date(Date.now() - 3600000),
      endedAt: new Date(),
    },
  });

  await prisma.vulnerability.createMany({
    data: [
      {
        scanId: sampleScan.id,
        title: 'SQL Injection in /api/products?id=',
        description: 'Unsanitized user input concatenated directly into SQL statement',
        severity: 'CRITICAL',
        status: 'OPEN',
        remediation: 'Use parameterized queries or ORM prepared statements.',
        filePath: '/src/controllers/product.controller.ts',
      },
      {
        scanId: sampleScan.id,
        title: 'Cross-Site Scripting (Reflected XSS)',
        description: 'Search parameter reflected without HTML encoding',
        severity: 'HIGH',
        status: 'OPEN',
        remediation: 'Implement contextual output encoding and CSP headers.',
        filePath: '/src/views/search.html',
      },
      {
        scanId: sampleScan.id,
        title: 'Missing Security Headers (Strict-Transport-Security)',
        description: 'The HSTS response header was not set by the server',
        severity: 'LOW',
        status: 'OPEN',
        remediation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
        filePath: 'nginx.conf',
      },
    ],
  });

  // 5. Seed initial Audit Log
  await prisma.auditLog.create({
    data: {
      userId: admin.id,
      action: 'SYSTEM_INITIALIZED',
      details: 'Database initialized and seeded with Administrator account and sample security data.',
    },
  });

  console.log('\n======================================================');
  console.log('🎉 Seeding completed successfully in SQLite (prisma/dev.db)!');
  console.log('Credentials stored in Database (hashed with bcrypt):');
  console.log('------------------------------------------------------');
  console.log('👑 ADMIN ACCOUNT:');
  console.log('   Email:    admin@scanner.local');
  console.log('   Password: graduationProject77@1');
  console.log('   Role:     ADMIN (Access Granted)');
  console.log('------------------------------------------------------');
  console.log('👤 REGULAR USER ACCOUNT (To test rejection):');
  console.log('   Email:    analyst@scanner.local');
  console.log('   Password: User@123456');
  console.log('   Role:     USER (Access Denied - role != admin)');
  console.log('======================================================\n');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
