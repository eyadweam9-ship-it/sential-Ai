# 1. Project Overview

The project is a web-based platform for scanning websites and identifying potential security vulnerabilities. Users will be able to add their websites, start security scans, view the results, and generate reports that explain the detected vulnerabilities and how to fix them.

The platform will also support rescanning websites to check whether previously detected vulnerabilities have been fixed.

---

# 2. Technologies Used

The following technologies were selected for the initial development of the project:

- **Node.js**: The runtime environment for the backend.
- **TypeScript**: Used to write more structured and maintainable code.
- **Express.js**: Used to build the backend APIs.
- **Prisma ORM**: Used to manage database operations and connect the backend to the database.
- **SQLite**: Used as the database during development because it is simple to set up and suitable for the current stage of the project (`prisma/dev.db`).
- *PostgreSQL can be considered for the production version as the project grows.*

---

# 3. Work Completed So Far

### A. Database Design
The initial database structure was created based on the project's requirements. It includes the following models:
- **User**: Stores user information, such as name, email, password, and account status.
- **Project**: Allows each user to organize their websites into separate projects.
- **Target**: Stores the website URLs that will be scanned.
- **Scan**: Stores scan information, including its status, such as Pending, Running, Completed, or Failed.
- **Vulnerability**: Stores information about detected vulnerabilities, including their names, descriptions, severity levels, remediation steps, and status.
- **Report**: Stores reports associated with scan results.
- **ScanConfiguration**: Stores the configuration options for each target.
- **AuditLog**: Records important actions performed within the platform.

These models provide the initial structure needed to connect users, projects, targets, scans, and their results.

### B. Backend API Setup
The initial backend server was set up using Node.js, TypeScript, and Express.js. A few API endpoints were added to test the basic functionality:
- `GET /api/health` — Checks whether the server is running and verifies database connectivity.
- `POST /api/users` — Provides an initial endpoint for creating users.
- `POST /api/scans/start` — Provides an initial endpoint for starting a scan and updating its status.

### C. Development Environment
The basic development environment was configured, including:
- Adjusting `tsconfig.json` to work with the backend setup.
- Configuring the `.env` file for environment variables and the database connection (`DATABASE_URL="file:./dev.db"`).
- Setting up Prisma to work with the database schema.

---

# 4. How the Frontend and Backend Work Together
The project follows a client-server architecture:
- **Backend responsibilities:** Handle API requests and business logic, manage database operations, handle user authentication and permissions, start scans and store their results, provide scan results and reports to the frontend.
- **Frontend responsibilities:** Display the website interface and dashboard, allow users to manage their projects and website targets, send requests to the backend APIs, display scan progress, detected vulnerabilities, and reports.

---

# 5. Admin Authentication System

An end-to-end Admin Authentication and Security Management module has been implemented:
- **Database Engine**: Built on **SQLite (`prisma/dev.db`)** using Prisma ORM (zero external database configuration required).
- **Security & Password Hashing**: Passwords are never hardcoded. All credentials are encrypted using **bcrypt** (salt rounds = 10) and queried dynamically from the `User` table in `prisma/dev.db`.
- **Strict Role Verification**: Enforces `role === 'ADMIN'` at both the login endpoint and on all protected API routes using JWT middleware (`requireAdminAuth`). Non-admin users are rejected with `403 Forbidden`.
- **Audit Logging**: Every successful admin login and unauthorized attempt is logged in real-time to the SQLite `AuditLog` table.
- **Frontend Portal (Sential AI Design)**:
  - **Admin Login UI** (`http://localhost:3000/admin/login`): Pixel-perfect implementation of the Sential AI Figma design with input validation, password toggle, status alerts, and responsive layout.
  - **Admin Dashboard** (`http://localhost:3000/admin/dashboard`): Protected dashboard route with JWT authentication check, displaying verified admin status.

---

# 6. Database & Application Setup Instructions (خطوات تشغيل الداتا بيز والمشروع)

### الخطوة 1: تثبيت الحزم (Install Dependencies)
```bash
npm install
```

### الخطوة 2: إنشاء وتهيئة قاعدة البيانات في SQLite (Push Schema)
يقوم هذا الأمر بإنشاء ملف قاعدة البيانات `prisma/dev.db` وتأسيس كافة الجداول المحددة في `prisma/schema.prisma` تلقائياً بدون أي سيرفر خارجي:
```bash
npx prisma db push
```

### الخطوة 3: زرع البيانات التجريبية وحسابات الدخول (Seed Database)
يقوم بزراعة حساب الأدمن، المستخدم العادي، والمشاريع والثغرات التجريبية وسجلات الفحص:
```bash
npm run seed
```

### الخطوة 4: تشغيل السيرفر المحلي (Start Server)
```bash
npm run dev
```

### الخطوة 5: فتح المتصفح
- **تسجيل دخول الأدمن:** [http://localhost:3000/admin/login](http://localhost:3000/admin/login)
- **داشبورد الأدمن:** [http://localhost:3000/admin/dashboard](http://localhost:3000/admin/dashboard)
- **الموقع الرئيسي والـ Assessment Flow:** [http://localhost:3000/](http://localhost:3000/)
- **تسجيل الدخول العادي:** [http://localhost:3000/login.html](http://localhost:3000/login.html)
- **إنشاء حساب جديد:** [http://localhost:3000/signup.html](http://localhost:3000/signup.html)
- **فحص الاتصال بقاعدة البيانات:** [http://localhost:3000/api/health](http://localhost:3000/api/health)

---

# 7. Default Seeded Test Accounts (بيانات الحسابات الافتراضية)

- **Admin Account (حساب المدير):**
  - **Email:** `admin@scanner.local`
  - **Password:** `graduationProject77@1`
  - **Role:** `ADMIN` *(صلاحية كاملة للدخول)*

- **Regular User (حساب مستخدم عادي):**
  - **Email:** `analyst@scanner.local`
  - **Password:** `User@123456`
  - **Role:** `USER` *(مستخدم عادي - يتم رفض دخوله لصفحات الأدمن بـ 403)*
