import { Router, Request, Response } from 'express';
import { ENV } from '../config/env';
import { prisma } from '../config/db';
import { knowledgeBaseService } from '../services/knowledge-base.service';

export const aiChatRouter = Router();

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * POST /api/ai/chat
 * Interactive Cyber Copilot Assistant for Sential AI
 * Fully bilingual (Arabic & English), context-aware of wizard steps, targets, and findings.
 */
aiChatRouter.post('/chat', async (req: Request, res: Response): Promise<void> => {
  try {
    const { message, context = {}, history = [] } = req.body;

    if (!message || typeof message !== 'string' || !message.trim()) {
      res.status(400).json({ success: false, error: 'A user message string is required.' });
      return;
    }

    const userMsg = message.trim();
    const isArabic = /[\u0600-\u06FF]/.test(userMsg);

    // Context enrichments
    let findingDetails = '';
    if (context.findingId) {
      try {
        const finding = await prisma.finding.findUnique({
          where: { id: Number(context.findingId) },
          include: { evidences: true },
        });
        if (finding) {
          findingDetails = `Current Selected Finding: "${finding.title}" (Severity: ${finding.severity}, CWE: ${finding.cwe || 'N/A'}, Category: ${finding.category || 'N/A'}). Evidence: ${finding.evidences[0]?.evidenceSummary || 'N/A'}`;
        }
      } catch {}
    }

    const systemPrompt = `You are "Sential AI Cyber Copilot", an elite DevSecOps cybersecurity engineer and automated application security assistant embedded directly inside the Sential AI vulnerability scanner.
Your role:
1. Help users configure assessments, understand scope boundaries (Included/Excluded patterns), and choose between Staging (aggressive deep testing) and Production (safe, non-destructive, rate-limited) environments.
2. Explain vulnerability findings clearly: root cause, real-world exploit impact, and exact remediation code with unified diffs.
3. Language adaptation: If the user writes in Arabic, respond fluently in polite, professional, and clear Arabic (with cybersecurity terms explained). If in English, respond in English.
4. Keep responses concise, clear, actionable, and formatted in markdown.

Active User Context:
- Wizard View: ${context.currentView || 'dashboard'}
- Target URL: ${context.targetUrl || 'Not specified'}
- Environment: ${context.environment || 'production'}
- Active Scan ID: ${context.scanId || 'None'}
${findingDetails}`;

    // 1. Try Gemini Cloud LLM if key is present
    if (ENV.GEMINI_API_KEY) {
      try {
        const geminiRes = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${ENV.GEMINI_API_KEY}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [
                { role: 'user', parts: [{ text: systemPrompt }] },
                ...history.slice(-6).map((h: ChatMessage) => ({
                  role: h.role === 'assistant' ? 'model' : 'user',
                  parts: [{ text: h.content }],
                })),
                { role: 'user', parts: [{ text: userMsg }] },
              ],
              generationConfig: {
                temperature: 0.3,
                maxOutputTokens: 800,
              },
            }),
            signal: AbortSignal.timeout(12000),
          }
        );

        if (geminiRes.ok) {
          const data = await geminiRes.json();
          const reply = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (reply) {
            res.json({ success: true, reply, source: 'gemini' });
            return;
          }
        }
      } catch (geminiErr) {
        console.warn('[AIChatRouter] Gemini query fallback:', (geminiErr as Error).message);
      }
    }

    // 2. Intelligent On-Device DevSecOps Copilot Engine (Zero-Cloud Fallback)
    const reply = generateOnDeviceCopilotReply(userMsg, isArabic, context);
    res.json({ success: true, reply, source: 'on-device-copilot' });
  } catch (error) {
    console.error('AI chat error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

function generateOnDeviceCopilotReply(msg: string, isArabic: boolean, ctx: any): string {
  const lower = msg.toLowerCase();

  // Topic 1: Staging vs Production
  if (lower.includes('staging') || lower.includes('production') || lower.includes('برودكشن') || lower.includes('ستيجينج') || lower.includes('الفرق')) {
    if (isArabic) {
      return `### الفرق بين بيئة Staging وبيئة Production في Sential AI:

1. **بيئة الـ Production (الموقع الحي):**
   * **فحص آمن وغير تدميري (Non-Destructive DAST):** نمنع أي أوامر تعديل أو مسح بيانات نهائياً (\`NO DELETE\`, \`NO UPDATE\`).
   * **معدل طلبات محكوم (Rate Limit):** 5 طلبات/ثانية لحماية استقرار السيرفر وتجنب حظر الـ WAF.
   * **استثناءات أمان تلقائية:** يتم حجب مسارات الدفع والمسح وتسجيل الخروج تلقائياً (\`/checkout\`, \`/pay\`, \`/delete\`, \`/logout\`).
   * **ترويسة تعريفية:** يتم إرسال هيدر \`X-Sential-Security-Scan\` لفريق الـ SOC.

2. **بيئة الـ Staging (بيئة الاختبار):**
   * **فحص هجومي عميق (Aggressive Active DAST):** تجربة Time-based Blind SQLi وتجربة ثغرات الـ RCE وحقن البيانات.
   * **سرعة عالية:** 25 إلى 50 طلب/ثانية لإنهاء الفحص سريعاً.
   * **فحص كامل الصلاحيات:** اختبار التلاعب بالـ IDOR وملء الفورمز التجريبية.`;
    } else {
      return `### Staging vs. Production Scanning in Sential AI:

1. **Production Environment (Live Site):**
   * **Strict Non-Destructive DAST:** All mutating database queries (\`DELETE\`, \`UPDATE\`, \`DROP\`) are strictly prohibited.
   * **Safe Rate Limiting:** 5 requests/sec to prevent DoS or triggering WAF bans.
   * **Automatic Safety Exclusions:** Critical billing and mutating paths (\`/checkout\`, \`/pay\`, \`/delete\`, \`/logout\`) are excluded automatically.
   * **Safe Audit Header:** Injects \`X-Sential-Security-Scan: Authorized-Audit-Engine\`.

2. **Staging Environment (Test Deployment):**
   * **Deep Active DAST:** Full parameter fuzzing, time-based delays (\`pg_sleep\`), and blind callback probing.
   * **High Concurrency:** 25-50 requests/sec for maximum speed.
   * **Stateful Form Testing:** Tests full user registration and permissions without fear of data corruption.`;
    }
  }

  // Topic 2: Scope (Included / Excluded)
  if (lower.includes('scope') || lower.includes('included') || lower.includes('excluded') || lower.includes('سكوب') || lower.includes('استثناء') || lower.includes('مسار')) {
    if (isArabic) {
      return `### كيفية ضبط نطاق الفحص (Scope) بدقة:

* **القاعدة الذهبية:** **الاستبعاد (Excluded) يتفوق دائماً على التضمين (Included)**!
* **Included Paths (المسارات المسموح بفحصها):**
  * استخدم \`/*\` لفحص الموقع بالكامل.
  * أو حدد مسارات معينة مثل: \`/api/*\`, \`/portal/*\`.
* **Excluded Paths (المسارات المحظورة من الفحص):**
  * المسارات التي يجب استبعادها دائماً:
    * \`/logout\` أو \`/signout\` (حتى لا يتم تسجيل خروج حساب الفاحص).
    * \`/api/delete*\` (لحماية السجلات).
    * \`/billing/cancel*\` أو بوابات الدفع.
* **منع التسرب:** الزاحف يقفل تلقائياً داخل الدومين المحدد ولا يتبع الروابط الخارجية أو الـ Subdomains غير المصرح بها.`;
    } else {
      return `### How Scope Rules Work in Sential AI:

* **Golden Rule:** **Exclusions ALWAYS take precedence over Inclusions!**
* **Included Paths:**
  * Use \`/*\` for whole-domain coverage.
  * Or specify prefixes: \`/api/v2/*\`, \`/app/*\`.
* **Excluded Paths:**
  * Always exclude:
    * \`/logout\` or \`/signout\` (prevents session invalidation during active crawls).
    * \`/api/delete*\` or \`/checkout*\` (prevents altering transactions).
    * Static media: \`*.pdf\`, \`*.mp4\`.
* **Boundary Enforcement:** The crawler prevents subdomain spilling and external origin crawling automatically.`;
    }
  }

  // Topic 3: Fix vulnerabilities (SQLi, XSS, SSRF, JWT)
  if (lower.includes('sql') || lower.includes('حقن') || lower.includes('xss') || lower.includes('jwt') || lower.includes('ssrf') || lower.includes('صلح') || lower.includes('fix')) {
    if (isArabic) {
      return `### دليل معالجة وإصلاح أشهر الثغرات:

1. **SQL Injection (CWE-89):**
   * **الحل:** استخدم الاستعلامات المعلمة (Parameterized Queries / Prepared Statements) أو ORM مثل Prisma / TypeORM / SQLAlchemy.
   * **مثال:** \`db.query('SELECT * FROM users WHERE id = $1', [userId])\`.

2. **Cross-Site Scripting XSS (CWE-79):**
   * **الحل:** ترميز كافة المدخلات (Contextual Output Encoding) وتفعيل Content-Security-Policy (CSP).

3. **JWT Security (CWE-347):**
   * **الحل:** رفض \`alg: "none"\` صراحة، واستخدام مفتاح سري عالي العشوائية (256-bit)، وعدم تخزين بيانات حساسة في الـ Payload.

4. **SSRF (CWE-918):**
   * **الحل:** استخدام Allowlist للعناوين الخارجية وحظر عناوين الـ Metadata (\`169.254.169.254\`) والـ Localhost على مستوى الشبكة.`;
    } else {
      return `### Vulnerability Remediation Guide:

1. **SQL Injection (CWE-89):**
   * Use strictly parameterized queries or modern ORMs. Never concatenate raw strings into database statements.
   * Example: \`db.query('SELECT * FROM users WHERE id = $1', [id])\`.

2. **SSRF & Cloud Metadata (CWE-918):**
   * Enforce destination domain allowlisting and block loopback CIDRs (\`127.0.0.0/8\`) and link-local cloud metadata (\`169.254.169.254\`). Enforce AWS IMDSv2.

3. **JWT Security (CWE-347):**
   * Reject \`alg: "none"\`, enforce RS256 or high-entropy HS256 secrets, and always set short-lived \`exp\` timestamps.`;
    }
  }

  // Default Guidance
  if (isArabic) {
    return `أهلاً بك! أنا **Sential AI Copilot**، مساعدك السيبراني الذكي 🛡️.

يمكنني مساعدتك في:
1. **شرح إعدادات الفحص:** اختيار بيئة Staging أو Production وتحديد مسارات الـ Scope بدقة.
2. **فهم وتصنيف الثغرات:** شرح أي ثغرة مكتشفة مع رقم الـ CWE وتأثيرها على البزنس.
3. **توفير كود الإصلاح:** كتابة كود ترقيع مباشر للثغرة باللغة البرمجية التي تستخدمها (Node.js, Python, PHP, Java, Go).

ما الذي ترغب في الاستفسار عنه بخصوص فحصك الحالي؟`;
  } else {
    return `Welcome! I am **Sential AI Copilot**, your embedded DevSecOps cybersecurity assistant 🛡️.

I can assist you with:
1. **Configuring your scan:** Choosing between Staging & Production, and setting up precise Included / Excluded paths.
2. **Understanding findings:** Explaining root causes, CVSS severity, and business risk.
3. **Remediation guidance:** Providing drop-in patch code and verification steps for any CWE.

How can I help you with your security assessment today?`;
  }
}
