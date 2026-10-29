import { Router, Request, Response } from 'express';
import { ENV } from '../config/env';
import { prisma } from '../config/db';
import { knowledgeBaseService, KnowledgeBaseEntry } from '../services/knowledge-base.service';

export const aiChatRouter = Router();

interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * POST /api/ai/chat
 * Sential AI Cyber Copilot - Highly Intelligent DevSecOps Assistant
 * Understands all questions in Egyptian/Standard Arabic and English.
 * Backed by Google Gemini LLM when available + Comprehensive On-Device Knowledge Base & DevSecOps Expert Engine.
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

    // 1. If Gemini API key is available, leverage Google Gemini LLM
    const geminiKey = ENV.GEMINI_API_KEY || process.env.GEMINI_API_KEY;
    if (geminiKey) {
      try {
        const systemPrompt = `You are "Sential AI Cyber Copilot", an elite cybersecurity and DevSecOps AI assistant embedded inside Sential AI (an autonomous web application security scanner).
Your capabilities:
1. Answer ANY user query regarding application security, DevSecOps, web development, testing, configuration, reports, or vulnerability fixes.
2. If the user writes in Arabic (including Egyptian Arabic slang or technical terms), respond fluently in polite, professional, and natural Arabic. If in English, respond in English.
3. Keep answers clear, accurate, actionable, and formatted in clean markdown (using bolding, lists, and code blocks).
4. Wizard Context: Step: ${context.currentStep || context.currentView || 'dashboard'}, Target: ${context.target || context.targetUrl || 'Local Codebase'}, Environment: ${context.environment || 'production'}, Status: ${context.status || 'idle'}, Findings: ${context.findingsCount || 0}.
${findingDetails}`;

        const geminiRes = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiKey}`,
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
                temperature: 0.35,
                maxOutputTokens: 1000,
              },
            }),
            signal: AbortSignal.timeout(10000),
          }
        );

        if (geminiRes.ok) {
          const data = await geminiRes.json();
          const reply = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (reply && reply.trim()) {
            res.json({ success: true, reply, source: 'gemini' });
            return;
          }
        }
      } catch (geminiErr) {
        console.warn('[AIChatRouter] Gemini query fallback:', (geminiErr as Error).message);
      }
    }

    // 2. High-Performance On-Device DevSecOps Expert Engine
    const reply = generateComprehensiveOnDeviceReply(userMsg, isArabic, context);
    res.json({ success: true, reply, source: 'on-device-copilot' });
  } catch (error) {
    console.error('AI chat error:', error);
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * Intelligent On-Device Natural Language Understanding & DevSecOps Knowledge Graph
 */
function generateComprehensiveOnDeviceReply(rawMsg: string, isArabic: boolean, ctx: any): string {
  // Normalize message: lowercase and remove diacritics / tatweel / unify hamzas
  const norm = rawMsg
    .toLowerCase()
    .replace(/[أإآ]/g, 'ا')
    .replace(/ة/g, 'ه')
    .replace(/ى/g, 'ي')
    .replace(/[\u064B-\u065F\u0640]/g, '')
    .trim();

  // Helper matching functions
  const has = (...terms: string[]) => terms.some(t => {
    const tNorm = t.toLowerCase().replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي');
    return norm.includes(tNorm);
  });

  // ==========================================
  // Category 1: Social, Greetings & Identity
  // ==========================================
  if (has('مين انت', 'انت مين', 'من انت', 'مين معايا', 'عرفني بنفسك', 'who are you', 'what are you', 'identity')) {
    if (isArabic) {
      return `أنا **Sential Cyber AI Copilot** 🛡️، مهندس الأمن السيبراني والـ DevSecOps المساعد المدمج داخل منصة **Sential AI**.

**أقدر أساعدك في كل حاجة في المنصة:**
1. **رفع الملفات وفحص الكود:** إرشادك لكيفية رفع ملفات الـ ZIP أو المجلدات وفحصها بالسورس كود (SAST).
2. **فحص المواقع والروابط:** كيفية إدخال الرابط، والفرق بين Staging و Production، وضبط الاستثناءات (Excluded Paths).
3. **التفويض وتأكيد النطاق:** فك قفل الفحص بإثبات الملكية أو إقرار ملكية الكود.
4. **شرح وإصلاح الثغرات:** شرح أي ثغرة (CWE) وإعطاؤك كود الترقيع الجاهز (Fix Patch).
5. **تصدير التقارير:** تحميل وطباعة تقرير تنفيذي للامتثال أو تقني للمطورين بصيغة PDF بالعربي أو الإنجليزي.

اسألني في أي وقت عن أي خطوة وسأجاوبك فوراً! 🚀`;
    } else {
      return `I am **Sential Cyber AI Copilot** 🛡️, your embedded DevSecOps cybersecurity engineer inside **Sential AI**.

**How I can assist you across the platform:**
1. **File & Code Uploads:** Guiding you to upload ZIP archives or full project folders for SAST code audits.
2. **Web & API Scans:** Setting up target URLs, scope inclusions/exclusions, and choosing between Staging & Production.
3. **Authorization & Domain Ownership:** Clearing DNS/file challenges or code ownership consent.
4. **Vulnerability Remediation:** Explaining CWE root causes and generating drop-in code patches.
5. **Report Exports:** Generating executive compliance or technical PDF dossiers in Arabic or English.

Ask me anything about your security workflow and I'll guide you step-by-step! 🚀`;
    }
  }

  if (has('ازيك', 'عامل ايه', 'صباح الخير', 'مساء الخير', 'اهلا', 'مرحبا', 'السلام عليكم', 'سلام عليكم', 'هاي', 'hello', 'hi', 'hey', 'good morning', 'good evening')) {
    if (isArabic) {
      return `أهلاً وسهلاً بك! 👋 أنا بخير وجاهز لمساعدتك في فحص وتأمين موقعك وكودك البرمجي.
تقدر تسألني عن أي حاجة: "ازاي أرفع ملفات؟"، "إيه الخطوات؟"، "الفرق بين Staging و Production؟"، أو "شرح أي ثغرة وطريقة حلها بالكود". كيف تحب أن نبدأ؟`;
    } else {
      return `Hello there! 👋 I am ready to assist you in testing and securing your application.
You can ask me anything: "How to upload code?", "What are the steps?", "Staging vs Production differences?", or "How to patch any CWE?". How may I help you today?`;
    }
  }

  if (has('شكرا', 'تسلم', 'تمام', 'مشكور', 'عاش', 'الله يخليك', 'thanks', 'thank you', 'great', 'awesome', 'perfect')) {
    if (isArabic) {
      return `على الرحب والسعة دائماً! 🌟 أنا هنا لمساعدتك في أي وقت لتأمين مشروعك. إذا احتجت أي مساعدة أو واجهتك أي ثغرة لا تتردد! 🛡️`;
    } else {
      return `You are very welcome! 🌟 I am always here to ensure your projects remain resilient and secure. Let me know whenever you need further assistance! 🛡️`;
    }
  }

  // ==========================================
  // Category 2: How to Upload Files & Source Code (ازاي يرفع الملفات والكود)
  // ==========================================
  if (has(
    'ارفع ملف', 'رفع ملف', 'ارفع كود', 'رفع كود', 'ارفع المشروع', 'رفع المشروع', 
    'ارفع فولدر', 'رفع فولدر', 'ارفع zip', 'رفع zip', 'ازاي ارفع', 'طريقه رفع', 
    'ازاي احط كود', 'upload file', 'upload code', 'how to upload', 'upload zip', 
    'attach file', 'attach zip', 'upload folder'
  )) {
    if (isArabic) {
      return `### طريقة وخطوات رفع ملفات الكود والمشروع (Source Code SAST):

1. **انتقل إلى الخطوة 2 (Target & Environment):**
   * اضغط على بطاقة **Development (SAST · Code Upload)** الموجودة في أقصى اليسار.
2. **طرق رفع الملفات:**
   * **خيار 1 (ملف مضغوط ZIP):** اضغط على زر **Attach ZIP** وحدد ملف مشروعك المضغوط بصيغة \`.zip\` أو \`.tar.gz\`.
   * **خيار 2 (مجلد كامل):** اضغط على زر **Folder** لاختيار فولدر المشروع بالكامل من جهازك دون الحاجة لضغطه!
   * **خيار 3 (أيقونة المشبك 📎):** اضغط على المشبك لاختيار ملفات برمجية فردية.
3. **الملفات المدعومة:**
   * يدعم كل اللغات: JavaScript, TypeScript, Python, PHP, Java, C/C++, Go, HTML, JSON, YAML, Dockerfiles, Terraform.
   * الحد الأقصى للملفات يصل إلى **1 جيجابايت (1GB)**.
4. **التأكيد:**
   * سيظهر اسم الملف وحجمه في شريط أزرق أنيق مع علامة **Ready**.
5. **المتابعة:**
   * اضغط على **Continue** للانتقال للخطوة 3.
   * *ملاحظة مهمة:* في فحص الكود المرفوع (Development)، **لا تحتاج لأي دومين أو DNS أو تحقق خارجي إطلاقاً**؛ مجرد تحديد خانة الإقرار بملكية الكود وسيبدأ الفحص فوراً!`;
    } else {
      return `### How to Upload Project Files & Source Code for SAST:

1. **Navigate to Step 2 (Target & Environment):**
   * Click the **Development (SAST · Code Upload)** card on the left.
2. **Uploading Options:**
   * **Option 1 (Compressed Archive):** Click **Attach ZIP** to upload your project archive (\`.zip\`, \`.tar.gz\`, \`.tgz\`).
   * **Option 2 (Full Directory):** Click **Folder** to upload the entire project directory directly from your filesystem without archiving!
   * **Option 3 (Clip Icon 📎):** Click the paperclip icon in the attachment bar.
3. **Supported Formats & Limits:**
   * Supports all major languages: JS, TS, Python, PHP, Java, C/C++, Go, HTML, JSON, IaC (Terraform, Dockerfiles).
   * File sizes supported up to **1 GB**.
4. **Proceeding:**
   * Once attached, a pill shows the filename, size, and **Ready** status.
   * Click **Continue** to Step 3. Local code audits require **zero DNS TXT records or domain verifications**—simply confirm code ownership consent and launch!`;
    }
  }

  // ==========================================
  // Category 3: What are the Steps / Workflow (إيه الخطوات / خطوات الفحص من البداية للنهاية)
  // ==========================================
  if (has(
    'ايه الخطوات', 'اي الخطوات', 'الخطوات ايه', 'ايه هي الخطوات', 'خطوات الفحص', 
    'خطوات الموقع', 'الخطوه الجايه', 'الخطوة الجاية', 'اعمل ايه', 'ايه اللي اعمله', 
    'المفروض اعمل ايه', 'ابدا ازاي', 'ابدأ ازاي', 'طريقه الفحص', 'ازاي استخدم', 
    'how does it work', 'what are the steps', 'what should i do', 'next step', 'workflow'
  )) {
    if (isArabic) {
      return `### دليل خطوات الفحص الكاملة في Sential AI (من الخطوة 1 إلى 7):

* **الخطوة 1: نوع الفحص (Assessment Type):**
  * **Scan Only:** فحص استكشافي شامل لكل الثغرات دون تعديل في الكود.
  * **Scan, Fix & Retest:** فحص شامل + توليد كود الترقيع تلقائياً بالذكاء الاصطناعي وإعادة الاختبار للتأكد من حل الثغرة.

* **الخطوة 2: الهدف والبيئة (Target & Environment):**
  * **Development:** لرفع وفحص ملفات الكود البرمجي محلياً (SAST).
  * **Staging:** لفحص موقع تجريبي نشط بأقصى عمق وسرعة (25-50 طلب/ثانية).
  * **Production:** لفحص موقع حي حقيقي آمن وغير تدميري (5 طلبات/ثانية لحماية السيرفر).

* **الخطوة 3: التفويض والنطاق (Authorization & Scope):**
  * تأكيد الإقرار القانوني وتأكيد النطاق.
  * تحديد المسارات المسموحة (**Included**) والمسارات المحمية من الزحف (**Excluded** مثل مسارات الدفع والـ \`/logout\`).
  * تزويد التوكن أو الكوكي إذا كان الفحص داخل حسابات مسجلة الدخول.

* **الخطوة 4: متابعة الفحص الحي (Live Telemetry & Code Stream):**
  * رادار الفحص وشاشات الأكواد الحية التي تقلب تلقائياً كل ثانيتين لمتابعة الفحص سطر بسطر.

* **الخطوة 5: لوحة الثغرات (Findings Dashboard):**
  * جدول الثغرات المكتشفة مصنفة حسب الخطورة (Critical, High, Medium, Low).

* **الخطوة 6: تفاصيل الثغرة (Finding Details):**
  * استعراض الـ PoC الفعلي، رقم الـ CWE، وسلسلة متجهات CVSS v3.1، وكود الترقيع الجاهز بصيغة Git Diff.

* **الخطوة 7: التقرير النهائي (Final Audit Report):**
  * تصدير تقرير تنفيذي للامتثال أو تقرير هندسي للمطورين بصيغة PDF قابلة للطباعة بالعربية أو الإنجليزية.`;
    } else {
      return `### Sential AI Complete Assessment Lifecycle (Steps 1 to 7):

* **Step 1: Assessment Type:** Choose **Scan Only** (pure auditing) or **Scan, Fix & Retest** (automated patch generation & delta retesting).
* **Step 2: Target & Environment:**
  * **Development:** Upload project ZIP/folder for SAST code audits.
  * **Staging:** Deep active testing on pre-production URLs (25-50 req/s).
  * **Production:** Safe, non-destructive audit (5 req/s) with safe headers and billing exclusions.
* **Step 3: Authorization & Scope:** Clear legal consent, confirm domain ownership, and set Included vs. Excluded boundaries.
* **Step 4: Live Telemetry:** Real-time multi-engine progress with live AST & code inspection streams.
* **Step 5: Findings Dashboard:** Comprehensive triage grid organized by severity (Critical, High, Medium, Low).
* **Step 6: Finding Details:** In-depth technical review, HTTP request/response PoCs, CVSS v3.1 vectors, and drop-in Git patches.
* **Step 7: Final Audit Report:** Printable Executive (compliance) or Technical (engineering) reports in English or Arabic.`;
    }
  }

  // ==========================================
  // Category 4: How to Scan a Website URL (ازاي افحص موقع ورابط)
  // ==========================================
  if (has('افحص موقع', 'افحص سايت', 'افحص لينك', 'افحص رابط', 'احط رابط', 'احط لينك', 'ازاي افحص', 'فحص موقع', 'فحص رابط', 'scan website', 'scan url')) {
    if (isArabic) {
      return `### كيفية فحص موقع إلكتروني أو تطبيق ويب (URL DAST):

1. **في الخطوة 2 (Target & Environment):**
   * اختر إما **Staging** (إذا كان موقع اختبار تجريبي) أو **Production** (إذا كان موقع حي للعملاء).
2. **إدخال الرابط:**
   * اكتب الدومين أو الرابط في حقل Application URL (مثال: \`https://app.yourdomain.com\`).
   * اضغط على زر **Verify** للتأكد من استجابة الدومين وسلامة شهادة SSL/TLS.
3. **الانتقال للخطوة 3 (Authorization & Scope):**
   * حدد خانة الإقرار القانوني بالتفويض.
   * اكتب اسم النطاق أو كلمة \`CONFIRM\` في حقل التأكيد.
   * أضف أي مسارات استبعاد تريد حمايتها (مثل \`/checkout\` أو \`/logout\`).
4. **بدء الفحص:**
   * اضغط **Continue** وسيبدأ الفاحص فوراً بالزحف (Crawling) واختبار كل واجهات الـ Web والـ APIs!`;
    } else {
      return `### How to Scan a Live Website or Web Application:

1. **Step 2 (Target & Environment):** Select **Staging** (for test sandbox) or **Production** (for live production).
2. **Enter Application URL:** Input your target URL (e.g. \`https://app.yourdomain.com\`) and click **Verify** to check DNS/TLS connectivity.
3. **Step 3 (Authorization & Scope):** Check the mandatory legal disclaimer, type the hostname (or \`CONFIRM\`) into the confirmation field, and add sensitive paths to Excluded Paths.
4. **Launch:** Click **Continue** to dispatch automated endpoint discovery, DOM taint inspection, and active vulnerability probing!`;
    }
  }

  // ==========================================
  // Category 5: Staging vs Production
  // ==========================================
  if (has('staging', 'production', 'ستيجينج', 'برودكشن', 'الفرق بين الاستيجنج والبرودكشن', 'الفرق بين البيئات', 'فرق البيئات')) {
    if (isArabic) {
      return `### الفرق التقني بين فحص Staging وفحص Production:

| وجه المقارنة | بيئة Production (الموقع الحي) | بيئة Staging (بيئة الاختبار) |
| :--- | :--- | :--- |
| **طبيعة الفحص** | **Strict Non-Destructive** (آمن وغير تدميري تماماً). | **Aggressive Active DAST** (هجومي عميق وشامل). |
| **الـ Payloads** | قراءة فقط ومنع أي أمر تعديل أو مسح (\`NO DROP\`, \`NO DELETE\`). | تجربة كافة الحمولات بما فيها Time-based SQLi وحقن الأوامر. |
| **معدل الطلبات** | **5 طلبات/ثانية** كحد أقصى لمنع الـ DoS وعدم إجهاد السيرفر. | **25 إلى 50 طلب/ثانية** لإنهاء الفحص بأقصى سرعة. |
| **الترويسة التعريفية** | يُرسل هيدر: \`X-Sential-Security-Scan\` لفريق الـ SOC. | ترافيك اختباري مفتوح. |
| **استثناءات الأمان** | حجب مسارات الشراء والدفع ومسح الحسابات تلقائياً. | فحص كافة المسارات والفورمز التجريبية بحرية. |`;
    } else {
      return `### Technical Comparison: Staging vs. Production Audits:

| Metric | Production Environment | Staging Environment |
| :--- | :--- | :--- |
| **Audit Posture** | **Strict Non-Destructive DAST** (Read-Only) | **Aggressive Active DAST** (Full Exploitation) |
| **Payload Behavior** | Zero mutating queries (\`NO DROP\`, \`NO DELETE\`) | Time-based SQLi (\`pg_sleep\`), RCE fuzzing, deep state mutations |
| **Rate Limiting** | **5 req/s** to protect SLA & prevent WAF lockouts | **25 - 50 req/s** for rapid turnaround |
| **Safe Header** | Injects \`X-Sential-Security-Scan\` for SOC teams | Standard testing headers |
| **Safety Exclusions** | Auto-excludes \`/checkout\`, \`/pay\`, \`/delete\`, \`/logout\` | Fuzzes all test forms and mutating endpoints |`;
    }
  }

  // ==========================================
  // Category 6: Scope (Included & Excluded)
  // ==========================================
  if (has('scope', 'included', 'excluded', 'استثناء', 'استبعاد', 'سكوب', 'نطاق', 'مسار', 'مسارات')) {
    if (isArabic) {
      return `### كيفية ضبط نطاق الفحص (Scope) وحماية المسارات الحساسة:

* **القاعدة الذهبية:** **الاستبعاد (Excluded Paths) يلغي ويتفوق دائماً على التضمين (Included Paths)!**
* **Included Paths (المسارات المستهدفة):**
  * اكتب \`/*\` لفحص التطبيق بالكامل.
  * أو حدد واجهات معينة مثل: \`/api/*\`, \`/dashboard/*\`.
* **Excluded Paths (المسارات المستبعدة والمحمية):**
  * **مسارات الجلسات:** \`/logout\`, \`/signout\` (حتى لا يتم إبطال توكن الفاحص أثناء الزحف).
  * **مسارات تدمير البيانات:** \`/api/delete*\`, \`/user/remove-account\`.
  * **مسارات الدفع والاشتراكات:** \`/checkout\`, \`/billing/cancel\`, \`/pay\`.
* **حماية النطاق (Zero Spilling):** المحرك يمنع تلقائياً الزحف خارج الدومين المفحوص ولا يتتبع الروابط الخارجية لحمايتك وحماية الغير.`;
    } else {
      return `### Scope Configuration & Boundary Enforcement:

* **Golden Rule:** **Exclusions ALWAYS take precedence over Inclusions!**
* **Included Paths:**
  * Use \`/*\` to cover the whole application.
  * Or specify sub-trees: \`/api/v1/*\`, \`/portal/*\`.
* **Excluded Paths (Safety Blacklist):**
  * **Session preservation:** \`/logout\`, \`/signout\` (prevents session eviction).
  * **Mutating transactions:** \`/api/delete*\`, \`/cart/empty\`, \`/checkout\`.
  * **Billing paths:** \`/billing/cancel\`, \`/pay\`.
* **Origin Integrity:** The crawler enforces strict same-origin constraints, preventing external links or unauthorized subdomains from being touched.`;
    }
  }

  // ==========================================
  // Category 7: Authorization & Verification Gates
  // ==========================================
  if (has('authorization', 'تفويض', 'اثبات ملكيه', 'اثبات الملكيه', 'dns', 'txt', 'ملف التحقق', 'file challenge', 'خطاب', 'تصريح', 'ليه محتاج اوزرايزيشن', 'gate', 'ownership')) {
    if (isArabic) {
      return `### بوابات التفويض وإثبات ملكية النطاق (Authorization Gates):

وفقاً لميثاق الشرف الأخلاقي (OWASP & CFAA)، يُمنع إجراء فحص أمني هجومي على أي دومين دون إثبات السيطرة عليه قانونياً. المنصة توفر 3 طرق:

1. **DNS TXT Record (الأسرع وفوري):**
   * إضافة سجل TXT في لوحة تحكم النطاق:
   * **Name:** \`_sentinel-challenge.yourdomain.com\`
   * **Value:** القيمة المعطاة في الخطوة 3 (تأكيد فوري تلقائي).
2. **File Challenge (عبر سيرفر الموقع):**
   * تنزيل ملف التحقق ورفعه على مسار: \`/.well-known/sentinel-verification-xxxx.txt\`.
3. **Written Authorization Letter (خطاب التفويض المكتوب):**
   * رفع تصريح كتابي موقع من إدارة الشركة، ويقوم الأدمن بمراجعته واعتماده من لوحة الأدمن.
4. **في بيئة التطوير (SAST):**
   * لا يتطلب أي DNS أو ملفات؛ يكفي تحديد خانة "إقرار ملكية الكود" فقط.`;
    } else {
      return `### Authorization & Target Ownership Verification:

Under ethical hacking regulations and CFAA standards, active scanning requires verified target ownership:

1. **DNS TXT Record (Instant Automation):** Add the challenge record \`_sentinel-challenge.yourdomain.com\` with the token value provided in Step 3.
2. **Well-Known File Challenge:** Download the verification file and place it under \`/.well-known/sentinel-verification-*.txt\`.
3. **Written Authorization Letter:** Upload a signed corporate audit permission letter, which is approved via the Admin Portal.
4. **Development Code Analysis (SAST):** Zero external DNS checks are required; simply check the local code ownership consent.`;
    }
  }

  // ==========================================
  // Category 8: Authenticated Scans (Cookies & Headers)
  // ==========================================
  if (has('cookie', 'session', 'header', 'bearer', 'توكن', 'تسجيل دخول', 'حساب', 'فحص ورا اللوج ان', 'authenticated', 'auth token')) {
    if (isArabic) {
      return `### كيفية فحص المسارات الداخلية المحمية بتسجيل الدخول:

في **الخطوة 3 (Step 3: Boundaries & Credentials)**، يمكنك تزويد الفاحص ببيانات الجلسة ليزحف داخل الداشبورد وصفحات الأعضاء:

1. **Session Cookie:**
   * افتح الموقع في المتصفح وسجل دخولك.
   * افتح الـ DevTools (F12) -> Application -> Cookies.
   * انسخ اسم وقيمة الكوكي، مثل: \`connect.sid=s%3A28a...; token=xyz...\`.
2. **Authorization Header (Bearer Token / JWT):**
   * إذا كان التطبيق يعتمد على الـ APIs أو Single Page Application (React/Vue):
   * أضف في حقل الهيدر: \`Bearer eyJhbGciOiJIUzI1NiIsIn...\`.
* الفاحص سيقوم بحقن هذه الترويسة في كل طلب لضمان الوصول لكافة الـ Endpoints المحمية.`;
    } else {
      return `### Performing Authenticated Scans Behind Login Gates:

In **Step 3 (Boundaries & Credentials)**, provide your authenticated session credentials:

1. **Session Cookie:**
   * Log into your app, open Browser DevTools -> Application -> Cookies.
   * Paste the session string, e.g.: \`connect.sid=s%3A9f8...; auth_session=123\`.
2. **Authorization Header (JWT / API Token):**
   * If testing Single Page Applications or REST/GraphQL APIs, provide: \`Bearer <jwt_token>\`.
* The orchestrator and crawler will inject this header into every crawled link, discovering authenticated portals and APIs.`;
    }
  }

  // ==========================================
  // Category 9: CVSS v3.1 Scoring & Calculation
  // ==========================================
  if (has('cvss', 'سكور', 'درجة الخطورة', 'حساب الخطورة', 'vector', 'معادلة الخطورة')) {
    if (isArabic) {
      return `### كيفية احتساب درجات خطورة CVSS v3.1 في المنصة:

نعتمد على المعيار العالمي الصادر عن منظمة **FIRST**:

* **مصفوفة المتجهات الأساسية (Base Metrics):**
  * **AV (Attack Vector):** هل الثغرة عبر الشبكة (Network)، أم محلية (Local)؟
  * **AC (Attack Complexity):** هل استغلالها سهل ومباشر (Low) أم معقد (High)؟
  * **PR (Privileges Required):** هل تتطلب صلاحيات أدمن (High) أم بدون صلاحيات (None)؟
  * **UI (User Interaction):** هل تتطلب تفاعل الضحية بالضغط على رابط (Required)؟
  * **S (Scope):** هل تتخطى حاجز الحماية إلى أنظمة أخرى (Changed)؟
  * **C / I / A (Confidentiality, Integrity, Availability):** مقدار الضرر في تسريب البيانات أو تعديلها أو إسقاط الخدمة.
* **تصنيف الدرجات:**
  * **Critical (حرج):** 9.0 - 10.0
  * **High (عالي):** 7.0 - 8.9
  * **Medium (متوسط):** 4.0 - 6.9
  * **Low (منخفض):** 0.1 - 3.9`;
    } else {
      return `### FIRST CVSS v3.1 Scoring Standard:

Our engine computes vulnerability severity using official FIRST CVSS v3.1 equations:

* **Vector Metrics:** \`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\`
  * **Attack Vector (AV):** Network, Adjacent, Local, Physical.
  * **Attack Complexity (AC):** Low vs High.
  * **Privileges Required (PR):** None, Low, High.
  * **User Interaction (UI):** None vs Required.
  * **Scope (S):** Unchanged vs Changed.
  * **Impact (C/I/A):** High, Low, None across Confidentiality, Integrity, and Availability.
* **Severity Tiers:**
  * **Critical:** 9.0 - 10.0
  * **High:** 7.0 - 8.9
  * **Medium:** 4.0 - 6.9
  * **Low:** 0.1 - 3.9`;
    }
  }

  // ==========================================
  // Category 10: Reports & PDF Export
  // ==========================================
  if (has('تقرير', 'pdf', 'export', 'report', 'طباعه', 'اطبع', 'تصدير', 'تحميل التقرير', 'ازاي اطبع')) {
    if (isArabic) {
      return `### نظام التقارير المزدوج (Dual-Mode Reports) في Sential AI:

يمكنك تصدير التقرير بالضغط على زر **Export Report** في لوحة الفحص أو التقرير النهائي:

1. **التقرير التنفيذي (Executive Report - 👔):**
   * مخصص للمدراء التنفيذيين ومسؤولي الامتثال وأصحاب البيزنس.
   * يحتوي على: معدل الأمان العام (Risk Score)، الأثر المالي والقانوني المحتمل، ومصفوفة الامتثال للشهادات الدولية (**OWASP Top 10 2026**, **PCI-DSS v4.0**, **ISO 27001**, **GDPR**).
   * متاح بـ **اللغة العربية (RTL) بخط Cairo الأنيق** أو بالإنجليزية.
2. **التقرير التقني المفصل (Technical Dossier - 💻):**
   * مخصص للمبرمجين ومهندسي الأمن والـ DevSecOps.
   * يحتوي على: حمولات الـ PoC الفعلية، الـ Request والـ Response، سلاسل الـ CVSS v3.1، ومسارات الأكواد المصابة وترقيعات Git Diff الجاهزة للتطبيق.
* التقارير مصممة وفق أبعاد A4 ومجهزة للطباعة المباشرة أو الحفظ كملف PDF بنقاوة عالية.`;
    } else {
      return `### Dual-Mode Report Generation in Sential AI:

Click **Export Report** on the Dashboard or Step 7 to open the export modal:

1. **Executive Report (👔 For Leadership & Compliance):**
   * Overall business risk score, financial/legal liability impact, and regulatory compliance matrices (**OWASP Top 10 2026, PCI-DSS v4.0, ISO 27001, GDPR**).
   * Available in English and Arabic RTL with typography optimized for PDF printing.
2. **Technical Dossier (💻 For Developers & Engineers):**
   * Exact HTTP PoC payloads, CVSS v3.1 vector strings, affected file line numbers, and drop-in git diff remediation patches.`;
    }
  }

  // ==========================================
  // Category 11: Admin Dashboard & Management
  // ==========================================
  if (has('ادمن', 'admin', 'لوحة الادمن', 'لوحة التحكم', 'dashboard admin', 'صلاحيات الادمن', 'صفحه الادمن')) {
    if (isArabic) {
      return `### تنظيم لوحة الأدمن (Admin Dashboard):

لوحة الأدمن متاحة على: \`/admin/dashboard.html\` ومقسمة إلى 4 تبويبات منظمة:

1. **Overview & Telemetry:** إحصائيات النظام العامة، عدد الفحوصات الجارية، وحالة المحركات وسجلات الأداء.
2. **Target Authorizations:** إدارة بوابات التفويض وإثبات الملكية؛ مراجعة سجلات الـ DNS وملفات التحقق واعتماد أو رفض خطابات التفويض المكتوبة.
3. **Security Audits & Tamper-Proof Logs:** جدول السجلات الرقابية والقانونية الذي يسجل عنوان الـ IP الحقيقي لكل مستخدم ووقت وتاريخ إطلاق الفحص لحمايتك قانونياً.
4. **Security Engines & Knowledge Base:** حالة محركات الفحص الـ 8 المدمجة واستعراض قاعدة معرفة الثغرات (970+ CWE).`;
    } else {
      return `### Sential AI Admin Dashboard Architecture:

Accessible via \`/admin/dashboard.html\` with 4 organized tab views:

1. **Overview & Telemetry:** System metrics, active scan workers, and platform telemetry.
2. **Target Authorizations:** Approve or reject DNS TXT validations, file challenges, and corporate authorization letters.
3. **Audit Logs:** Tamper-proof legal audit logs recording user IPs, targets, and launch timestamps.
4. **Security Engines & KB:** Health monitoring of all 8 audit engines and the 970+ CWE definitions.`;
    }
  }

  // ==========================================
  // Category 12: Retest & Delta Verification
  // ==========================================
  if (has('اعاده فحص', 'اعادة فحص', 'retest', 'rescan', 'تاكيد الاصلاح', 'تاكيد الترقيع', 'verify fix')) {
    if (isArabic) {
      return `### ميزة إعادة الاختبار والتحقق التلقائي (Retest & Delta Verification):

عند الضغط على زر **Verify & Retest** بجانب أي ثغرة أو فحص:
1. يقوم المحرك بإنشاء فحص جديد معزول لنفس الهدف.
2. يتم تشغيل نفس الـ Payloads التي اكتشفت الثغرة في المرة الأولى.
3. يقوم محرك **Delta Comparison Engine** بمقارنة النتيجة مع الفحص السابق (Baseline):
   * إذا لم تستجب الثغرة، يتم تعليمها تلقائياً كـ **RESOLVED (تم الإصلاح)**.
   * إذا ظلت موجودة، تُسجل كـ **REGRESSION / UNRESOLVED** مع إشعار بالسبب.`;
    } else {
      return `### Automated Retesting & Delta Verification:

Clicking **Verify & Retest** executes an automated verification workflow:
1. An isolated scan is dispatched against the target endpoint.
2. The exact trigger payload is replayed.
3. The **Delta Comparison Engine** compares against the historical baseline:
   * If remediated, the finding status transitions to **RESOLVED**.
   * If vulnerable, it is flagged as **UNRESOLVED** with regression details.`;
    }
  }

  // ==========================================
  // Category 13: Troubleshooting (واقف، بطيء، مقفول، مشكلة)
  // ==========================================
  if (has('مشكله', 'واقف', 'معلق', 'بطيء', 'مقفول', 'ليه مقفول', 'ليه مش شغال', 'ليه مش راضي', 'stuck', 'slow', 'locked', 'error', 'problem')) {
    if (isArabic) {
      return `### إرشادات حل المشاكل الشائعة (Troubleshooting):

1. **إذا كانت الخطوة مقفولة (Step Locked):**
   * الفحص يسير بنظام تسلسلي لحمايتك؛ يجب إنهاء الخطوة الحالية أولاً.
   * في **الخطوة 3**: يجب تحديد خانة الإقرار القانوني وكتابة اسم الدومين أو \`CONFIRM\` في حقل التأكيد لفك القفل.
   * بمجرد انتهاء الفحص ووصول العداد إلى 100%، **تنفتح جميع الخطوات التالية فوراً دفعة واحدة** (الداشبورد، التفاصيل، والتقرير).
2. **إذا كان الفحص يبدو بطيئاً:**
   * في بيئة **Production**: الفاحص مقيد بأمان بـ 5 طلبات/ثانية لحماية السيرفر من الحظر والـ DoS.
   * إذا أردت أقصى سرعة (25-50 طلب/ثانية)، اختر بيئة **Staging** أثناء إعداد الفحص.
3. **إذا واجهت خطأ في الاتصال بالهدف:**
   * تأكد أن الرابط يعمل ويبدأ بـ \`https://\` أو \`http://\`، وأن السيرفر متاح علناً للإنترنت.`;
    } else {
      return `### Troubleshooting Common Issues:

1. **Step is Locked:**
   * Sequential progression is enforced. In Step 3, you must check the legal consent checkbox and confirm the domain name.
   * As soon as the scan completes (100%), all subsequent views (Dashboard, Details, Reports) unlock simultaneously.
2. **Scan is Slow:**
   * Production mode is strictly throttled to 5 req/s to prevent denial-of-service and WAF bans. For maximum speed (25-50 req/s), choose **Staging** mode.
3. **Target Connectivity Errors:**
   * Ensure your URL has a valid protocol (\`https://\`) and is publicly reachable.`;
    }
  }

  // ==========================================
  // Category 14: How to Fix / Remediate Vulnerabilities (طريقة الإصلاح والترقيع)
  // ==========================================
  if (has('صلح', 'تصليح', 'عالج', 'معالجه', 'رقع', 'ترقيع', 'حل الثغره', 'حل الثغرات', 'ازاي اصلح', 'fix', 'patch', 'remediate')) {
    if (isArabic) {
      return `### كيفية إصلاح وترقيع الثغرات في كودك البرمجي:

1. **في لوحة الثغرات (Findings Dashboard):**
   * اضغط على أي ثغرة مكتشفة للانتقال لصفحة **Finding Details (الخطوة 6)**.
2. **استعراض الترقيع التلقائي (Automated Remediation):**
   * ستجد قسماً مخصصاً بعنوان **Drop-in Git Diff Remediation Patch**.
   * يعرض لك الكود المصاب بالأحمر والكود المؤمن بالأخضر، مع رقم السطر واسم الملف المصاب بدقة.
3. **تطبيق الإصلاح:**
   * اضغط على زر **Copy Patch** لنسخ الكود واستبداله في مشروعك.
4. **إعادة التحقق:**
   * اضغط على زر **Verify & Retest** وسيقوم الفاحص تلقائياً بإعادة اختبار نفس المكان والتأكد من إغلاق الثغرة تماماً!
* *ملاحظة:* يمكنك أن تكتب لي اسم أي ثغرة الآن وسأعطيك كود الإصلاح المباشر لها بلغة مشروعك!`;
    } else {
      return `### How to Remediate Detected Vulnerabilities:

1. **Navigate to Finding Details (Step 6):** Click any finding row in the Dashboard.
2. **Review the Automated Git Diff Patch:** Inspect the affected file path and exact line numbers with side-by-side vulnerable vs. secured code snippets.
3. **Apply the Patch:** Click **Copy Patch** and paste it into your codebase.
4. **Verify Remediation:** Click **Verify & Retest** to trigger an automated delta re-audit confirming the patch resolves the flaw.`;
    }
  }

  // ==========================================
  // Category 15: Specific Vulnerability Knowledge Base Lookup (970+ CWEs)
  // ==========================================
  const kbEntry = lookupKnowledgeBase(norm);
  if (kbEntry) {
    return formatKnowledgeBaseReply(kbEntry, isArabic);
  }

  // Handlers for common vulnerability topics if not caught by KB exact match
  if (has('sql', 'حقن قواعد', 'sqli')) {
    if (isArabic) {
      return `### ثغرة حقن قواعد البيانات SQL Injection (CWE-89):
* **السبب:** دمج مدخلات المستخدم مباشرة داخل جمل الاستعلام النصية دون معالجة أو تهيئة.
* **الأثر:** تسريب قاعدة البيانات بالكامل، تخطي شاشات تسجيل الدخول، أو تعديل البيانات.
* **كود الإصلاح الصحيح (Parameterized Query):**
\`\`\`javascript
// ❌ كود مصاب:
const q = "SELECT * FROM users WHERE id = " + req.query.id;

// ✅ كود مؤمن (Prepared Statement):
const q = "SELECT * FROM users WHERE id = $1";
await db.query(q, [req.query.id]);
\`\`\`
* **نصيحة:** استخدم ORM موثوق مثل Prisma أو TypeORM أو Sequelize.`;
    } else {
      return `### SQL Injection Remediation (CWE-89):
* **Root Cause:** Direct string concatenation of untrusted user input into raw SQL queries.
* **Drop-in Remediation:**
\`\`\`typescript
// ❌ Vulnerable:
const query = \`SELECT * FROM users WHERE email = '\${email}'\`;

// ✅ Secure (Parameterized):
const query = 'SELECT * FROM users WHERE email = ?';
await db.execute(query, [email]);
\`\`\`
Always leverage parameterized prepared statements or vetted ORMs (Prisma, TypeORM).`;
    }
  }

  if (has('xss', 'cross site', 'حقن سكريبت')) {
    if (isArabic) {
      return `### ثغرة حقن نصوص البرمجة عبر المواقع XSS (CWE-79):
* **السبب:** عرض مدخلات غير مفحوصة مباشرة في صفحة الـ HTML مما يمكن المهاجم من تشغيل جافاسكريبت خبيث في متصفح الضحية.
* **الأثر:** سرقة الـ Cookies والتوكنات، وتزوير طلبات المستخدم.
* **طريقة الإصلاح البرمجي:**
\`\`\`javascript
// 1. استخدام مكتبة DOMPurify للتعقيم:
import DOMPurify from 'dompurify';
const cleanHtml = DOMPurify.sanitize(userInput);

// 2. تفعيل ترويسة Content-Security-Policy (CSP):
// Content-Security-Policy: default-src 'self'; script-src 'self';
\`\`\``;
    } else {
      return `### Cross-Site Scripting (XSS) Remediation (CWE-79):
* **Root Cause:** Untrusted input rendered directly into the DOM/HTML without contextual escaping.
* **Remediation:**
\`\`\`javascript
// 1. Sanitize with DOMPurify:
import DOMPurify from 'isomorphic-dompurify';
const safeHtml = DOMPurify.sanitize(userInput);

// 2. Enforce strict CSP headers:
Content-Security-Policy: default-src 'self'; script-src 'self';
\`\`\``;
    }
  }

  if (has('idor', 'bola', 'تلاعب بالمعرفات', 'تخطي الصلاحيات')) {
    if (isArabic) {
      return `### ثغرة التلاعب بالمعرفات المباشرة IDOR / BOLA (CWE-639):
* **السبب:** الاعتماد على المعرف القادم من المستخدم (مثل \`/api/order/105\`) دون التحقق من أن هذا المعرف يخص المستخدم الحالي المسجل.
* **طريقة الحل:**
\`\`\`javascript
// ✅ التحقق دائماً من ملكية السجل لجلسة المستخدم الحالية:
app.get('/api/orders/:id', async (req, res) => {
  const order = await prisma.order.findFirst({
    where: {
      id: Number(req.params.id),
      userId: req.currentUser.id // فحص الملكية الإلزامي
    }
  });
  if (!order) return res.status(403).json({ error: 'غير مصرح لك بالوصول لهذا السجل' });
  res.json(order);
});
\`\`\``;
    } else {
      return `### Insecure Direct Object References (IDOR / BOLA) (CWE-639):
* **Root Cause:** Accessing backend resources directly via user-supplied identifiers without enforcing tenant ownership boundaries.
* **Secure Pattern:**
\`\`\`typescript
// Always scope data queries to the authenticated session's user ID:
const record = await db.document.findFirst({
  where: {
    id: req.params.documentId,
    tenantId: req.session.user.tenantId // Enforce tenant boundary
  }
});
if (!record) throw new ForbiddenException();
\`\`\``;
    }
  }

  if (has('jwt', 'توكن jwt', 'alg none', 'توقيع التوكن')) {
    if (isArabic) {
      return `### تأمين توكنات الـ JWT (CWE-347 / CWE-522):
* **أهم الممارسات:**
  1. **رفض خوارزمية \`alg: "none"\` صراحة** أثناء فك التشفير.
  2. استخدام مفتاح سري عشوائي طويل (256-bit على الأقل) أو استخدام التشفير غير المتماثل (RS256 / ES256).
  3. تحديد وقت صلاحية قصير (\`exp\`) للتوكن (مثلاً 15 دقيقة) مع استخدام Refresh Token محمي بـ HttpOnly Cookie.
  4. عدم تخزين كلمات المرور أو البيانات الحساسة داخل الـ Payload.`;
    } else {
      return `### JWT Hardening Guidelines (CWE-347):
* Explicitly reject \`alg: "none"\` during verification (\`algorithms: ['RS256']\`).
* Enforce high-entropy 256-bit secrets for HMAC or use Asymmetric RSA/ECDSA pairs.
* Always enforce explicit short-lived expiration claims (\`exp: 900\`).
* Never store sensitive secrets or passwords in the unencrypted JWT payload.`;
    }
  }

  if (has('ssrf', 'طلب من طرف السيرفر', 'metadata', '169.254')) {
    if (isArabic) {
      return `### ثغرة تزوير الطلبات من جانب الخادم SSRF (CWE-918):
* **السبب:** قيام السيرفر بإرسال طلبات HTTP لروابط يدخلها المستخدم دون فلترة، مما يمكنه من الوصول للشبكة الداخلية أو خدمات الكلاود (Cloud Metadata).
* **طريقة الوقاية:**
  1. حظر عناوين الـ Link-Local وعناوين الميتا داتا: \`169.254.169.254\`.
  2. حظر عناوين الـ Localhost: \`127.0.0.0/8\`, \`::1\`.
  3. استخدام قائمة بيضاء (Allowlist) بالنطاقات المسموح جلب بيانات منها.
  4. في AWS، تفعيل **IMDSv2** الذي يمنع سحب التوكنات بطلبات GET بسيطة.`;
    } else {
      return `### Server-Side Request Forgery (SSRF) Hardening (CWE-918):
* Enforce strict destination domain allowlists.
* Block private CIDRs at network and application levels (\`10.0.0.0/8\`, \`172.16.0.0/12\`, \`192.168.0.0/16\`, \`127.0.0.0/8\`).
* Block Link-Local Cloud Metadata IP (\`169.254.169.254\`).
* Mandate AWS IMDSv2 token session requirements.`;
    }
  }

  // ==========================================
  // Category 16: Ultra-Intelligent Context & Semantic Fallback
  // ==========================================
  if (isArabic) {
    const step = ctx.currentStep || ctx.currentView || 'dashboard';
    return `أهلاً بك! بخصوص استفسارك: "${rawMsg}".

بصفتي مساعد **Sential AI DevSecOps**، إليك التوجيه الأنسب لطلبك:

* **إذا أردت رفع ملفات الكود:** في الخطوة 2، اختر **Development** واضغط على **Attach ZIP** أو **Folder** لرفع مشروعك كاملاً دون الحاجة لأي دومين.
* **إذا أردت فحص موقع إلكتروني:** اختر **Staging** أو **Production** وضع الرابط واضغط على **Verify**.
* **إذا سألت عن الخطوات التالية:** تأكد من إقرار التفويض في الخطوة 3 وضبط مسارات الاستبعاد (Excluded Paths)، ثم اضغط **Continue**.
* **إذا أردت حل ثغرة معينة:** اكتب لي اسم الثغرة (مثل: SQLi, XSS, CSRF, IDOR, SSRF, JWT) وسأعطيك كود الإصلاح المباشر لها فوراً!

أخبرني بالجزئية المحددة التي تود المساعدة فيها خطوة بخطوة وسأكون معك! 🛡️`;
  } else {
    return `Hello! Regarding your inquiry: "${rawMsg}".

As your **Sential AI DevSecOps Copilot**, here is direct guidance:

* **Uploading Code Archives:** In Step 2, select **Development** and click **Attach ZIP** or **Folder** to scan your local project via SAST without needing DNS verification.
* **Scanning Web URLs:** Select **Staging** or **Production**, provide your reachable URL, and click **Verify**.
* **Assessment Workflow:** In Step 3, confirm legal consent, configure Included/Excluded boundaries, and click **Continue**.
* **Vulnerability Fixes:** Mention any CWE (e.g., SQLi, XSS, CSRF, IDOR, SSRF, JWT) for immediate root cause analysis and drop-in code patches.

Let me know which specific step or issue you would like me to assist with! 🛡️`;
  }
}

/**
 * Searches the 970+ CWE Knowledge Base for matches against user query
 */
function lookupKnowledgeBase(query: string): KnowledgeBaseEntry | null {
  const entries = knowledgeBaseService.getAllEntries();
  if (!entries || entries.length === 0) return null;

  const q = query.toLowerCase();

  // 1. Direct CWE-ID match (e.g. "cwe-89", "cwe 79", "cwe-918")
  const cweMatch = q.match(/cwe[-_\s]?(\d+)/i);
  if (cweMatch) {
    const targetCwe = `CWE-${cweMatch[1]}`;
    const found = entries.find(e => (e.cwe_id || '').toUpperCase() === targetCwe);
    if (found) return found;
  }

  // 2. Direct keyword in title
  const directKeywords = [
    'prototype pollution', 'command injection', 'path traversal', 'directory traversal',
    'open redirect', 'clickjacking', 'cors', 'csrf', 'xxe', 'deserialization',
    'ldap injection', 'buffer overflow', 'race condition', 'graphql', 'websocket',
    'file upload', 'hardcoded credentials', 'weak password', 'information disclosure'
  ];

  for (const kw of directKeywords) {
    if (q.includes(kw)) {
      const match = entries.find(e => (e.name || '').toLowerCase().includes(kw));
      if (match) return match;
    }
  }

  return null;
}

/**
 * Formats a Knowledge Base Entry into a rich response
 */
function formatKnowledgeBaseReply(entry: KnowledgeBaseEntry, isArabic: boolean): string {
  const cwe = entry.cwe_id || 'N/A';
  const name = entry.name || 'Security Weakness';
  const desc = entry.description || 'Vulnerability details registered in security knowledge base.';
  const impact = entry.business_impact || 'Potential unauthorized access or compromise of system integrity.';
  const rem = entry.remediation;

  if (isArabic) {
    let out = `### ثغرة ${name} (${cwe})

* **الوصف:** ${desc}
* **الأثر على النظام:** ${impact}
`;

    if (rem) {
      if (rem.guidance) {
        out += `\n* **إرشادات الإصلاح:** ${rem.guidance}\n`;
      }
      if (rem.vulnerable_code && rem.secure_code) {
        out += `\n**مقارنة الكود (Vulnerable vs. Secure):**
\`\`\`javascript
// ❌ الكود المصاب:
${rem.vulnerable_code}

// ✅ الكود المؤمن:
${rem.secure_code}
\`\`\`\n`;
      }
    }
    return out;
  } else {
    let out = `### Vulnerability Analysis: ${name} (${cwe})

* **Description:** ${desc}
* **Business Impact:** ${impact}
`;

    if (rem) {
      if (rem.guidance) {
        out += `\n* **Remediation Guidance:** ${rem.guidance}\n`;
      }
      if (rem.vulnerable_code && rem.secure_code) {
        out += `\n**Code Diff:**
\`\`\`javascript
// ❌ Vulnerable Pattern:
${rem.vulnerable_code}

// ✅ Secure Pattern:
${rem.secure_code}
\`\`\`\n`;
      }
    }
    return out;
  }
}
