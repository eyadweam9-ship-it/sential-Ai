// =========================================================
// Sential AI - Internationalization (i18n) Engine (EN / AR)
// Sleek bilingual switcher with bi-directional DOM translation
// Preserves code blocks, terminal inspector, and patch diffs
// =========================================================

(function(window) {
    'use strict';

    const DICTIONARY = {
        // Navigation & Stepper
        "Assessment Type": "نوع الفحص الأمني",
        "Target & Environment": "الهدف والبيئة البرمجية",
        "Authorization & Scope": "التفويض ونطاق الفحص",
        "Assessment in Progress": "الفحص قيد التنفيذ",
        "Findings Dashboard": "لوحة الثغرات المكتشفة",
        "Finding Details": "تفاصيل الثغرة",
        "Assessment Report": "تقرير الفحص الأمني",
        "Security Workspace": "مساحة العمل الأمنية",
        "New assessment": "فحص أمني جديد",
        "New Assessment": "فحص أمني جديد",
        "Start New Assessment": "بدء فحص جديد",
        "Assessment flow": "مراحل الفحص الأمني",
        "Clear History": "مسح السجل",
        "Download CSV": "تصدير CSV",
        "Export CSV": "تصدير CSV",
        "Generate Report": "إنشاء التقرير",
        "Log in": "تسجيل الدخول",
        "Sign in": "تسجيل الدخول",
        "Log out": "تسجيل الخروج",
        "Sign out": "تسجيل الخروج",
        "Sign Out": "تسجيل الخروج",
        "Sign Up": "إنشاء حساب",
        "Sign up": "إنشاء حساب",
        "Start free": "ابدأ مجاناً",
        "Settings": "الإعدادات",
        "Settings & History": "الإعدادات وسجل الفحوصات",
        "Admin Portal": "بوابة الإدارة",
        "Admin Dashboard": "لوحة تحكم المشرف",
        "Autonomous Security": "أمن تطبيقات الويب الذاتي",

        // Step numbers in stepper
        "Step 1": "الخطوة 1",
        "Step 2": "الخطوة 2",
        "Step 3": "الخطوة 3",
        "Step 4": "الخطوة 4",
        "Step 5": "الخطوة 5",
        "Step 6": "الخطوة 6",
        "Step 7": "الخطوة 7",
        "Step 1 • Locked": "الخطوة 1 • مغلقة",
        "Step 2 • Locked": "الخطوة 2 • مغلقة",
        "Step 3 • Locked": "الخطوة 3 • مغلقة",
        "Step 4 • Locked": "الخطوة 4 • مغلقة",
        "Step 5 • Locked": "الخطوة 5 • مغلقة",
        "Step 6 • Locked": "الخطوة 6 • مغلقة",
        "Step 7 • Locked": "الخطوة 7 • مغلقة",

        // Common Buttons & Actions
        "Continue": "متابعة",
        "Back": "رجوع",
        "Cancel": "إلغاء",
        "Save": "حفظ",
        "Confirm": "تأكيد",
        "Close": "إغلاق",
        "Search": "بحث",
        "Actions": "الإجراءات",
        "Filter": "تصفية",
        "All": "الكل",
        "Status": "الحالة",
        "Severity": "الخطورة",
        "Endpoint": "المسار / الهدف",
        "Tool": "الأداة",
        "CVSS": "مقياس CVSS",
        "Details": "التفاصيل",
        "View Details": "عرض التفاصيل",
        "Apply Patch": "تطبيق الترقيع",
        "Run Retest": "إجراء فحص تحقق",
        "Retest & Verify": "إعادة الفحص والتحقق",
        "Verify Fix": "التحقق من الإصلاح",
        "Download PDF": "تحميل PDF",

        // Severities & Statuses
        "Critical": "حرجة",
        "High": "عالية",
        "Medium": "متوسطة",
        "Low": "منخفضة",
        "Info": "معلوماتية",
        "Fix ready": "الإصلاح جاهز",
        "Confirmed": "مؤكدة",
        "In review": "قيد المراجعة",
        "Mitigated": "تم التخفيف",
        "Fixed": "تم الإصلاح",
        "Completed": "مكتمل",
        "Running": "قيد التشغيل",
        "Queued": "في الانتظار",
        "Skipped": "تم التخطي",
        "Detected": "تم الاكتشاف",
        "VULN DETECTED": "تم رصد ثغرة",
        "VULN DETECTED: CWE-89": "تم رصد ثغرة: CWE-89",

        // Welcome / Landing Page
        "AI-powered web security": "أمن تطبيقات الويب بالذكاء الاصطناعي",
        "Find vulnerabilities.": "اكتشف الثغرات الأمنية.",
        "Fix them before attackers exploit them.": "وأصلحها قبل أن يستغلها المهاجمون.",
        "Fix them faster.": "وأصلحها بسرعة فائقة.",
        "Run comprehensive security assessments, prioritize what matters, and ship AI-guided fixes with confidence.": "أجرِ فحوصات أمنية شاملة، وحدد الأولويات بدقة، وطبق ترقيعات برمجية مؤكدة بالذكاء الاصطناعي.",
        "Start free assessment": "ابدأ فحصاً مجانياً",
        "Start your first scan": "ابدأ فحصك الأول",
        "View dashboard": "عرض لوحة المراقبة",
        "First scan in minutes": "أول فحص في دقائق",
        "Watch interactive demo": "مشاهدة العرض التفاعلي",
        "No credit card required": "لا يلزم بطاقة ائتمان",
        "Free 14-day trial": "تجربة مجانية لمدة 14 يوماً",
        "Trusted by security and engineering teams": "موثوق به من قِبل نخبة فرق الأمن السيبراني والهندسة البرمجية",
        "TRUSTED BY SECURITY TEAMS AT": "موثوق به من فِرق الأمان السيبراني في",
        "Dark Mode": "الوضع الليلي",
        "Light Mode": "الوضع النهاري",
        "Work Email": "البريد الإلكتروني للعمل",
        "Log in to Admin Portal": "تسجيل الدخول إلى لوحة الإدارة",
        "Return to Main Application": "العودة إلى التطبيق الرئيسي",
        "Return to Main Application ←": "العودة إلى التطبيق الرئيسي ←",
        "← Return to Main Application": "العودة إلى التطبيق الرئيسي ←",

        // Auth Views
        "Security clarity, without the noise.": "وضوح أمني فائق، بدون إنذارات زائفة.",
        "From first scan to verified fix, Sential AI makes every vulnerability actionable.": "من أول فحص حتى التحقق من الإصلاح، Sential AI يجعل كل ثغرة قابلة للمعالجة الفورية الموثقة.",
        "Built for modern teams": "مصمم لفرق التطوير والأمن السيبراني الحديثة",
        "Welcome back": "مرحباً بعودتك",
        "Sign in to access your security dashboard": "سجل الدخول للوصول إلى لوحة المراقبة الأمنية",
        "Create your account": "إنشاء حساب جديد",
        "Create account": "إنشاء حساب",
        "New to Sential AI?": "جديد في Sential AI؟",
        "Get started with autonomous vulnerability scanning in minutes.": "ابدأ الفحص الأمني الذاتي في دقائق معدودة.",
        "First name": "الاسم الأول",
        "Last name": "اسم العائلة",
        "Email address": "البريد الإلكتروني",
        "Password": "كلمة المرور",
        "Confirm password": "تأكيد كلمة المرور",
        "Remember me": "تذكرني",
        "Forgot password?": "نسيت كلمة المرور؟",
        "Don't have an account?": "ليس لديك حساب؟",
        "Already have an account?": "لديك حساب بالفعل؟",

        // Step 1: Assessment Type
        "What would you like us to do?": "ما نوع الفحص الأمني المطلوب؟",
        "Choose the depth of your security assessment. You can review every change before it is applied.": "حدد عمق الفحص الأمني المطلوب. يمكنك مراجعة كل ترقيع كود قبل اعتماده.",
        "Autonomous Assessment & Remediation": "فحص ذاتي كامل مع توليد أكواد الإصلاح",
        "RECOMMENDED": "موصى به",
        "LIGHTWEIGHT": "فحص سريع",
        "Full security assessment with automated, verified remediation code ready to review and merge into your repository.": "فحص أمني شامل مع توليد أكواد ترقيع برمجية مُحققة وجاهزة للمراجعة والدمج في مستودع مشروعك.",
        "Scan & Surface Findings Only": "فحص واكتشاف الثغرات فقط",
        "Standard vulnerability scan. Delivers detailed findings, proof of exploit, and severity scores without generating code changes.": "فحص أمني قياسي يكتشف الثغرات وأدلة الاستغلال ومستويات الخطورة دون توليد تعديلات برمجية.",
        "Continue to target": "المتابعة لاختيار الهدف",
        "Scan + Fix + Test": "فحص شامل + إصلاح + تحقق",
        "Full assessment, automated fixes, and validation testing": "فحص أمني شامل، ترقيعات تلقائية، واختبارات تحقق موثقة",
        "Scan Only": "فحص واكتشاف فقط",
        "Identify and prioritize vulnerabilities without making changes": "اكتشاف وتصنيف الثغرات الأمنية دون إجراء أي تعديل برمجى",
        "Identify and prioritize vulnerabilities without making changes.": "اكتشاف وتصنيف الثغرات الأمنية دون إجراء أي تعديل برمجى.",
        "You're always in control": "أنت دائماً صاحب القرار والتحكم",
        "We never deploy changes automatically. Review and approve every suggested fix before applying it.": "نحن لا نطبق أي تعديل تلقائياً أبداً. يمكنك مراجعة واعتماد كل ترقيع قبل تطبيقه.",
        "We never deploy changes automatically. Review and approve every suggested fix before applying it": "نحن لا نطبق أي تعديل تلقائياً أبداً. يمكنك مراجعة واعتماد كل ترقيع قبل تطبيقه",
        "COMPLETE": "شامل",
        "QUICK": "سريع",
        "~35 minutes": "~35 دقيقة",
        "~10 minutes": "~10 دقائق",
        "minutes 35~": "~35 دقيقة",
        "minutes 10~": "~10 دقائق",

        // Step 2: Target & Environment
        "Where should we look?": "أين يجب أن نبدأ الفحص؟",
        "Define the target application and provide source access for deep analysis and verified fixes.": "حدد عنوان تطبيق الهدف وأرفق الكود المصدري للتحليل المعمق وتوليد الإصلاحات المؤكدة.",
        "Target URL": "رابط التطبيق (URL)",
        "Target Name": "اسم الهدف / المشروع",
        "Environment": "البيئة البرمجية",
        "Production (live users)": "الإنتاج - مستخدمين فعليين (Production)",
        "Staging (pre-release)": "التجهيز - ما قبل الإطلاق (Staging)",
        "Development (local)": "التطوير - محلي (Development)",
        "Web Application URL": "رابط تطبيق الويب",
        "Upload ZIP Archive": "رفع أرشيف ZIP",
        "Upload Project Folder": "رفع مجلد المشروع",
        "Upload source code archive": "رفع أرشيف الكود المصدري",
        "Drag and drop your .zip archive here": "اسحب وأفلت ملف الـ .zip الخاص بمشروعك هنا",
        "Run pre-scan discovery": "تشغيل الاستكشاف الأولي للهدف",
        "Continue to scope": "المتابعة لتحديد النطاق",

        // Step 3: Authorization & Scope
        "Define testing boundaries and authorization": "تحديد حدود الاختبار والتفويض القانوني",
        "Sential AI requires documented authorization before security testing begins.": "يتطلب Sential AI تفويضاً رسمياً موثقاً قبل بدء الفحص الأمني لضمان الالتزام القانوني.",
        "Written Authorization": "خطاب التفويض المكتوب",
        "Upload signed authorization (PDF)": "رفع خطاب تفويض موقع (PDF)",
        "I confirm I am authorized to test this target": "أقر وأؤكد بأنني مصرح لي رسمياً بإجراء هذا الاختبار الأمني",
        "In-Scope Endpoints": "المسارات المصرح باختبارها (In-Scope)",
        "Out-of-Scope Rules": "المسارات المستثناة من الفحص (Out-of-Scope)",
        "Launch Security Assessment": "إطلاق الفحص الأمني",

        // Step 4: Assessment in Progress
        "Analyzing Code Repository": "تحليل مستودع الكود البرمجي",
        "FULL LIFECYCLE ASSESSMENT • RUNNING": "دورة الفحص الكاملة • قيد التشغيل",
        "Running full multi-tool assessment pipeline with AI threat intelligence and verification": "تشغيل منظومة الفحص المتكاملة متعددة الأدوات مع ذكاء التهديدات والتحقق",
        "Scanning code, evaluating attack surfaces, and executing security adapters in real-time...": "جاري فحص الأكواد واختبار المسارات وتشغيل أدوات الفحص التلقائية في الوقت الحقيقي...",
        "Live Code Inspector": "مفتش الأكواد البرمجية المباشر",
        "Active File": "الملف النشط حالياً",
        "Scanning Laser": "مؤشر المسح بالليزر",
        "Vulnerabilities Detected": "الثغرات المكتشفة",
        "Assessment Progress": "تقدم الفحص الأمني",
        "Assessment progress": "تقدم الفحص الأمني",
        "Scanning Code for Vulnerabilities": "فحص الأكواد البرمجية للثغرات",
        "Cancel Assessment": "إلغاء الفحص",
        "Assessment Complete": "اكتمل الفحص بنجاح",
        "View Findings Dashboard": "عرض لوحة الثغرات",
        "View findings dashboard": "عرض لوحة الثغرات",
        "Security Adapters & Engines": "أدوات ومحركات الفحص الأمني",
        "Running security adapters and AI correlation...": "تشغيل أدوات الأمان وتحليل الذكاء الاصطناعي المترابط...",
        "ACTIVE TOOL": "الأداة النشطة",
        "REMAINING": "المتبقي",
        "ELAPSED": "الوقت المستغرق",
        "AUDITED": "تم الفحص",
        "ANALYSIS COMPLETE": "اكتمل التحليل",
        "Full Pipeline": "المنظومة الكاملة",
        "Supply Chain (Trivy, OSV & npm audit)": "سلسلة التوريد (Trivy, OSV & npm)",
        "SentinelAI Correlation Engine": "محرك الترابط وتحليل التهديدات",
        "Cross-tool deduplication, evidence validation & AI triage": "منع التكرار، التحقق من الأدلة، وفرز الذكاء الاصطناعي",

        // Step 5: Findings Dashboard
        "Security findings": "الثغرات والنتائج الأمنية",
        "Discovered Security Issues": "الثغرات الأمنية المكتشفة",
        "Review, triage, and apply automated remediations.": "راجع الثغرات المكتشفة واطلع على أكواد الترقيع الجاهزة.",
        "Search findings, endpoints, CWEs...": "ابحث عن الثغرات، المسارات، أو أكواد CWE...",
        "Search findings": "البحث في الثغرات...",
        "All Severities": "كافة المستويات",
        "All severity": "كافة المستويات",
        "All status": "كافة الحالات",
        "Issue / Vulnerability": "الثغرة / المشكلة الأمنية",
        "Target / Endpoint": "الهدف / المسار",
        "View Report": "عرض التقرير",
        "Export Report": "تصدير التقرير",
        "Retest (Rescan)": "إعادة الفحص والتحقق",
        "Source Code & Component Security Engine": "محرك أمان الكود المصدري والمكونات",
        "Total findings": "إجمالي الثغرات",
        "Fixes available": "إصلاحات متوفرة",
        "Review within 24h": "مراجعة خلال 24 ساعة",
        "Fix immediately": "إصلاح فوري",
        "High risk": "خطورة مرتفعة",
        "Security score": "مؤشر الأمان",
        "All findings": "كافة الثغرات",
        "findings cataloged": "ثغرة مفهرسة",
        "Infrastructure (IaC)": "البنية التحتية (IaC)",
        "Dependencies (SCA)": "الاعتماديات (SCA)",
        "Secrets & Credentials": "الأسرار والبيانات الحساسة",
        "Web App (DAST)": "تطبيق الويب (DAST)",
        "Source Code (SAST)": "الكود المصدري (SAST)",
        "FINDING": "الثغرة الأمنية",
        "CATEGORY": "التصنيف",
        "Hardcoded Password in Environment / Config Definition": "كلمة مرور ثابتة في ملف الإعدادات والبيئة",

        // Step 6: Finding Details
        "Root Cause Analysis & Remediation": "تحليل السبب الجذري والإصلاح البرمجي",
        "Back to findings": "العودة إلى لوحة الثغرات",
        "Overview": "نظرة عامة",
        "Evidence & HTTP Request": "الأدلة والطلب البرمجي",
        "Evidence & Request": "الأدلة والطلب البرمجي",
        "AI Remediation Patch": "كود الترقيع بالذكاء الاصطناعي",
        "Remediation Code": "كود الترقيع المقترح",
        "Verify Retest": "إعادة الفحص والتحقق",
        "What we found": "ما تم اكتشافه",
        "Remediation Recommendation": "توصية الإصلاح والمعالجة",
        "Confidence": "نسبة التأكيد",
        "Severity Score": "درجة الخطورة",
        "OWASP Category": "تصنيف OWASP",
        "CWE ID": "معرّف CWE",

        // Step 7: Assessment Report
        "Security Assessment Report": "تقرير الفحص الأمني الشامل",
        "Executive Summary & Compliance Audit": "الملخص التنفيذي وتدقيق الامتثال الأمني",
        "Executive Summary": "الملخص التنفيذي",
        "Compliance Matrix": "مصفوفة الامتثال والمعايير",
        "Total Findings": "إجمالي الثغرات",
        "Critical Risk Score": "مؤشر الخطورة الحرجة",
        "Remediation Rate": "نسبة المعالجة",

        // Admin Dashboard & Pages
        "Administration / Overview": "الإدارة / نظرة عامة",
        "Monitor users, database targets, security scans and audit activity.": "مراقبة المستخدمين، الأهداف، الفحوصات الأمنية، وسجلات النشاط.",
        "Total Users": "إجمالي المستخدمين",
        "Active Admins": "المشرفون النشطون",
        "Total Targets": "إجمالي الأهداف",
        "Total Scans": "إجمالي الفحوصات",
        "Total Vulnerabilities": "إجمالي الثغرات المكتشفة",
        "System Health": "حالة النظام",
        "Database Status": "حالة قاعدة البيانات",
        "Recent Scans": "أحدث الفحوصات الأمنية",
        "Admin Management": "إدارة المشرفين",
        "Add New Admin": "إضافة مشرف جديد",
        "+ Add New Admin": "+ إضافة مشرف جديد",
        "Back to Dashboard": "العودة للوحة التحكم",
        "Audit Logs": "سجلات التدقيق",
        "Role": "الصلاحية",
        "Created At": "تاريخ الإنشاء",
        "Last Login": "آخر تسجيل دخول",
        "Admin Portal • Role Verification": "بوابة الإدارة • التحقق من الصلاحيات",
        "Log in to Sential AI": "تسجيل الدخول إلى Sential AI",
        "Sign in with your Administrator credentials to manage security scans and database audit logs.": "سجل الدخول باستخدام بيانات المشرف لإدارة الفحوصات وسجلات التدقيق.",
        "Assessments": "فحوصات أمنية",
        "Uptime": "استقرار النظام",
        "Setup time": "وقت الإعداد",
    };

    // Reverse dictionary for lossless reverting back to English
    const REVERSE_DICTIONARY = {};
    Object.keys(DICTIONARY).forEach(en => {
        REVERSE_DICTIONARY[DICTIONARY[en]] = en;
    });

    const I18n = {
        currentLang: 'en',
        initialized: false,

        init() {
            try {
                const saved = localStorage.getItem('sential_lang');
                if (saved === 'ar' || saved === 'en') {
                    this.currentLang = saved;
                } else {
                    const navLang = navigator.language || navigator.userLanguage || '';
                    this.currentLang = navLang.startsWith('ar') ? 'ar' : 'en';
                }
            } catch (e) {
                this.currentLang = 'en';
            }
            this.applyLanguage(false);
            this.initialized = true;
        },

        applyLanguage(notify = true) {
            const isAr = this.currentLang === 'ar';
            document.documentElement.setAttribute('lang', this.currentLang);
            document.documentElement.setAttribute('dir', isAr ? 'rtl' : 'ltr');
            
            if (document.body) {
                if (isAr) {
                    document.body.classList.add('rtl-mode');
                } else {
                    document.body.classList.remove('rtl-mode');
                }
            }

            try {
                localStorage.setItem('sential_lang', this.currentLang);
            } catch (e) {}

            // Update all active language toggle pills on the page
            this.updateAllTogglePills();

            // Run DOM Translation
            this.translateDOM(document.body || document.documentElement);

            if (notify && typeof window.showToast === 'function') {
                const msg = isAr ? '🌐 تم التبديل إلى اللغة العربية' : '🌐 Switched to English';
                window.showToast(msg, 'info');
            }
        },

        toggleLang(event) {
            if (event && event.preventDefault) {
                event.preventDefault();
            }
            this.currentLang = (this.currentLang === 'ar') ? 'en' : 'ar';
            this.applyLanguage(true);

            // If App exists, re-render view cleanly
            if (window.App && typeof window.App.render === 'function') {
                window.App.render();
            }
        },

        t(key, fallback = '') {
            if (this.currentLang === 'ar') {
                return DICTIONARY[key] || fallback || key;
            }
            return fallback || key;
        },

        renderToggle() {
            const isAr = this.currentLang === 'ar';
            return `
                <div class="lang-toggle-wrap">
                    <button type="button" class="lang-switch-btn ${isAr ? 'is-ar' : 'is-en'}" onclick="I18n.toggleLang(event)" title="${isAr ? 'Switch to English' : 'التحويل إلى العربية'}" aria-label="Toggle language">
                        <svg class="lang-globe-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="2" y1="12" x2="22" y2="12"></line>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                        </svg>
                        <span class="lang-pill-item lang-en ${!isAr ? 'active' : ''}">EN</span>
                        <span class="lang-pill-sep">/</span>
                        <span class="lang-pill-item lang-ar ${isAr ? 'active' : ''}">عربي</span>
                    </button>
                </div>
            `;
        },

        updateAllTogglePills() {
            const isAr = this.currentLang === 'ar';
            document.querySelectorAll('.lang-toggle-wrap').forEach(wrap => {
                const temp = document.createElement('div');
                temp.innerHTML = this.renderToggle();
                const newEl = temp.firstElementChild;
                if (newEl && wrap.parentNode) {
                    wrap.parentNode.replaceChild(newEl, wrap);
                }
            });

            // Auto-render into admin containers if present
            document.querySelectorAll('#adminLangToggleContainer').forEach(container => {
                container.innerHTML = this.renderToggle();
            });
        },

        translateDOM(container) {
            if (!container) return;
            const isAr = this.currentLang === 'ar';

            // Walk text nodes
            const walker = document.createTreeWalker(
                container,
                NodeFilter.SHOW_TEXT,
                {
                    acceptNode: function(node) {
                        const parent = node.parentElement;
                        if (!parent) return NodeFilter.FILTER_REJECT;
                        const tag = parent.tagName.toLowerCase();
                        // Strictly skip code, scripts, styles, pre blocks, terminal content
                        if (tag === 'script' || tag === 'style' || tag === 'code' || tag === 'pre' || 
                            parent.classList.contains('code-font') || 
                            parent.classList.contains('code-line-content') || 
                            parent.classList.contains('laser-stream') || 
                            parent.classList.contains('terminal-code-body') ||
                            parent.classList.contains('patch-diff-content') ||
                            parent.classList.contains('brand-name') ||
                            parent.classList.contains('brand-ai')) {
                            return NodeFilter.FILTER_REJECT;
                        }
                        return NodeFilter.FILTER_ACCEPT;
                    }
                },
                false
            );

            let node;
            while ((node = walker.nextNode())) {
                const originalText = node.nodeValue;
                const trimmed = originalText.trim();
                if (!trimmed) continue;

                if (isAr) {
                    if (DICTIONARY[trimmed]) {
                        node.nodeValue = originalText.replace(trimmed, DICTIONARY[trimmed]);
                    }
                } else {
                    if (REVERSE_DICTIONARY[trimmed]) {
                        node.nodeValue = originalText.replace(trimmed, REVERSE_DICTIONARY[trimmed]);
                    }
                }
            }

            // Translate placeholders, titles, aria-labels
            container.querySelectorAll('input[placeholder], textarea[placeholder], button[title], a[title]').forEach(el => {
                if (el.placeholder) {
                    const p = el.placeholder.trim();
                    if (isAr && DICTIONARY[p]) {
                        if (!el.getAttribute('data-i18n-placeholder')) el.setAttribute('data-i18n-placeholder', p);
                        el.placeholder = DICTIONARY[p];
                    } else if (!isAr && el.getAttribute('data-i18n-placeholder')) {
                        el.placeholder = el.getAttribute('data-i18n-placeholder');
                    }
                }
                if (el.title) {
                    const t = el.title.trim();
                    if (isAr && DICTIONARY[t]) {
                        if (!el.getAttribute('data-i18n-title')) el.setAttribute('data-i18n-title', t);
                        el.title = DICTIONARY[t];
                    } else if (!isAr && el.getAttribute('data-i18n-title')) {
                        el.title = el.getAttribute('data-i18n-title');
                    }
                }
            });
        }
    };

    // Auto-init on script load
    I18n.init();
    window.I18n = I18n;

    // Run DOM translation once DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            I18n.applyLanguage(false);
            I18n.updateAllTogglePills();
        });
    } else {
        I18n.applyLanguage(false);
        I18n.updateAllTogglePills();
    }

})(window);
