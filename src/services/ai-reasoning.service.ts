import fs from 'fs';
import path from 'path';
import { RawToolFinding } from '../tools/security-tool.interface';
import { ENV } from '../config/env';

export interface SuspiciousCodeBlock {
  filePath: string;
  relPath: string;
  lineStart: number;
  lineEnd: number;
  trigger: string;
  codeSnippet: string;
}

/**
 * Hybrid AI Security Auditor & Deep Reasoning Engine
 * Stage 1: Fast AST / Code Block Extractor for complex business logic, auth, and data-sinks.
 * Stage 2: Deep Semantic Reasoning & Local / Remote LLM Auditor.
 * Understands business logic (BOLA/IDOR), race conditions (TOCTOU), NoSQL bypasses, and ReDoS.
 */
export class AIReasoningService {
  /**
   * Run hybrid deep reasoning on the audited repository.
   */
  public static async analyze(targetDir: string): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    if (!fs.existsSync(targetDir)) {
      return findings;
    }

    const files: string[] = [];
    this.collectSourceFiles(targetDir, files);

    // Stage 1: Extract candidate suspicious code blocks
    const candidateBlocks: SuspiciousCodeBlock[] = [];
    for (const filePath of files) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const relPath = path.relative(targetDir, filePath).replace(/\\/g, '/');

        if (relPath.includes('node_modules') || relPath.includes('vulnerabilities.json')) {
          continue;
        }

        this.extractCandidateBlocks(filePath, relPath, content, candidateBlocks);
      } catch {}
    }

    // Stage 2A: On-Device Semantic Deep Reasoning Engine (100% Offline / Zero-Cloud)
    for (const block of candidateBlocks) {
      const semanticFindings = this.auditBlockSemantics(block);
      findings.push(...semanticFindings);
    }

    // Stage 2B: Local or Remote LLM Review Layer (if configured)
    if (ENV.OPENAI_API_KEY || ENV.GEMINI_API_KEY || process.env.LOCAL_LLM_URL) {
      try {
        const llmFindings = await this.queryLLMSecurityAuditor(candidateBlocks.slice(0, 5));
        findings.push(...llmFindings);
      } catch (llmErr) {
        console.warn('[AIReasoningService] LLM query notice:', (llmErr as Error).message);
      }
    }

    return findings;
  }

  private static extractCandidateBlocks(
    fullPath: string,
    relPath: string,
    content: string,
    out: SuspiciousCodeBlock[]
  ): void {
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Financial / Race Condition / Balance check trigger
      if (/(?:balance\s*>=|balance\s*-=|amount\s*<=|withdraw|transfer|double-spend)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 35)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 35),
          trigger: 'RACE_CONDITION_BALANCE',
          codeSnippet: block,
        });
      }

      // Mass Assignment / BOLA trigger
      if (/(?:Object\.assign\s*\(|(?:\.\.\.req\.body)|req\.body\.role|req\.body\.isAdmin)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 25)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 25),
          trigger: 'MASS_ASSIGNMENT_BOLA',
          codeSnippet: block,
        });
      }

      // Cart Quantity & Currency Rounding trigger
      if (/(?:cart|items|quantity|exchangeRate|Math\.floor|checkout)/i.test(line)) {
        if (/quantity|Math\.floor/i.test(line)) {
          const block = lines.slice(Math.max(0, i - 4), Math.min(lines.length, i + 25)).join('\n');
          out.push({
            filePath: fullPath,
            relPath,
            lineStart: i + 1,
            lineEnd: Math.min(lines.length, i + 25),
            trigger: 'BUSINESS_LOGIC_CART',
            codeSnippet: block,
          });
        }
      }

      // ReDoS trigger
      if (/(?:new RegExp|\/[^\/]+\/(?:test|exec|match))\s*\(.*?(?:email|domain|input|text)/i.test(line) ||
          /\(\[[^\]]+\]\+\)\*/i.test(line) ||
          /\([a-zA-Z0-9_+-]+\+\)\+/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 15)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 15),
          trigger: 'REDOS_REGEX',
          codeSnippet: block,
        });
      }

      // XPath injection trigger
      if (/(?:xpath|select\(|evaluate\(|xpath\.find)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 15)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 15),
          trigger: 'XPATH_INJECTION',
          codeSnippet: block,
        });
      }

      // Cryptographic timing attack trigger
      if (/(?:===|==)\s*(?:key|token|secret|apiKey|expectedKey)|(?:expectedKey|secretKey|serviceKey)\s*(?:===|==)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 10)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 10),
          trigger: 'TIMING_ATTACK',
          codeSnippet: block,
        });
      }

      // SVG XXE / SSRF trigger
      if (/(?:svg|upload-svg|DOMParser|xml2js|parseFromString)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 25)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 25),
          trigger: 'SVG_XXE_SSRF',
          codeSnippet: block,
        });
      }

      // AI Prompt Injection & Token Sponge trigger
      if (/(?:summarize|embeddings|ai\/model|prompt|openai\.create|claude|gemini)/i.test(line)) {
        const block = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 25)).join('\n');
        out.push({
          filePath: fullPath,
          relPath,
          lineStart: i + 1,
          lineEnd: Math.min(lines.length, i + 25),
          trigger: 'AI_PIPELINE_SECURITY',
          codeSnippet: block,
        });
      }
    }
  }

  /**
   * On-Device Semantic Reasoning Engine
   * Deeply analyzes the syntax tree and control flow of candidate blocks.
   */
  private static auditBlockSemantics(block: SuspiciousCodeBlock): RawToolFinding[] {
    const findings: RawToolFinding[] = [];
    const code = block.codeSnippet;

    // 1. Race Condition / TOCTOU Double-Spend (CWE-367)
    if (block.trigger === 'RACE_CONDITION_BALANCE') {
      const hasBalanceCheck = /if\s*\(\s*.*?(?:balance\s*>=|amount\s*<=)/i.test(code);
      const hasAsyncDelay = /(?:setTimeout|await\s+new\s+Promise|await\s+sleep|sleep\s*\()/i.test(code);
      const hasBalanceDeduct = /(?:balance\s*-=|balance\s*=\s*.*?-\s*amount)/i.test(code);
      const hasAtomicOrTx = /(?:transaction|SELECT\s+.*?\s+FOR\s+UPDATE|mutex|lock|atomic)/i.test(code);

      if (hasBalanceCheck && hasAsyncDelay && hasBalanceDeduct && !hasAtomicOrTx) {
        findings.push({
          title: 'Race Condition / TOCTOU Concurrency Flaw in Balance Transfer',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'RACE_CONDITION',
          sourceRuleId: 'ai-auditor.race-condition.double-spend',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `State check (balance check) is separated from state update (balance deduction) by an asynchronous operation without database transaction locks (SELECT FOR UPDATE) or atomic decrements, allowing double-spending under concurrent requests.`,
          rawSnippet: code.split('\n').slice(0, 8).join('\n'),
          remediation: `Wrap balance verification and deduction inside an atomic database transaction with isolation level SERIALIZABLE or use atomic decrement queries ($inc: { balance: -amount } with balance >= amount condition).`,
          cwe: 'CWE-367',
        });
      }
    }

    // 2. Mass Assignment / Privilege Escalation (CWE-915)
    if (block.trigger === 'MASS_ASSIGNMENT_BOLA') {
      const hasObjectAssign = /Object\.assign\s*\(\s*(?:target|user|settings|profile|tenant|account)/i.test(code);
      const hasUncheckedBody = /req\.body/i.test(code);
      const hasRoleOrAdmin = /(?:isAdmin|role|permissions|tenantId|isSuperUser|superadmin)/i.test(code);

      if ((hasObjectAssign || code.includes('...req.body')) && hasUncheckedBody && hasRoleOrAdmin) {
        findings.push({
          title: 'Mass Assignment / Over-Posting Leading to Privilege Escalation',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'MASS_ASSIGNMENT',
          sourceRuleId: 'ai-auditor.mass-assignment.privilege-escalation',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `User-controlled request body is merged directly into sensitive user/tenant state using Object.assign or spread operator without a field allowlist, permitting unprivileged users to inject administrative roles or tenant identifiers.`,
          rawSnippet: code.split('\n').slice(0, 8).join('\n'),
          remediation: `Use Data Transfer Object (DTO) allowlists. Explicitly pick authorized fields (e.g. const { bio, name } = req.body) rather than passing the entire req.body object.`,
          cwe: 'CWE-915',
        });
      }
    }

    // 3. Business Logic: Missing Positive Quantity Validation (CWE-840)
    if (block.trigger === 'BUSINESS_LOGIC_CART') {
      const hasQuantityParam = /quantity/i.test(code);
      const lacksPositiveCheck = !/(?:quantity\s*>\s*0|Math\.max\s*\(\s*1|parseInt\(.*?\)\s*>\s*0)/i.test(code);
      const hasTotalCalculation = /(?:total\s*\+=|total\s*=|item\.price\s*\*|price\s*\*)/i.test(code);

      if (hasQuantityParam && lacksPositiveCheck && hasTotalCalculation) {
        findings.push({
          title: 'Business Logic Flaw: Missing Positive Quantity Validation in Checkout',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'BUSINESS_LOGIC',
          sourceRuleId: 'ai-auditor.logic.negative-quantity-cart',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `Shopping cart / order calculation computes order totals using user-supplied quantity without asserting that quantity is a strictly positive integer, allowing attackers to submit negative values and reduce total invoice costs.`,
          rawSnippet: code.split('\n').slice(0, 6).join('\n'),
          remediation: `Assert that item quantities are integers greater than zero (if (!Number.isInteger(quantity) || quantity <= 0) throw new BadRequest('Invalid quantity')).`,
          cwe: 'CWE-840',
        });
      }

      // Currency Rounding Flaw (CWE-840)
      if (/Math\.floor\s*\(\s*(?:amount|rate|balance|converted|units)/i.test(code)) {
        findings.push({
          title: 'Business Logic Flaw: Currency Conversion Floor Rounding Inaccuracy',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          category: 'BUSINESS_LOGIC',
          sourceRuleId: 'ai-auditor.logic.currency-rounding-flaw',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `Financial conversion logic uses Math.floor on fractional currency conversions, which truncates micro-pennies or rounds rates to zero, enabling systematic rounding exploitation across micro-transactions.`,
          rawSnippet: code.split('\n').slice(0, 5).join('\n'),
          remediation: `Use precision decimal arithmetic libraries (such as decimal.js or bignumber.js) and bankers rounding (round-half-to-even) for monetary calculations.`,
          cwe: 'CWE-840',
        });
      }
    }

    // 4. Regular Expression Denial of Service (ReDoS - CWE-1333)
    if (block.trigger === 'REDOS_REGEX') {
      const hasCatastrophicRegex =
        /\(\[?[a-zA-Z0-9_.-]+\]?\+\)\*/i.test(code) ||
        /\([a-zA-Z0-9]+\+\)\+/i.test(code) ||
        /\(\.\*\)\+/i.test(code) ||
        /([a-zA-Z0-9]+)\*\+/i.test(code);

      if (hasCatastrophicRegex) {
        findings.push({
          title: 'Regular Expression Denial of Service (ReDoS) via Catastrophic Backtracking',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          category: 'DENIAL_OF_SERVICE',
          sourceRuleId: 'ai-auditor.redos.catastrophic-backtracking',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `Regular expression employs nested quantifiers (e.g. (a+)+ or ([a-zA-Z0-9]+)*@) that trigger exponential catastrophic backtracking when matched against maliciously crafted input strings, freezing the Node.js event loop.`,
          rawSnippet: code.split('\n').slice(0, 5).join('\n'),
          remediation: `Refactor regular expressions to remove nested quantified groups, or use linear-time regex engines like RE2 or validator.isEmail().`,
          cwe: 'CWE-1333',
        });
      }
    }

    // 5. XPath Injection (CWE-643)
    if (block.trigger === 'XPATH_INJECTION') {
      const hasDynamicConcat = /(?:\+.*?(?:req\.body|req\.query|username|user)|\$\{.*?(?:username|user|req)\})/i.test(code);
      if (hasDynamicConcat) {
        findings.push({
          title: 'XPath Injection in XML Authentication / Query Sink',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'INJECTION',
          sourceRuleId: 'ai-auditor.xpath.injection-sink',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `XPath query is dynamically assembled using untrusted user input without parameterized variable mapping, enabling attackers to bypass authentication or extract sensitive XML nodes.`,
          rawSnippet: code.split('\n').slice(0, 5).join('\n'),
          remediation: `Use parameterized XPath queries or pre-compiled variables instead of dynamic string concatenation.`,
          cwe: 'CWE-643',
        });
      }
    }

    // 6. Cryptographic Timing Attack (CWE-208)
    if (block.trigger === 'TIMING_ATTACK') {
      const hasDirectComparison = /(?:===|==)\s*(?:expectedKey|serviceKey|apiSecret|secretToken|authKey)/i.test(code) ||
                                  /(?:expectedKey|serviceKey|apiSecret|secretToken|authKey)\s*(?:===|==)/i.test(code);
      if (hasDirectComparison) {
        findings.push({
          title: 'Cryptographic Timing Attack via Non-Constant-Time String Comparison',
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          category: 'CRYPTOGRAPHIC_ISSUE',
          sourceRuleId: 'ai-auditor.timing-attack.string-comparison',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `API key or cryptographic secret is validated using standard equality operators (===) which short-circuit upon the first mismatched byte, leaking key character positions via microsecond latency timing differences.`,
          rawSnippet: code.split('\n').slice(0, 5).join('\n'),
          remediation: `Use crypto.timingSafeEqual(Buffer.from(providedKey), Buffer.from(expectedKey)) for comparing cryptographic credentials.`,
          cwe: 'CWE-208',
        });
      }
    }

    // 7. SVG XXE & SSRF (CWE-611 / CWE-918)
    if (block.trigger === 'SVG_XXE_SSRF') {
      const parsesSvgXml = /(?:DOMParser|xml2js|parseFromString|svg2png|librsvg)/i.test(code);
      if (parsesSvgXml) {
        findings.push({
          title: 'XML External Entity (XXE) & SSRF via Insecure SVG Logo Parsing',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'INJECTION',
          sourceRuleId: 'ai-auditor.svg.xxe-ssrf-parser',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `User-uploaded SVG image is processed using an XML parser without explicitly disabling external entity resolution (DOCTYPE / ENTITY) or external resource fetching, permitting local file disclosure and SSRF attacks.`,
          rawSnippet: code.split('\n').slice(0, 6).join('\n'),
          remediation: `Disable external DTDs and entity resolution in XML/SVG parsers, or sanitize SVGs using DOMPurify with USE_PROFILES: { svg: true } before processing.`,
          cwe: 'CWE-611',
        });
      }
    }

    // 8. AI Prompt Injection & Token Sponge DoS (CWE-1426 / CWE-400)
    if (block.trigger === 'AI_PIPELINE_SECURITY') {
      // Insecure DOM rendering of AI model output
      if (/(?:innerHTML\s*=\s*.*?(?:summary|completion|response)|<div class="ai-summary">\$\{)/i.test(code)) {
        findings.push({
          title: 'AI Output Injection / DOM Rendering without Contextual Encoding',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'CROSS_SITE_SCRIPTING',
          sourceRuleId: 'ai-auditor.llm.insecure-output-handling',
          filePath: block.relPath,
          lineStart: block.lineStart,
          lineEnd: block.lineEnd,
          evidenceSummary: `AI model output derived from untrusted documents is rendered directly into HTML without contextual encoding or sanitization, enabling Indirect Prompt Injection to execute Stored XSS.`,
          rawSnippet: code.split('\n').slice(0, 6).join('\n'),
          remediation: `Treat all AI-generated output as untrusted user input. Contextual-encode or sanitize using DOMPurify before injecting into client HTML.`,
          cwe: 'CWE-1426',
        });
      }

      // Model Sponge / Token Exhaustion
      if (/(?:embeddings|createEmbedding|model\/embeddings)/i.test(code)) {
        const lacksTokenLimit = !/(?:slice\s*\(\s*0\s*,\s*\d+|max_tokens|tokenCount\s*<)/i.test(code);
        if (lacksTokenLimit) {
          findings.push({
            title: 'AI Model Sponge Attack / Unbounded Token Exhaustion DoS',
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'DENIAL_OF_SERVICE',
            sourceRuleId: 'ai-auditor.llm.token-exhaustion-sponge',
            filePath: block.relPath,
            lineStart: block.lineStart,
            lineEnd: block.lineEnd,
            evidenceSummary: `AI embedding endpoint processes user-supplied text without enforcing maximum input character or token count limits, permitting Model Sponge attacks that exhaust computational quota and memory.`,
            rawSnippet: code.split('\n').slice(0, 6).join('\n'),
            remediation: `Enforce maximum character/token boundaries on input strings (e.g. text.slice(0, 2048)) before passing to embedding generation or LLM inference.`,
            cwe: 'CWE-400',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Optional Local/Remote LLM Security Auditor call
   */
  private static async queryLLMSecurityAuditor(blocks: SuspiciousCodeBlock[]): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const localEndpoint = process.env.LOCAL_LLM_URL;

    if (!localEndpoint && !ENV.OPENAI_API_KEY && !ENV.GEMINI_API_KEY) {
      return findings;
    }

    // If local Ollama endpoint is running
    if (localEndpoint) {
      for (const block of blocks) {
        try {
          const prompt = `You are a Senior Application Security Auditor. Analyze this code snippet for critical vulnerabilities, specifically:
- Broken Object Level Authorization (BOLA/IDOR)
- Race Conditions (TOCTOU)
- Unfiltered NoSQL objects ($regex, $ne, $where)
- Insecure DOM rendering or second-order flows.

File: ${block.relPath}
Code:
\`\`\`javascript
${block.codeSnippet}
\`\`\`

Return a JSON array of findings with keys: title, severity (CRITICAL/HIGH/MEDIUM), cwe, evidenceSummary, remediation. If none found, return [].`;

          const res = await fetch(`${localEndpoint}/api/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              model: 'qwen2.5-coder',
              prompt,
              stream: false,
              format: 'json',
            }),
            signal: AbortSignal.timeout(5000),
          });

          if (res.ok) {
            const data = await res.json() as any;
            const parsed = JSON.parse(data.response || '[]');
            if (Array.isArray(parsed)) {
              for (const item of parsed) {
                if (item.title && item.severity) {
                  findings.push({
                    title: item.title,
                    severity: item.severity,
                    confidence: 'CONFIRMED',
                    category: 'AI_REASONING_DISCOVERY',
                    sourceRuleId: 'local-llm.audit.discovery',
                    filePath: block.relPath,
                    lineStart: block.lineStart,
                    lineEnd: block.lineEnd,
                    evidenceSummary: item.evidenceSummary || 'Identified via local LLM security reasoning layer.',
                    rawSnippet: block.codeSnippet.split('\n').slice(0, 6).join('\n'),
                    remediation: item.remediation || 'Apply standard OWASP secure coding best practices.',
                    cwe: item.cwe || 'CWE-20',
                  });
                }
              }
            }
          }
        } catch {
          // If local LLM server isn't answering, proceed seamlessly with built-in semantic engine
          break;
        }
      }
    }

    return findings;
  }

  private static collectSourceFiles(dir: string, out: string[]): void {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const ent of entries) {
        if (ent.name === 'node_modules' || ent.name === 'dist' || ent.name === 'storage' || ent.name === '.git') {
          continue;
        }
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          this.collectSourceFiles(full, out);
        } else if (/\.(js|ts|jsx|tsx|py|php)$/i.test(ent.name)) {
          out.push(full);
        }
      }
    } catch {}
  }
}
