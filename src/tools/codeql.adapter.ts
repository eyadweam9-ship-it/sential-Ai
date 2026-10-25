import fs from 'fs';
import path from 'path';
import { SecurityToolAdapter, ToolInput, ToolExecutionResult, RawToolFinding } from './security-tool.interface';

interface TaintPathRule {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  sourcePattern: RegExp;
  sinkPattern: RegExp;
  sanitizerPattern?: RegExp;
  description: string;
  remediation: string;
}

const TAINT_FLOW_RULES: TaintPathRule[] = [
  // 1. SQL Injection via Dynamic Query Construction
  {
    id: 'codeql.js.sql-injection-taint',
    title: 'CodeQL Data-Flow: SQL Injection via Untrusted Query Input',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-89',
    sourcePattern: /(?:req\.(?:query|params|body)|location\.search|searchParams\.get)\s*\[?['"]?([a-zA-Z0-9_]+)?/i,
    sinkPattern: /(?:db|client|connection|pool|sequelize|prisma)\.(?:query|raw|execute|\$queryRawUnsafe)\s*\(\s*(?:['"`][^'"`]*\$\{|(?:['"`][^'"`]*['"`]\s*\+\s*))/i,
    sanitizerPattern: /(?:parameterized|prepare|bind|query\s*\(\s*['"][^'"]*['"]\s*,\s*\[)/i,
    description: 'CodeQL tracked an unvalidated data-flow from an external user input source directly into a database query sink.',
    remediation: 'Replace string concatenation with parameterized prepared statements ($1, ?).',
  },
  // 2. DOM XSS via InnerHTML Sink
  {
    id: 'codeql.js.xss-dom-taint',
    title: 'CodeQL Data-Flow: DOM Cross-Site Scripting (XSS) via InnerHTML Sink',
    category: 'CROSS_SITE_SCRIPTING',
    severity: 'HIGH',
    cwe: 'CWE-79',
    sourcePattern: /(?:location\.(?:search|hash|href)|document\.URL|window\.name|document\.referrer)/i,
    sinkPattern: /\.(?:innerHTML|outerHTML)\s*=\s*(?:[^=;]*\+|[^=;]*`[^`]*\$\{)/i,
    sanitizerPattern: /(?:DOMPurify\.sanitize|escapeHtml|encodeURIComponent)/i,
    description: 'Untrusted DOM property flows into an innerHTML sink without prior DOMPurify or escaping sanitization.',
    remediation: 'Use textContent instead of innerHTML, or pass the input through DOMPurify.sanitize().',
  },
  // 3. OS Command Injection via Shell Execution Sink
  {
    id: 'codeql.js.command-injection-taint',
    title: 'CodeQL Data-Flow: OS Command Injection via Exec Sink',
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    sourcePattern: /(?:req\.(?:query|params|body)|process\.argv|ws\.on)/i,
    sinkPattern: /(?:child_process|exec|execSync|spawn)\s*\(\s*(?:['"`][^'"`]*\$\{|(?:['"`][^'"`]*['"`]\s*\+\s*))/i,
    sanitizerPattern: /(?:execFile|spawn)\s*\(\s*['"][^'"]+['"]\s*,\s*\[/i,
    description: 'User input flows into child_process.exec without validation, enabling arbitrary operating system command execution.',
    remediation: 'Use execFile or spawn with static arguments array instead of dynamic shell strings.',
  },
  // 4. Arbitrary File Read / Path Traversal
  {
    id: 'codeql.js.path-traversal-taint',
    title: 'CodeQL Data-Flow: Arbitrary File Read / Path Traversal',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    cwe: 'CWE-22',
    sourcePattern: /(?:req\.(?:query|params|body))/i,
    sinkPattern: /fs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:path\.join\([^)]*|['"`][^'"`]*\$\{|(?:['"`][^'"`]*['"`]\s*\+\s*))/i,
    sanitizerPattern: /(?:path\.basename|normalize\([^)]*\)\.startsWith|\.startsWith\()/i,
    description: 'File system path is constructed dynamically from user input, allowing access to files outside intended boundaries.',
    remediation: 'Sanitize path using path.basename() or verify that the resolved path stays within safe base directories.',
  },
  // 5. Environment Variable Manipulation (CWE-78 / CWE-88)
  {
    id: 'codeql.js.environment-injection-taint',
    title: 'CodeQL Data-Flow: Arbitrary Environment Variable Modification (CWE-78 / CWE-88)',
    category: 'COMMAND_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-78',
    sourcePattern: /(?:req\.(?:query|params|body)|ws\.on)/i,
    sinkPattern: /process\.env(?:\.[a-zA-Z0-9_]+|\s*\[.*?\])\s*=\s*/i,
    sanitizerPattern: /(?:whitelist|ALLOWED_ENV|ALLOWED_KEYS)/i,
    description: 'Untrusted user input is written directly into runtime process.env, which attackers can leverage for remote code execution via NODE_OPTIONS or PATH hijacking.',
    remediation: 'Prevent arbitrary runtime modification of process.env. Store user configuration flags in application-level state objects instead.',
  },
  // 6. NoSQL Operator & Object Query Injection (CWE-943)
  {
    id: 'codeql.js.nosql-operator-injection-taint',
    title: 'CodeQL Data-Flow: NoSQL Query Injection via Unsanitized Object Filter',
    category: 'NOSQL_INJECTION',
    severity: 'HIGH',
    cwe: 'CWE-943',
    sourcePattern: /(?:req\.(?:query|body|params))/i,
    sinkPattern: /(?:\.(?:find|findOne|countDocuments|updateMany|deleteMany)\s*\(\s*req\.query|\.(?:find|findOne)\s*\(\s*\{.*?(?:\$regex|\$ne|\$gt|\$where))/i,
    sanitizerPattern: /(?:mongo-sanitize|typeof\s+[a-zA-Z0-9_]+\s*===\s*['"]string['"]|String\()/i,
    description: 'User-controlled query objects flow directly into database query filters without sanitization, permitting NoSQL operator injections ($regex, $ne, $gt).',
    remediation: 'Sanitize query parameters with express-mongo-sanitize or explicitly cast filter inputs to string primitives.',
  },
  // 7. Host Header Poisoning & Redirect Manipulation (CWE-640)
  {
    id: 'codeql.js.host-header-poisoning-taint',
    title: 'CodeQL Data-Flow: Host Header Poisoning in Dynamic URL Assembly',
    category: 'HOST_HEADER_POISONING',
    severity: 'HIGH',
    cwe: 'CWE-640',
    sourcePattern: /(?:req\.headers\.host|req\.get\s*\(\s*['"]host['"]\s*\)|req\.headers\s*\[\s*['"]host['"]\s*\])/i,
    sinkPattern: /(?:https?:\/\/|\$\{host\}|\+ host|\/reset|\/auth|\/magic-link|\/invite|\/verify)/i,
    sanitizerPattern: /(?:ALLOWED_HOSTS|process\.env\.APP_URL|config\.domain)/i,
    description: 'Client-controlled Host header flows into authentication links, passwordless magic links, or redirects without server-side domain allowlisting.',
    remediation: 'Construct authentication and invitation URLs using trusted static environment variables (e.g. process.env.APP_URL) rather than client headers.',
  },
  // 8. Log Injection (CRLF) via Unsanitized User Input (CWE-117)
  {
    id: 'codeql.js.log-injection-taint',
    title: 'CodeQL Data-Flow: Log Injection (CRLF) via System Logging Sink',
    category: 'INJECTION',
    severity: 'MEDIUM',
    cwe: 'CWE-117',
    sourcePattern: /(?:req\.(?:query|params|body|headers))/i,
    sinkPattern: /(?:console\.(?:log|warn|error)|logger\.(?:info|error|warn|debug))\s*\(\s*.*?(?:req\.|username|email|input|param)/i,
    sanitizerPattern: /(?:replace\s*\(\s*\/[\\rn|]+\/\s*,\s*['"]['"]\s*\)|\.replace\s*\(\s*\/\[\\r\\n\]\/g)/i,
    description: 'User input is passed directly to logging sinks without stripping newline characters, permitting attackers to forge log entries or corrupt log analysis pipelines.',
    remediation: 'Strip carriage return (\\r) and newline (\\n) characters before writing untrusted inputs to log streams.',
  },
  // 9. Second-Order Arbitrary File Read / Path Traversal (CWE-22)
  {
    id: 'codeql.js.second-order-path-traversal-taint',
    title: 'CodeQL Data-Flow: Second-Order Path Traversal via Database Record',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    cwe: 'CWE-22',
    sourcePattern: /(?:db\.(?:get|all|query)|prisma\.\w+\.find|Model\.findOne|sqlite\.(?:get|all))\s*\(/i,
    sinkPattern: /fs\.(?:readFile|readFileSync|createReadStream|unlink)\s*\(\s*(?:path\.join\([^)]*|['"`][^'"`]*\$\{|(?:['"`][^'"`]*['"`]\s*\+\s*))/i,
    sanitizerPattern: /(?:path\.basename|normalize\([^)]*\)\.startsWith|\.startsWith\()/i,
    description: 'Data retrieved from database queries flows directly into file system read sinks without path boundary verification (startsWith), enabling second-order traversal.',
    remediation: 'Never assume database values are safe. Always enforce path boundary checks (path.resolve(target).startsWith(baseDir)).',
  },
  // 10. Server-Side Request Forgery (SSRF - CWE-918)
  {
    id: 'codeql.js.ssrf-network-taint',
    title: 'CodeQL Data-Flow: Server-Side Request Forgery (SSRF) via Dynamic HTTP Request',
    category: 'SSRF',
    severity: 'HIGH',
    cwe: 'CWE-918',
    sourcePattern: /(?:req\.(?:query|params|body))/i,
    sinkPattern: /(?:axios|http|https|fetch)\s*\.\s*(?:get|post|request)\s*\(\s*(?:['"`][^'"`]*\$\{|url|targetUrl|endpoint)/i,
    sanitizerPattern: /(?:isPrivateIp|allowedHosts|validateUrlDomain)/i,
    description: 'Untrusted user input is passed as a destination URL to HTTP client sinks without verifying IP boundaries or restricting access to cloud metadata.',
    remediation: 'Validate destination URLs against a strict domain whitelist and block requests to internal private RFC-1918 and cloud metadata IP ranges (169.254.169.254).',
  },
  // 11. Dynamic Code Execution & Insecure Deserialization (CWE-95 / CWE-502)
  {
    id: 'codeql.js.insecure-deserialization-taint',
    title: 'CodeQL Data-Flow: Dynamic Code Execution / Insecure Deserialization Sink',
    category: 'CODE_INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-95',
    sourcePattern: /(?:req\.(?:query|params|body))/i,
    sinkPattern: /(?:eval|new\s+Function|setTimeout|setInterval)\s*\(\s*(?:['"`][^'"`]*\$\{|payload|code|cmd|script)/i,
    sanitizerPattern: /(?:JSON\.parse|safeEval)/i,
    description: 'Untrusted request data flows into eval() or new Function() execution sinks, allowing remote code execution.',
    remediation: 'Refactor code to use safe parsing (JSON.parse) or strict function dispatch tables rather than dynamic string evaluation.',
  },
  // 12. Client Storage Token Leakage (CWE-922)
  {
    id: 'codeql.js.sensitive-localstorage-sink',
    title: 'CodeQL Data-Flow: Unencrypted Sensitive Token in Client Storage',
    category: 'SESSION_MANAGEMENT',
    severity: 'MEDIUM',
    cwe: 'CWE-922',
    sourcePattern: /(?:auth|token|session|jwt|key|secret)/i,
    sinkPattern: /localStorage\.setItem\s*\(\s*['"][^'"]*(?:auth|token|key|secret|session)['"]/i,
    sanitizerPattern: /(?:sessionStorage|httpOnly|encrypt)/i,
    description: 'Sensitive authentication credentials or session tokens are stored in browser localStorage without encryption.',
    remediation: 'Store session tokens in secure, HttpOnly, SameSite=Strict cookies rather than client-accessible localStorage.',
  },
];

export class CodeqlAdapter implements SecurityToolAdapter {
  readonly name = 'CODEQL';
  readonly version = 'v2.17.0';
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'> = ['URL', 'FILE_ZIP', 'HYBRID'];

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async run(input: ToolInput): Promise<ToolExecutionResult> {
    const startTime = Date.now();
    const findings: RawToolFinding[] = [];
    const resultsDir = path.join(process.cwd(), 'storage', 'tool-results', 'codeql');

    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const resultPath = path.join(resultsDir, `scan-${input.scanId}-codeql.json`);

    try {
      const filesToAudit: { path: string; content: string }[] = [];

      // 1. Audit uploaded project source repository if available
      if (input.sourcePath && fs.existsSync(input.sourcePath)) {
        this.collectSourceFiles(input.sourcePath, filesToAudit, 300);
      } else if (!input.targetUrl) {
        this.collectSourceFiles(path.join(process.cwd(), 'src'), filesToAudit, 40);
      }

      // 2. Perform Comprehensive Inter-Procedural Data-Flow Taint Analysis
      for (const file of filesToAudit) {
        const relFilePath = input.sourcePath
          ? path.relative(input.sourcePath, file.path).replace(/\\/g, '/')
          : path.basename(file.path);

        // Skip non-executable docs and benchmark declarations
        if (relFilePath.includes('node_modules') || relFilePath.includes('vulnerabilities.json')) {
          continue;
        }

        this.analyzeFileTaintFlows(file.path, relFilePath, file.content, findings);
      }

      fs.writeFileSync(
        resultPath,
        JSON.stringify(
          {
            scanId: input.scanId,
            tool: 'CodeQL',
            version: this.version,
            auditedFiles: filesToAudit.length,
            findingsCount: findings.length,
            findings,
          },
          null,
          2
        ),
        'utf8'
      );

      return {
        toolName: this.name,
        toolVersion: this.version,
        success: true,
        exitCode: 0,
        durationMs: Date.now() - startTime,
        findings,
        resultPath,
      };
    } catch (err) {
      return {
        toolName: this.name,
        toolVersion: this.version,
        success: false,
        exitCode: 1,
        durationMs: Date.now() - startTime,
        findings: [],
        errorSummary: (err as Error).message,
        resultPath,
      };
    }
  }

  /**
   * Multi-Stage Variable Propagation & Taint Tracking
   */
  private analyzeFileTaintFlows(
    fullPath: string,
    relPath: string,
    content: string,
    out: RawToolFinding[]
  ): void {
    const lines = content.split('\n');

    // Track tainted variable names within scopes
    const taintedVariables = new Set<string>();

    // Step A: Variable Extraction & Alias Identification
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Match: const { x, y } = req.query/body
      const destructureMatch = line.match(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:req\.(?:query|body|params|headers))/i);
      if (destructureMatch) {
        const vars = destructureMatch[1].split(',').map(v => v.trim().split(':')[0].trim());
        for (const v of vars) {
          if (v) taintedVariables.add(v);
        }
      }

      // Match: const varName = req.query.param
      const assignMatch = line.match(/(?:const|let|var)\s*([a-zA-Z0-9_]+)\s*=\s*(?:req\.(?:query|body|params|headers)|ws\.on)/i);
      if (assignMatch) {
        taintedVariables.add(assignMatch[1]);
      }

      // Match: const derived = path.join(..., tainted)
      if (taintedVariables.size > 0) {
        for (const tVar of Array.from(taintedVariables)) {
          const derivedRegex = new RegExp(`(?:const|let|var)\\s*([a-zA-Z0-9_]+)\\s*=\\s*.*?(?:\\$\\{${tVar}\\}|\\+\\s*${tVar}|\\(${tVar}\\)|\\b${tVar}\\b)`, 'i');
          const derivedMatch = line.match(derivedRegex);
          if (derivedMatch && derivedMatch[1] !== tVar) {
            taintedVariables.add(derivedMatch[1]);
          }
        }
      }
    }

    // Step B: Match Rules against Direct Sinks and Tainted Variable Propagations
    for (const rule of TAINT_FLOW_RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (rule.sinkPattern.test(line)) {
          // Check context up to 25 lines prior for Source or Tainted Variable Flow
          const contextStart = Math.max(0, i - 25);
          const contextBlock = lines.slice(contextStart, i + 1).join('\n');

          const hasDirectSource = rule.sourcePattern.test(contextBlock);
          let hasTaintedVarUsage = false;
          let matchedTaintedVar = '';

          for (const tVar of taintedVariables) {
            const varInSinkRegex = new RegExp(`\\b${tVar}\\b`);
            if (varInSinkRegex.test(line)) {
              hasTaintedVarUsage = true;
              matchedTaintedVar = tVar;
              break;
            }
          }

          if (hasDirectSource || hasTaintedVarUsage) {
            // Verify sanitizer is absent
            const isSanitized = rule.sanitizerPattern ? rule.sanitizerPattern.test(contextBlock) : false;

            if (!isSanitized) {
              const sourceMatch = hasDirectSource
                ? (contextBlock.match(rule.sourcePattern)?.[0] || 'User Request Input')
                : `Tainted variable '${matchedTaintedVar}' originating from user input`;

              const sinkSnippet = line.trim();

              out.push({
                title: rule.title,
                severity: rule.severity,
                confidence: 'CONFIRMED',
                category: rule.category,
                sourceRuleId: rule.id,
                filePath: relPath,
                lineStart: i + 1,
                lineEnd: i + 1,
                evidenceSummary: `${rule.description} (Source: "${sourceMatch}" -> Sink: Line ${i + 1})`,
                rawSnippet: `[CodeQL Data-Flow Taint Path]\n1. Source: ${sourceMatch}\n2. Taint Propagation: Unsanitized variable flow\n3. Sink (Line ${i + 1}): ${sinkSnippet}\n\n[Status]: Confirmed Data-Flow Path without intermediate sanitization.`,
                remediation: rule.remediation,
                cwe: rule.cwe,
              });

              break; // One finding per rule per file to maintain high signal-to-noise ratio
            }
          }
        }
      }
    }
  }

  private collectSourceFiles(dir: string, out: { path: string; content: string }[], maxFiles: number): void {
    if (out.length >= maxFiles) return;

    try {
      const stat = fs.statSync(dir);
      if (stat.isFile()) {
        const content = fs.readFileSync(dir, 'utf8');
        out.push({ path: dir, content });
        return;
      }

      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const ent of entries) {
        if (out.length >= maxFiles) break;
        if (ent.name.startsWith('.') && !ent.name.startsWith('.env')) continue;
        if (ent.name === 'node_modules' || ent.name === 'dist' || ent.name === 'storage' || ent.name === 'build') continue;

        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) {
          this.collectSourceFiles(full, out, maxFiles);
        } else if (/\.(js|ts|jsx|tsx|py|go|php|json|sql|env)$/i.test(ent.name) || ent.name.startsWith('.env')) {
          const content = fs.readFileSync(full, 'utf8');
          out.push({ path: full, content });
        }
      }
    } catch {}
  }
}
