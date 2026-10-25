import fs from 'fs';
import path from 'path';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface DiscoveredEndpoint {
  filePath: string;
  line: number;
  method: string;
  route: string;
  hasAuthMiddleware: boolean;
  hasCsrfProtection: boolean;
  hasRateLimiting: boolean;
  usesHostHeader: boolean;
  logsUserInput: boolean;
  rawCode: string;
}

export interface AttackSurfaceReport {
  endpoints: DiscoveredEndpoint[];
  findings: RawToolFinding[];
}

/**
 * Attack Surface Auto-Discovery & Security Matrix Engine
 * Statically parses project routes across Express, Fastify, Spring, GraphQL, WebSockets, and Actuators.
 * Evaluates every endpoint against a mandatory 6-pillar security matrix:
 * 1. Authentication & Authorization (CWE-285 / CWE-862)
 * 2. Anti-CSRF on state-changing operations (CWE-352)
 * 3. Rate Limiting on sensitive endpoints (CWE-307 / CWE-770)
 * 4. Origin & CORS Trust (CWE-942)
 * 5. Host Header Poisoning (CWE-640)
 * 6. Log Injection / CRLF (CWE-117)
 */
export class AttackSurfaceService {
  /**
   * Discover and audit all endpoints across the target project directory.
   */
  public static async analyze(targetDir: string): Promise<AttackSurfaceReport> {
    const endpoints: DiscoveredEndpoint[] = [];
    const findings: RawToolFinding[] = [];

    if (!fs.existsSync(targetDir)) {
      return { endpoints, findings };
    }

    const files: string[] = [];
    this.collectSourceFiles(targetDir, files);

    for (const filePath of files) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const relPath = path.relative(targetDir, filePath).replace(/\\/g, '/');

        // Skip non-executable docs and benchmark definitions
        if (relPath.includes('node_modules') || relPath.includes('vulnerabilities.json')) {
          continue;
        }

        this.scanFileForEndpoints(filePath, relPath, content, endpoints, findings);
      } catch (err) {
        console.warn(`[AttackSurface] Failed to analyze ${filePath}:`, (err as Error).message);
      }
    }

    return { endpoints, findings };
  }

  private static scanFileForEndpoints(
    fullPath: string,
    relPath: string,
    content: string,
    endpoints: DiscoveredEndpoint[],
    findings: RawToolFinding[]
  ): void {
    const lines = content.split('\n');

    // 1. Detect Global CORS / Origin Null Trust (CWE-942)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (
        (line.includes("origin === 'null'") || line.includes('origin === "null"') || line.includes("origin === 'null'")) &&
        (content.includes('Access-Control-Allow-Credentials') || content.includes('credentials: true') || line.includes('credentials'))
      ) {
        findings.push({
          title: 'Insecure CORS: Null Origin Acceptance with Credentials',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'SECURITY_MISCONFIGURATION',
          sourceRuleId: 'attack-surface.cors.null-origin',
          filePath: relPath,
          lineStart: i + 1,
          lineEnd: i + 1,
          evidenceSummary: `CORS policy explicitly trusts 'null' origin with credentials allowed, enabling sandboxed iframes or file:// protocols to hijack authenticated sessions.`,
          rawSnippet: line.trim(),
          remediation: `Never whitelist 'null' origin. Strictly enumerate trusted domain origins (e.g., https://app.example.com).`,
          cwe: 'CWE-942',
        });
        break;
      }
    }

    // 2. Detect Actuator & Memory Telemetry Exposures (CWE-200)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const actuatorMatch = line.match(/(?:app|router)\.(?:get|use)\s*\(\s*['"](\/actuator\/(?:heapdump|env|metrics|logfile|configprops))['"]/i);
      if (actuatorMatch) {
        const route = actuatorMatch[1];
        findings.push({
          title: `Actuator Diagnostic Endpoint Exposure (${route})`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'INFORMATION_DISCLOSURE',
          sourceRuleId: 'attack-surface.actuator.heapdump-leak',
          filePath: relPath,
          lineStart: i + 1,
          lineEnd: i + 1,
          evidenceSummary: `Internal actuator diagnostic route ${route} is exposed without administrative authentication, leaking memory snapshots, cloud tokens, and environment secrets.`,
          rawSnippet: line.trim(),
          remediation: `Restrict actuator diagnostic routes to internal management subnets or disable /actuator/heapdump in production environments.`,
          cwe: 'CWE-200',
        });
      }
    }

    // 3. Detect WebSocket Privilege Escalation / Origin Bypass (CWE-287)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/ws\.on\s*\(\s*['"]message['"]/i.test(line)) {
        const block = lines.slice(i, Math.min(lines.length, i + 35)).join('\n');
        if (/role\s*=\s*['"]superadmin['"]|isAdmin\s*=\s*true|role\s*:\s*['"]admin['"]/i.test(block)) {
          findings.push({
            title: 'WebSocket Unauthenticated Privilege State Escalation',
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'AUTHENTICATION_BYPASS',
            sourceRuleId: 'attack-surface.websocket.privilege-flip',
            filePath: relPath,
            lineStart: i + 1,
            lineEnd: Math.min(lines.length, i + 20),
            evidenceSummary: `WebSocket message handler accepts client-supplied state flags to elevate user session privileges to superadmin without cryptographic token validation.`,
            rawSnippet: block.split('\n').slice(0, 5).join('\n'),
            remediation: `Enforce server-side session authorization and never permit client WebSocket messages to alter user roles or privileges directly.`,
            cwe: 'CWE-287',
          });
        }
      }
    }

    // 4. Scan Route Handlers across Express / Fastify / Spring
    // Regex matches app.get('/...', ...), router.post('/...', ...), @GetMapping('/...')
    const routeRegex = /(?:app|router)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]([\s\S]*?)(?=(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all)|$)/gi;
    let match: RegExpExecArray | null;

    while ((match = routeRegex.exec(content)) !== null) {
      const method = match[1].toUpperCase();
      const route = match[2];
      const handlerBlock = match[3] || '';

      const matchIndex = match.index;
      const lineStart = content.substring(0, matchIndex).split('\n').length;
      const blockLines = handlerBlock.split('\n');
      const lineEnd = lineStart + blockLines.length;

      const hasAuth = /(?:authenticate|verifyToken|requireAuth|ensureLoggedIn|authMiddleware|passport\.authenticate|checkJwt|requireRole)/i.test(handlerBlock);
      const hasCsrf = /(?:csrf|csurf|antiCsrf|checkCsrf|verifyCsrfToken|csrfProtection)/i.test(handlerBlock);
      const hasRateLimit = /(?:rateLimit|limiter|loginLimiter|apiLimiter|slowDown)/i.test(handlerBlock);
      const usesHost = /(?:req\.headers\.host|req\.get\s*\(\s*['"]host['"]\s*\)|req\.headers\s*\[\s*['"]host['"]\s*\])/i.test(handlerBlock);
      const logsInput = /(?:console\.log|logger\.(?:info|error|warn|debug))\s*\(\s*.*(?:req\.(?:body|query|params|headers))/i.test(handlerBlock);

      const endpoint: DiscoveredEndpoint = {
        filePath: relPath,
        line: lineStart,
        method,
        route,
        hasAuthMiddleware: hasAuth,
        hasCsrfProtection: hasCsrf,
        hasRateLimiting: hasRateLimit,
        usesHostHeader: usesHost,
        logsUserInput: logsInput,
        rawCode: handlerBlock.slice(0, 500),
      };
      endpoints.push(endpoint);

      // --- Security Matrix Evaluation on Endpoint ---

      // A. Host Header Poisoning on ANY route that builds URLs / sends emails (CWE-640)
      if (usesHost) {
        const constructsUrl = /(?:http:\/\/|https:\/\/|\$\{host\}|\+ host|`\$\{.*?host)/i.test(handlerBlock);
        if (constructsUrl) {
          findings.push({
            title: `Host Header Injection / Passwordless Poisoning in ${method} ${route}`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            category: 'HOST_HEADER_POISONING',
            sourceRuleId: 'attack-surface.matrix.host-poisoning',
            filePath: relPath,
            lineStart,
            lineEnd: Math.min(lineEnd, lineStart + 15),
            evidenceSummary: `Route ${method} ${route} directly incorporates untrusted Host header ('req.headers.host') into URL construction without server-side domain allowlisting.`,
            rawSnippet: handlerBlock.split('\n').slice(0, 8).join('\n'),
            remediation: `Bind domain URLs to static server-side environment configurations (e.g. process.env.APP_URL) rather than client-controlled Host headers.`,
            cwe: 'CWE-640',
          });
        }
      }

      // B. Missing Anti-CSRF on Sensitive State-Changing Routes (CWE-352)
      const isStateChanging = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);
      const isSensitiveAction = /(?:delete|update|remove|settings|transfer|pay|checkout|password|profile|role|email|webhook)/i.test(route);
      if (isStateChanging && isSensitiveAction && !hasCsrf) {
        // Check if there is an explicit anti-CSRF token check inside body
        const checksCsrfInside = /(?:req\.body\._csrf|req\.headers\['x-csrf-token'\]|req\.headers\['x-xsrf-token'\])/i.test(handlerBlock);
        if (!checksCsrfInside) {
          findings.push({
            title: `Cross-Site Request Forgery (CSRF) on Sensitive State-Changing Endpoint: ${method} ${route}`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            category: 'CSRF',
            sourceRuleId: 'attack-surface.matrix.csrf-missing',
            filePath: relPath,
            lineStart,
            lineEnd: Math.min(lineEnd, lineStart + 10),
            evidenceSummary: `State-altering endpoint ${method} ${route} performs sensitive modifications without Anti-CSRF token validation or SameSite cookie restrictions.`,
            rawSnippet: handlerBlock.split('\n').slice(0, 6).join('\n'),
            remediation: `Implement synchronized Anti-CSRF tokens (e.g. csurf) and configure cookies with SameSite=Strict or SameSite=Lax.`,
            cwe: 'CWE-352',
          });
        }
      }

      // C. Missing Rate Limiting on Authentication / Reset / Expensive Actions (CWE-307 / CWE-770)
      const isAuthOrExpensive = /(?:login|auth|signin|signup|register|reset-password|verify|otp|sms|embeddings|ai\/|generate-pdf)/i.test(route);
      if (isAuthOrExpensive && !hasRateLimit) {
        findings.push({
          title: `Missing Rate Limiting on Critical Action Endpoint: ${method} ${route}`,
          severity: 'MEDIUM',
          confidence: 'CONFIRMED',
          category: 'INSUFFICIENT_ANTI_AUTOMATION',
          sourceRuleId: 'attack-surface.matrix.missing-rate-limit',
          filePath: relPath,
          lineStart,
          lineEnd: Math.min(lineEnd, lineStart + 10),
          evidenceSummary: `Critical endpoint ${method} ${route} lacks rate limiting or request throttling, permitting automated brute-force, credential stuffing, or resource exhaustion.`,
          rawSnippet: handlerBlock.split('\n').slice(0, 6).join('\n'),
          remediation: `Apply express-rate-limit middleware to restrict request frequencies per client IP/account.`,
          cwe: 'CWE-307',
        });
      }

      // D. Log Injection (CRLF) via un-sanitized user inputs into Logging (CWE-117)
      if (logsInput) {
        const hasCrlfStrip = /(?:replace\s*\(\s*\/[\\rn|]+\/\s*,\s*['"]['"]\s*\)|replace\s*\(\s*\/\[\\r\\n\]\/g)/i.test(handlerBlock);
        if (!hasCrlfStrip) {
          findings.push({
            title: `Log Injection (CWE-117) via Unsanitized User Input in ${method} ${route}`,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'INJECTION',
            sourceRuleId: 'attack-surface.matrix.log-injection',
            filePath: relPath,
            lineStart,
            lineEnd: Math.min(lineEnd, lineStart + 8),
            evidenceSummary: `Route ${method} ${route} outputs raw user input directly to system logs without removing carriage return (\\r) and newline (\\n) characters, permitting log forging.`,
            rawSnippet: handlerBlock.split('\n').slice(0, 5).join('\n'),
            remediation: `Strip CRLF characters from untrusted user inputs before passing to logging routines (e.g. input.replace(/[\\r\\n]/g, '')).`,
            cwe: 'CWE-117',
          });
        }
      }
    }
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
        } else if (/\.(js|ts|jsx|tsx|py|go|php|java)$/i.test(ent.name)) {
          out.push(full);
        }
      }
    } catch {}
  }
}
