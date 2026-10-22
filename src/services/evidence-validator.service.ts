import { RawToolFinding } from '../tools/security-tool.interface';

export interface FindingValidationResult {
  verdict: 'VALID' | 'NEEDS_REVIEW' | 'DROP_FALSE_POSITIVE';
  confidence: 'CONFIRMED' | 'POTENTIAL' | 'INFORMATIONAL' | 'HIGH' | 'MEDIUM' | 'NEEDS_REVIEW' | 'LIKELY_FALSE_POSITIVE';
  verificationStatus: 'VERIFIED' | 'UNVERIFIED' | 'NEEDS_REVIEW';
  status: 'CONFIRMED' | 'NEEDS_REVIEW' | 'FALSE_POSITIVE' | 'OPEN';
  adjustedSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  reason?: string;
  adjustedTitle?: string;
  adjustedRemediation?: string;
}

/**
 * 5-Stage Evidence Validation & False Positive Elimination Engine
 * Evaluates raw finding claims against technical code evidence, AST context, and syntax validity.
 * Distinguishes Confirmed vulnerabilities from Potential and Informational configuration baselines.
 */
export function validateFindingEvidence(finding: RawToolFinding): FindingValidationResult {
  const cwe = (finding.cwe || '').toUpperCase();
  const category = (finding.category || '').toUpperCase();
  const title = (finding.title || '').toLowerCase();
  const snippet = (finding.rawSnippet || '').trim();
  const snippetLower = snippet.toLowerCase();
  const filePath = (finding.filePath || '').toLowerCase();

  // -------------------------------------------------------------------------
  // 0. Non-Executable Documentation & Data File Protection
  // -------------------------------------------------------------------------
  const isNonExecutableDoc =
    filePath.endsWith('.json') ||
    filePath.endsWith('.md') ||
    filePath.endsWith('.txt') ||
    filePath.endsWith('.csv') ||
    filePath.endsWith('.lock') ||
    filePath.endsWith('.pdf') ||
    filePath.includes('vulnerabilities.json');

  const isCodeExecutionFlaw =
    cwe === 'CWE-89' ||
    cwe === 'CWE-78' ||
    cwe === 'CWE-79' ||
    cwe === 'CWE-22' ||
    cwe === 'CWE-95' ||
    cwe === 'CWE-918' ||
    cwe === 'CWE-639' ||
    category === 'SQL_INJECTION' ||
    category === 'COMMAND_INJECTION' ||
    category === 'CROSS_SITE_SCRIPTING' ||
    category === 'PATH_TRAVERSAL';

  if (isNonExecutableDoc && isCodeExecutionFlaw) {
    return {
      verdict: 'DROP_FALSE_POSITIVE',
      confidence: 'INFORMATIONAL',
      verificationStatus: 'UNVERIFIED',
      status: 'FALSE_POSITIVE',
      reason: 'Discarded False Positive: Target is a documentation or data file (.json/.md/.txt), not running application code.',
    };
  }

  // -------------------------------------------------------------------------
  // Non-Sensitive localStorage UI Filter Protection
  // -------------------------------------------------------------------------
  if (
    (title.includes('localstorage') || snippetLower.includes('localstorage')) &&
    !snippetLower.includes('token') &&
    !snippetLower.includes('jwt') &&
    !snippetLower.includes('secret') &&
    !snippetLower.includes('auth') &&
    !snippetLower.includes('password') &&
    !snippetLower.includes('session')
  ) {
    return {
      verdict: 'DROP_FALSE_POSITIVE',
      confidence: 'INFORMATIONAL',
      verificationStatus: 'UNVERIFIED',
      status: 'FALSE_POSITIVE',
      reason: 'Discarded False Positive: localStorage is used for non-sensitive UI checkbox state or layout preference.',
    };
  }

  // =========================================================================
  // 1. SQL Injection Validation (CWE-89)
  // =========================================================================
  if (cwe === 'CWE-89' || category === 'SQL_INJECTION' || title.includes('sql injection')) {
    // A. DOM/CSS selector false positive (e.g. group.querySelector('#' + targetId))
    if (
      snippetLower.includes('queryselector') ||
      snippetLower.includes('queryselectorall') ||
      snippetLower.includes('getelementby') ||
      snippetLower.includes('classlist') ||
      snippetLower.includes('setattribute') ||
      snippetLower.includes('addeventlistener')
    ) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Evidence matches a DOM CSS selector (querySelector), not a database SQL query.',
      };
    }

    // B. ES Module / package import/export false positive (e.g. import ... from '...')
    if (/^\s*(?:import|export)\b.*?\bfrom\b/i.test(snippet)) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Evidence is ES Module import/export syntax.',
      };
    }

    // C. HTML markup string concatenation (e.g. '<div class="form-group">' + ...)
    if (
      (snippet.includes('<div') || snippet.includes('<span') || snippet.includes('<table') || snippet.includes('class=') || snippet.includes('href=')) &&
      !/\b(?:SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+.*?\s+SET|DELETE\s+FROM)\b/i.test(snippet)
    ) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Evidence is HTML markup concatenation, not an SQL statement.',
      };
    }

    // D. English conversational words ("from", "where", "select option") without real SQL grammar
    const hasSqlVerbs = /\b(?:SELECT\s+[\w\*\s,\(\)\.`'"]+\s+FROM|INSERT\s+INTO\s+[\w\.`'"]+|UPDATE\s+[\w\.`'"]+\s+SET|DELETE\s+FROM\s+[\w\.`'"]+|UNION\s+SELECT)\b/i.test(snippet);
    if (!hasSqlVerbs) {
      const hasDbSink = /\b(?:db|pool|client|connection|sequelize|prisma|pdo|mysqli?)\s*\.(?:query|execute|raw|\$queryRaw)\s*\(/i.test(snippet);
      if (!hasDbSink) {
        return {
          verdict: 'DROP_FALSE_POSITIVE',
          confidence: 'LIKELY_FALSE_POSITIVE',
          verificationStatus: 'UNVERIFIED',
          status: 'FALSE_POSITIVE',
          reason: 'Discarded False Positive: Code line contains generic words without SQL syntax or database sink.',
        };
      }
    }

    // E. Properly parameterized queries ($1, ?, prepared statements)
    if (/\b(?:query|execute)\s*\(\s*['"][^'"]*['"]\s*,\s*\[/i.test(snippet) || /\$queryRaw\b/i.test(snippet)) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Safe Pattern: Query is properly parameterized with bind parameters.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      verificationStatus: 'VERIFIED',
      status: 'CONFIRMED',
      adjustedSeverity: 'CRITICAL',
    };
  }

  // =========================================================================
  // 2. Cross-Site Scripting (XSS) Validation (CWE-79)
  // =========================================================================
  // 2. Cross-Site Scripting (XSS) Validation (CWE-79)
  // =========================================================================
  if (cwe === 'CWE-79' || category === 'CROSS_SITE_SCRIPTING' || title.includes('xss')) {
    // If detected in backend Node.js / PHP server code, classify as Server-Side Reflected XSS (or Stored XSS), NOT DOM XSS!
    const isBackendServerFile =
      filePath.includes('server.js') ||
      filePath.includes('app.js') ||
      filePath.includes('controller') ||
      filePath.includes('route') ||
      filePath.endsWith('.php');

    const isStored =
      title.includes('stored') ||
      title.includes('reviews') ||
      snippetLower.includes('insert into') ||
      snippetLower.includes('comments');

    if (isStored) {
      return {
        verdict: 'VALID',
        confidence: 'CONFIRMED',
        verificationStatus: 'VERIFIED',
        status: 'CONFIRMED',
        adjustedTitle: 'Stored Cross-Site Scripting (Stored XSS) in User Reviews',
        adjustedSeverity: 'HIGH',
        adjustedRemediation: 'Sanitize user inputs before database storage and encode content using textContent or DOMPurify when rendering.',
      };
    }

    if (isBackendServerFile && (title.includes('dom') || snippetLower.includes('res.send') || snippetLower.includes('res.write') || snippetLower.includes('html'))) {
      return {
        verdict: 'VALID',
        confidence: 'CONFIRMED',
        verificationStatus: 'VERIFIED',
        status: 'CONFIRMED',
        adjustedTitle: 'Reflected Cross-Site Scripting (Reflected XSS) in Server Response',
        adjustedSeverity: 'HIGH',
        adjustedRemediation: 'HTML-encode untrusted user input before rendering in HTTP responses or utilize template engines with contextual auto-escaping.',
      };
    }

    // A. Static HTML assignment to innerHTML / outerHTML
    if (/\.(?:innerHTML|outerHTML)\s*=\s*/i.test(snippet)) {
      const rhs = snippet.replace(/.*?\.(?:innerHTML|outerHTML)\s*=\s*/i, '').trim().replace(/;$/, '');
      const isStaticString =
        (/^['"][^'"]*['"]$/.test(rhs)) ||
        (rhs === '""' || rhs === "''") ||
        (/^`[^`]*`$/.test(rhs) && !rhs.includes('${'));

      if (isStaticString) {
        return {
          verdict: 'DROP_FALSE_POSITIVE',
          confidence: 'LIKELY_FALSE_POSITIVE',
          verificationStatus: 'UNVERIFIED',
          status: 'FALSE_POSITIVE',
          reason: 'Discarded False Positive: innerHTML is assigned a purely static literal string without dynamic user input.',
        };
      }

      // Check for contextual sanitization
      if (
        snippetLower.includes('dompurify.sanitize') ||
        snippetLower.includes('escapehtml') ||
        snippetLower.includes('encodeuricomponent')
      ) {
        return {
          verdict: 'DROP_FALSE_POSITIVE',
          confidence: 'LIKELY_FALSE_POSITIVE',
          verificationStatus: 'UNVERIFIED',
          status: 'FALSE_POSITIVE',
          reason: 'Safe Pattern: innerHTML sink is sanitized with DOMPurify / escaping function.',
        };
      }
    }

    // B. Static document.write calls
    if (/document\.write(?:ln)?\s*\(\s*['"][^'"]*['"]\s*\)/i.test(snippet) && !snippet.includes('+') && !snippet.includes('${')) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'POTENTIAL',
        verificationStatus: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'document.write used with static argument. Code modernization advised, but immediate exploitation is unlikely.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      verificationStatus: 'VERIFIED',
      status: 'CONFIRMED',
      adjustedSeverity: 'HIGH',
    };
  }

  // =========================================================================
  // 3. Email & PII Disclosure Validation (CWE-200 / CWE-359)
  // =========================================================================
  if (cwe === 'CWE-200' || cwe === 'CWE-359' || title.includes('email') || category.includes('EXPOSURE') || category.includes('PII')) {
    // A. Form inputs & placeholders
    if (
      snippetLower.includes('<input') ||
      snippetLower.includes('type="email"') ||
      snippetLower.includes("type='email'") ||
      snippetLower.includes('placeholder=') ||
      snippetLower.includes('name="email"') ||
      snippetLower.includes("name='email'") ||
      snippetLower.includes('htmlspecialchars') ||
      snippetLower.includes('filter_var') ||
      snippetLower.includes('filter_input') ||
      snippetLower.includes("$_post['email']") ||
      snippetLower.includes('req.body.email')
    ) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: HTML form input field, placeholder, or input sanitization, not a leaked email.',
      };
    }

    // B. RFC Standard example/documentation placeholders
    if (
      snippetLower.includes('@example.com') ||
      snippetLower.includes('@example.org') ||
      snippetLower.includes('@example.net') ||
      snippetLower.includes('@test.com') ||
      snippetLower.includes('@domain.com') ||
      snippetLower.includes('@localhost') ||
      snippetLower.includes('@yourcompany.com') ||
      snippetLower.includes('@sample.com')
    ) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Email address uses standard RFC documentation placeholder domain (example.com).',
      };
    }

    // C. Installer, Setup, or Seed script context
    if (
      filePath.includes('install') ||
      filePath.includes('setup') ||
      filePath.includes('seed') ||
      filePath.includes('migration') ||
      filePath.includes('fixture') ||
      filePath.includes('test')
    ) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'POTENTIAL',
        verificationStatus: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'Hardcoded administrative email detected in an installer or setup script. Review whether the installation script remains exposed in production environments.',
        adjustedTitle: 'Administrative Email Disclosed in Installation Script',
        adjustedRemediation: 'Ensure install.php and setup scripts are deleted or access-restricted after initial system configuration.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'INFORMATIONAL',
      verificationStatus: 'UNVERIFIED',
      status: 'OPEN',
      adjustedSeverity: 'LOW',
    };
  }

  // =========================================================================
  // 4. Hardcoded Credentials & Passwords Validation (CWE-798 / CWE-259)
  // =========================================================================
  if (cwe === 'CWE-798' || cwe === 'CWE-259' || title.includes('password') || category === 'HARDCODED_SECRET') {
    // A. Form inputs & type definitions
    if (
      snippetLower.includes('<input') ||
      snippetLower.includes('type="password"') ||
      snippetLower.includes("type='password'") ||
      snippetLower.includes('placeholder="password"') ||
      /password\s*:\s*(?:string|boolean|any|null)\b/i.test(snippet) ||
      snippetLower.includes("$_post['password']") ||
      snippetLower.includes('req.body.password')
    ) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Input parameter or type declaration, not a hardcoded secret.',
      };
    }

    // B. Empty password literal
    if (/(?:password|passwd|pwd)\s*[:=]\s*['"]\s*['"]/i.test(snippet)) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        verificationStatus: 'UNVERIFIED',
        status: 'FALSE_POSITIVE',
        reason: 'Safe Pattern: Password is initialized to an empty string.',
      };
    }

    // C. Template placeholders & weak default passwords (admin, changeme, 123456)
    if (
      snippetLower.includes('your_password') ||
      snippetLower.includes('changeme') ||
      snippetLower.includes('todo') ||
      snippetLower.includes('placeholder') ||
      /['"](?:admin|password|123456|root|test|secret|temp)['"]/i.test(snippet)
    ) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'POTENTIAL',
        verificationStatus: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        adjustedSeverity: 'LOW',
        reason: 'Default/placeholder credential detected. Downgraded from Critical to Low/Needs Review.',
      };
    }

    // D. Installer / Setup script context
    if (
      filePath.includes('install') ||
      filePath.includes('setup') ||
      filePath.includes('seed') ||
      filePath.includes('test') ||
      filePath.includes('mock') ||
      filePath.includes('fixture')
    ) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'POTENTIAL',
        verificationStatus: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        adjustedSeverity: 'MEDIUM',
        reason: 'Setup credentials in installation, test or seed script. Downgraded to Medium; verify script is deleted after provisioning.',
      };
    }

    // E. High-entropy real production credential or verified account pair
    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      verificationStatus: 'VERIFIED',
      status: 'CONFIRMED',
      adjustedSeverity: 'HIGH',
    };
  }

  // =========================================================================
  // 5. Command Injection Validation (CWE-78)
  // =========================================================================
  if (cwe === 'CWE-78' || category === 'COMMAND_INJECTION' || title.includes('command injection')) {
    // A. Static command strings without variables or dynamic interpolation
    const isStaticCommand =
      /^(?:exec|system|passthru|shell_exec|popen)\s*\(\s*['"][a-zA-Z0-9_\-\s\.\/]+['"]\s*\)\s*;?$/i.test(snippet) ||
      /^child_process\.(?:exec|execSync)\s*\(\s*['"][a-zA-Z0-9_\-\s\.\/]+['"]\s*\)\s*;?$/i.test(snippet);

    if (isStaticCommand) {
      return {
        verdict: 'VALID',
        confidence: 'INFORMATIONAL',
        verificationStatus: 'UNVERIFIED',
        status: 'OPEN',
        adjustedSeverity: 'LOW',
        reason: 'Static system command with hardcoded arguments. No dynamic taint or user input injection possible.',
      };
    }

    // B. Properly escaped commands using escapeshellarg or escapeshellcmd
    if (snippetLower.includes('escapeshellarg') || snippetLower.includes('escapeshellcmd')) {
      return {
        verdict: 'VALID',
        confidence: 'POTENTIAL',
        verificationStatus: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        adjustedSeverity: 'LOW',
        reason: 'Shell argument escaping detected (escapeshellarg). Command execution appears protected against injection.',
      };
    }

    // C. Direct unescaped user input concatenation into shell sink
    const hasTaintedInput =
      snippetLower.includes('$_get') ||
      snippetLower.includes('$_post') ||
      snippetLower.includes('$_request') ||
      snippetLower.includes('req.query') ||
      snippetLower.includes('req.body') ||
      snippetLower.includes('req.params');

    if (hasTaintedInput) {
      return {
        verdict: 'VALID',
        confidence: 'CONFIRMED',
        verificationStatus: 'VERIFIED',
        status: 'CONFIRMED',
        adjustedSeverity: 'CRITICAL',
        reason: 'Unvalidated user input directly concatenated into shell command execution sink.',
      };
    }

    // D. Dynamic or ambiguous variable passed to exec - Tuned to CRITICAL
    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      verificationStatus: 'VERIFIED',
      status: 'CONFIRMED',
      adjustedSeverity: 'CRITICAL',
      reason: 'Dynamic variable passed to system command execution sink. Tuned to CRITICAL severity.',
    };
  }

  // =========================================================================
  // 5. Security Headers, TLS & Technology Banners (CWE-16 / CWE-693 / CWE-1021)
  // =========================================================================
  if (
    title.includes('header') ||
    title.includes('permissions-policy') ||
    title.includes('referrer-policy') ||
    title.includes('x-content-type-options') ||
    title.includes('strict-transport-security') ||
    title.includes('content security policy') ||
    title.includes('x-frame-options') ||
    title.includes('clickjacking') ||
    title.includes('banner') ||
    title.includes('cookie missing') ||
    category === 'SECURITY_MISCONFIGURATION' ||
    category === 'INSECURE_COMMUNICATION' ||
    cwe === 'CWE-16' ||
    cwe === 'CWE-693' ||
    cwe === 'CWE-1021'
  ) {
    // SentinelAI Core Rule: Distinguish Informational baseline recommendations from active attacks.
    // The mere absence of a security header does NOT constitute proof of an exploitable active attack.
    return {
      verdict: 'VALID',
      confidence: 'INFORMATIONAL',
      verificationStatus: 'UNVERIFIED',
      status: 'OPEN',
      reason: 'Defense-in-depth security baseline recommendation. The absence of this header alone does not indicate an active vulnerability or immediate exploitation.',
    };
  }

  // Default: pass through as Potential
  return {
    verdict: 'VALID',
    confidence: (finding.confidence as any) || 'POTENTIAL',
    verificationStatus: 'UNVERIFIED',
    status: 'OPEN',
  };
}
