import { RawToolFinding } from '../tools/security-tool.interface';

export interface FindingValidationResult {
  verdict: 'VALID' | 'NEEDS_REVIEW' | 'DROP_FALSE_POSITIVE';
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'NEEDS_REVIEW' | 'LIKELY_FALSE_POSITIVE';
  status: 'CONFIRMED' | 'NEEDS_REVIEW' | 'FALSE_POSITIVE';
  reason?: string;
  adjustedTitle?: string;
  adjustedRemediation?: string;
}

/**
 * 5-Stage Evidence Validation & False Positive Elimination Engine
 * Evaluates raw finding claims against technical code evidence, AST context, and syntax validity.
 */
export function validateFindingEvidence(finding: RawToolFinding): FindingValidationResult {
  const cwe = (finding.cwe || '').toUpperCase();
  const category = (finding.category || '').toUpperCase();
  const title = (finding.title || '').toLowerCase();
  const snippet = (finding.rawSnippet || '').trim();
  const snippetLower = snippet.toLowerCase();
  const filePath = (finding.filePath || '').toLowerCase();

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
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Evidence matches a DOM CSS selector (querySelector), not a database SQL query.',
      };
    }

    // B. ES Module / package import/export false positive (e.g. import ... from '...')
    if (/^\s*(?:import|export)\b.*?\bfrom\b/i.test(snippet)) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
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
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Evidence is HTML markup concatenation, not an SQL statement.',
      };
    }

    // D. English conversational words ("from", "where", "select option") without real SQL grammar
    const hasSqlVerbs = /\b(?:SELECT\s+[\w\*\s,\(\)\.`'"]+\s+FROM|INSERT\s+INTO\s+[\w\.`'"]+|UPDATE\s+[\w\.`'"]+\s+SET|DELETE\s+FROM\s+[\w\.`'"]+|UNION\s+SELECT)\b/i.test(snippet);
    if (!hasSqlVerbs) {
      // Check if there is an explicit DB query sink
      const hasDbSink = /\b(?:db|pool|client|connection|sequelize|prisma|pdo|mysqli?)\s*\.(?:query|execute|raw|\$queryRaw)\s*\(/i.test(snippet);
      if (!hasDbSink) {
        return {
          verdict: 'DROP_FALSE_POSITIVE',
          confidence: 'LIKELY_FALSE_POSITIVE',
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
        status: 'FALSE_POSITIVE',
        reason: 'Safe Pattern: Query is properly parameterized with bind parameters.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      status: 'CONFIRMED',
    };
  }

  // =========================================================================
  // 2. DOM Cross-Site Scripting (XSS) Validation (CWE-79)
  // =========================================================================
  if (cwe === 'CWE-79' || category === 'CROSS_SITE_SCRIPTING' || title.includes('xss')) {
    // A. Static HTML assignment to innerHTML / outerHTML (e.g. el.innerHTML = '<span ...>انتهت الصلاحية</span>')
    if (/\.(?:innerHTML|outerHTML)\s*=\s*/i.test(snippet)) {
      // Check if RHS is a static string literal without variables or concatenation
      const rhs = snippet.replace(/.*?\.(?:innerHTML|outerHTML)\s*=\s*/i, '').trim().replace(/;$/, '');
      const isStaticString =
        (/^['"][^'"]*['"]$/.test(rhs)) ||
        (rhs === '""' || rhs === "''") ||
        (/^`[^`]*`$/.test(rhs) && !rhs.includes('${'));

      if (isStaticString) {
        return {
          verdict: 'DROP_FALSE_POSITIVE',
          confidence: 'LIKELY_FALSE_POSITIVE',
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
          status: 'FALSE_POSITIVE',
          reason: 'Safe Pattern: innerHTML sink is sanitized with DOMPurify / escaping function.',
        };
      }
    }

    // B. Static document.write calls
    if (/document\.write(?:ln)?\s*\(\s*['"][^'"]*['"]\s*\)/i.test(snippet) && !snippet.includes('+') && !snippet.includes('${')) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'document.write used with static argument. Code modernization advised, but immediate exploitation is unlikely.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'HIGH',
      status: 'CONFIRMED',
    };
  }

  // =========================================================================
  // 3. Email & PII Disclosure Validation (CWE-200 / CWE-359)
  // =========================================================================
  if (cwe === 'CWE-200' || cwe === 'CWE-359' || title.includes('email') || category.includes('EXPOSURE') || category.includes('PII')) {
    // A. Form inputs & placeholders (e.g. <input type="email" name="email" value="<?= htmlspecialchars($_POST['email']) ?>">)
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
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Email address uses standard RFC documentation placeholder domain (example.com).',
      };
    }

    // C. Installer, Setup, or Seed script context (e.g. $adminEmail in install.php or seed.ts)
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
        confidence: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'Hardcoded administrative email detected in an installer or setup script. Review whether the installation script remains exposed in production environments.',
        adjustedTitle: 'Administrative Email Disclosed in Installation Script',
        adjustedRemediation: 'Ensure install.php and setup scripts are deleted or access-restricted after initial system configuration.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'HIGH',
      status: 'CONFIRMED',
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
        status: 'FALSE_POSITIVE',
        reason: 'Discarded False Positive: Input parameter or type declaration, not a hardcoded secret.',
      };
    }

    // B. Empty password literal
    if (/(?:password|passwd|pwd)\s*[:=]\s*['"]\s*['"]/i.test(snippet)) {
      return {
        verdict: 'DROP_FALSE_POSITIVE',
        confidence: 'LIKELY_FALSE_POSITIVE',
        status: 'FALSE_POSITIVE',
        reason: 'Safe Pattern: Password is initialized to an empty string.',
      };
    }

    // C. Template placeholders (CHANGEME, YOUR_PASSWORD)
    if (
      snippetLower.includes('your_password') ||
      snippetLower.includes('changeme') ||
      snippetLower.includes('todo') ||
      snippetLower.includes('placeholder')
    ) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'Template placeholder credential detected. Verify that default placeholder has been replaced before deployment.',
      };
    }

    // D. Installer / Setup script context
    if (
      filePath.includes('install') ||
      filePath.includes('setup') ||
      filePath.includes('seed')
    ) {
      return {
        verdict: 'NEEDS_REVIEW',
        confidence: 'NEEDS_REVIEW',
        status: 'NEEDS_REVIEW',
        reason: 'Initial setup credentials in installation/seed script. Verify that installation scripts are removed after provisioning.',
      };
    }

    return {
      verdict: 'VALID',
      confidence: 'CONFIRMED',
      status: 'CONFIRMED',
    };
  }

  // Default: pass through as Valid
  return {
    verdict: 'VALID',
    confidence: (finding.confidence as any) || 'HIGH',
    status: 'CONFIRMED',
  };
}
