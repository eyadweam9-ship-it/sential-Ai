import { URL } from 'url';

/**
 * SentinelAI - Target Scope Engine
 * 1. Validate: Path formatting and normalization (leading slash, decoding, query params)
 * 2. Scope Boundaries: Check that path belongs to target domain
 * 3. Priority Precedence: Exclusion overrides Inclusion (الاستثناء أقوى من التضمين)
 * 4. Wildcard and prefix matching (/api/*, /admin/**)
 * 5. Full logging of skipped paths
 */

export interface ScopeRule {
  includedPaths: string[];
  excludedPaths: string[];
}

export function normalizeScopePath(rawPath: string): string {
  if (!rawPath) return '/';
  let p = rawPath.trim();
  try {
    p = decodeURIComponent(p);
  } catch {}
  // Extract path portion if full URL
  if (/^https?:\/\//i.test(p)) {
    try {
      const u = new URL(p);
      p = u.pathname;
    } catch {}
  }
  // Strip query string and fragments
  p = p.split('?')[0].split('#')[0];
  if (!p.startsWith('/')) p = `/${p}`;
  // Remove multiple adjacent slashes
  p = p.replace(/\/+/g, '/');
  // Remove trailing slash if longer than 1 character
  if (p.length > 1 && p.endsWith('/')) {
    p = p.slice(0, -1);
  }
  return p.toLowerCase();
}

export function pathMatchesPattern(path: string, pattern: string): boolean {
  const normPath = normalizeScopePath(path);
  const normPattern = normalizeScopePath(pattern);

  if (normPattern === '/*' || normPattern === '*' || normPattern === '/') {
    return true;
  }

  // Exact match
  if (normPath === normPattern) {
    return true;
  }

  // Prefix directory match: /api matches /api/v1, /api/users
  if (normPath.startsWith(normPattern + '/')) {
    return true;
  }

  // Wildcard match: /api/* or /admin/*
  if (normPattern.endsWith('/*')) {
    const base = normPattern.slice(0, -2);
    if (normPath === base || normPath.startsWith(base + '/')) {
      return true;
    }
  }

  return false;
}

/**
 * Evaluate whether a given URL or path is permitted by the Scope Rules.
 * Absolute Rule: Exclusion always wins over Inclusion!
 */
export function evaluateScope(
  targetUrlOrPath: string,
  scope: ScopeRule
): { allowed: boolean; reason: string; matchedRule?: string } {
  const testPath = normalizeScopePath(targetUrlOrPath);

  // 1. Exclusions ALWAYS override Inclusions
  const excluded = (scope.excludedPaths || []).map((p) => p.trim()).filter(Boolean);
  for (const excl of excluded) {
    if (excl.toLowerCase() === 'none' || excl === '') continue;
    if (pathMatchesPattern(testPath, excl)) {
      return {
        allowed: false,
        reason: `Request skipped: Path matches exclusion rule "${excl}"`,
        matchedRule: excl,
      };
    }
  }

  // 2. Inclusions
  const included = (scope.includedPaths || []).map((p) => p.trim()).filter(Boolean);
  if (included.length === 0 || included.includes('/*') || included.includes('*')) {
    return {
      allowed: true,
      reason: 'Path within full authorized domain scope (/*)',
    };
  }

  for (const incl of included) {
    if (pathMatchesPattern(testPath, incl)) {
      return {
        allowed: true,
        reason: `Path permitted by inclusion rule "${incl}"`,
        matchedRule: incl,
      };
    }
  }

  return {
    allowed: false,
    reason: `Request outside defined inclusion scope (Allowed: [${included.join(', ')}])`,
  };
}
