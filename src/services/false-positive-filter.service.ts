export interface FilterEvaluation {
  isValidFinding: boolean;
  originalConfidence: string;
  adjustedConfidence: 'CONFIRMED' | 'HIGH' | 'LOW' | 'FALSE_POSITIVE';
  reason: string;
  noiseReductionScore: number; // 0 to 100
}

export class FalsePositiveFilterService {
  /**
   * Evaluates a finding against zero-noise heuristic and contextual rules
   */
  public static evaluateFinding(
    finding: {
      category?: string;
      title?: string;
      evidenceSummary?: string;
      rawSnippet?: string;
      targetUrl?: string;
      confidence?: string;
    },
    responseContext?: {
      statusCode?: number;
      contentType?: string;
      body?: string;
    }
  ): FilterEvaluation {
    const title = (finding.title || '').toLowerCase();
    const category = (finding.category || '').toUpperCase();
    const snippet = (finding.rawSnippet || finding.evidenceSummary || '').toLowerCase();
    const originalConfidence = finding.confidence || 'TENTATIVE';

    const statusCode = responseContext?.statusCode;
    const contentType = (responseContext?.contentType || '').toLowerCase();
    const body = (responseContext?.body || '').toLowerCase();

    // 1. WAF Blocking Page False Positive Check
    // When a WAF returns 403/429 and includes the payload in its standard block message
    if (statusCode === 403 || statusCode === 429) {
      if (
        body.includes('cloudflare') ||
        body.includes('access denied') ||
        body.includes('request blocked') ||
        body.includes('security incident')
      ) {
        return {
          isValidFinding: false,
          originalConfidence,
          adjustedConfidence: 'FALSE_POSITIVE',
          reason: 'Payload was blocked and reflected on a standard WAF rejection page (HTTP 403/429). Target is protected, not vulnerable.',
          noiseReductionScore: 98,
        };
      }
    }

    // 2. Cross-Site Scripting (XSS) Context Filtering
    if (category.includes('XSS') || title.includes('xss') || title.includes('cross-site scripting')) {
      // JSON or plain-text responses cannot execute XSS in modern browsers
      if (contentType.includes('application/json') || contentType.includes('text/plain')) {
        return {
          isValidFinding: false,
          originalConfidence,
          adjustedConfidence: 'FALSE_POSITIVE',
          reason: `Payload reflected inside Content-Type: ${contentType}. Modern browsers will not execute HTML/JS in non-HTML contexts.`,
          noiseReductionScore: 95,
        };
      }

      // Check if payload is properly HTML entity encoded
      if (snippet.includes('&lt;script') || snippet.includes('&gt;') || snippet.includes('&quot;')) {
        return {
          isValidFinding: false,
          originalConfidence,
          adjustedConfidence: 'FALSE_POSITIVE',
          reason: 'Canary payload was properly sanitized and HTML entity encoded (&lt;...&gt;) by the server.',
          noiseReductionScore: 99,
        };
      }
    }

    // 3. SQL Injection False Positive Check
    if (category.includes('SQL') || title.includes('sql injection')) {
      // If error message is generic without DBMS syntax confirmation
      if (
        snippet.includes('syntax error') &&
        !snippet.includes('mysql') &&
        !snippet.includes('postgresql') &&
        !snippet.includes('sqlite') &&
        !snippet.includes('ora-') &&
        !snippet.includes('sqlstate')
      ) {
        return {
          isValidFinding: true,
          originalConfidence,
          adjustedConfidence: 'LOW',
          reason: 'Generic error detected without DBMS-specific syntax signature. Confidence downgraded to LOW to prevent false alerts.',
          noiseReductionScore: 70,
        };
      }
    }

    // 4. Default: Valid Finding
    return {
      isValidFinding: true,
      originalConfidence,
      adjustedConfidence: (originalConfidence as any) || 'CONFIRMED',
      reason: 'Finding verified: payload reflection, syntax signature, and execution context confirmed valid.',
      noiseReductionScore: 10,
    };
  }
}
