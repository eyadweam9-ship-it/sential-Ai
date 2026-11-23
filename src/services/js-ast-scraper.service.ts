import { safeFetchText } from './crawler.service';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface ScrapedSecret {
  type: string;
  match: string;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM';
}

export interface JsScraperResult {
  scriptUrl: string;
  endpoints: string[];
  secrets: ScrapedSecret[];
  findings: RawToolFinding[];
}

export class JsAstScraperService {
  private static readonly SECRET_PATTERNS: Array<{ type: string; regex: RegExp; confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' }> = [
    { type: 'AWS Access Key ID', regex: /\b(AKIA[0-9A-Z]{16})\b/g, confidence: 'CONFIRMED' },
    { type: 'Google Cloud / Maps API Key', regex: /\b(AIza[0-9A-Za-z\\-_]{35})\b/g, confidence: 'CONFIRMED' },
    { type: 'Stripe Live Secret Key', regex: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g, confidence: 'CONFIRMED' },
    { type: 'Slack Bot/User Token', regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g, confidence: 'CONFIRMED' },
    { type: 'Hardcoded JSON Web Token (JWT)', regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, confidence: 'HIGH' },
    { type: 'GitHub Personal Access Token', regex: /\b(gh[pous]_[0-9a-zA-Z]{36})\b/g, confidence: 'CONFIRMED' },
    { type: 'Generic Private Key Header', regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g, confidence: 'CONFIRMED' },
  ];

  private static readonly ENDPOINT_REGEX = /["'](\/(api|v[1-9]|auth|admin|internal|graphql|users|accounts|checkout)[a-zA-Z0-9_\-\/{}]*)["']/g;

  /**
   * Scrapes and analyzes a JavaScript bundle for hidden endpoints and credentials
   */
  public static async scrapeScript(scriptUrl: string): Promise<JsScraperResult> {
    const endpointsSet = new Set<string>();
    const secrets: ScrapedSecret[] = [];
    const findings: RawToolFinding[] = [];

    let scriptContent = '';
    try {
      const res = await safeFetchText(new URL(scriptUrl), 6000, {
        Accept: 'application/javascript, text/javascript, */*',
      });
      if (res.statusCode === 200) {
        scriptContent = res.body;
      }
    } catch {
      return { scriptUrl, endpoints: [], secrets: [], findings: [] };
    }

    if (!scriptContent) {
      return { scriptUrl, endpoints: [], secrets: [], findings: [] };
    }

    // 1. Extract API Endpoints
    let match: RegExpExecArray | null;
    while ((match = this.ENDPOINT_REGEX.exec(scriptContent)) !== null) {
      const ep = match[1];
      if (ep.length > 2 && !ep.endsWith('.js') && !ep.endsWith('.css') && !ep.endsWith('.png')) {
        endpointsSet.add(ep);
      }
    }

    // 2. Extract Secrets
    for (const pat of this.SECRET_PATTERNS) {
      pat.regex.lastIndex = 0;
      let sMatch: RegExpExecArray | null;
      while ((sMatch = pat.regex.exec(scriptContent)) !== null) {
        const raw = sMatch[1] || sMatch[0];
        // Redact partial
        const redacted = raw.length > 8 ? raw.substring(0, 4) + '...' + raw.substring(raw.length - 4) : '***';
        secrets.push({
          type: pat.type,
          match: redacted,
          confidence: pat.confidence,
        });

        findings.push({
          title: `Hardcoded Credential Leaked in Client JavaScript: ${pat.type}`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'HARDCODED_SECRETS',
          sourceRuleId: 'js.hardcoded-secret',
          targetUrl: scriptUrl,
          evidenceSummary: `Found exposed credential matching ${pat.type} inside client-side bundle: "${redacted}". Anyone visiting the site can extract this secret to authenticate against backend cloud services.`,
          remediation: 'Revoke the exposed key immediately and store all API keys on secure server-side environments or secret managers (e.g. AWS Secrets Manager, Vault).',
          cwe: 'CWE-798',
        });
      }
    }

    // 3. Finding: Sensitive Internal Endpoints
    const endpoints = Array.from(endpointsSet);
    const internalRoutes = endpoints.filter((e) => e.includes('/admin') || e.includes('/internal') || e.includes('/debug'));
    if (internalRoutes.length > 0) {
      findings.push({
        title: `Internal / Administrative Endpoints Discovered in Client JavaScript (${internalRoutes.length} routes)`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        category: 'INFORMATION_DISCLOSURE',
        sourceRuleId: 'js.exposed-internal-routes',
        targetUrl: scriptUrl,
        evidenceSummary: `The client-side bundle discloses internal API paths: ${internalRoutes.slice(0, 5).join(', ')}`,
        remediation: 'Remove references to unpublished or internal management endpoints from public client-side JavaScript bundles.',
        cwe: 'CWE-200',
      });
    }

    return {
      scriptUrl,
      endpoints,
      secrets,
      findings,
    };
  }

  /**
   * Scrapes HTML page to find all script tags and analyze them
   */
  public static async scrapePageScripts(pageUrl: string, htmlContent: string): Promise<JsScraperResult[]> {
    const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    const scriptUrls: string[] = [];
    const base = new URL(pageUrl);

    let m: RegExpExecArray | null;
    while ((m = scriptSrcRegex.exec(htmlContent)) !== null) {
      try {
        const fullUrl = new URL(m[1], base.origin).toString();
        scriptUrls.push(fullUrl);
      } catch {}
    }

    const results: JsScraperResult[] = [];
    // Scrape up to 5 top JS files to maintain high scan speed
    for (const url of scriptUrls.slice(0, 5)) {
      const res = await this.scrapeScript(url);
      results.push(res);
    }

    return results;
  }
}
