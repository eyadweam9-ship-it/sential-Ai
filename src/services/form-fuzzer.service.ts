import { RawToolFinding } from '../tools/security-tool.interface';

interface DiscoveredForm {
  action: string;
  method: 'GET' | 'POST';
  inputs: Array<{ name: string; type: string; value: string }>;
}

/**
 * FormFuzzerService
 * Active Form & Parameter Fuzzer: Tests discovered HTML form inputs and URL query parameters
 * for unescaped Cross-Site Scripting (Reflected XSS) using safe diagnostic canaries.
 */
export class FormFuzzerService {
  private static readonly CANARY = 'sential_probe_xss"\'><sential_canary>';
  private static readonly UNESCAPED_MARKER = '><sential_canary>';

  /**
   * Extracts HTML forms and input elements from page HTML
   */
  public static extractForms(html: string, baseUrl: string): DiscoveredForm[] {
    const forms: DiscoveredForm[] = [];
    const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch: RegExpExecArray | null;

    while ((formMatch = formRegex.exec(html)) !== null) {
      const formAttrs = formMatch[1] || '';
      const formBody = formMatch[2] || '';

      const actionMatch = /action=["']([^"']*)["']/i.exec(formAttrs);
      const methodMatch = /method=["']([^"']*)["']/i.exec(formAttrs);

      let action = actionMatch ? actionMatch[1].trim() : '';
      const method = (methodMatch ? methodMatch[1].trim().toUpperCase() : 'GET') === 'POST' ? 'POST' : 'GET';

      if (!action) {
        action = baseUrl;
      } else {
        try {
          action = new URL(action, baseUrl).toString();
        } catch {
          action = baseUrl;
        }
      }

      const inputs: Array<{ name: string; type: string; value: string }> = [];
      const inputRegex = /<(?:input|textarea|select)\b([^>]*)>/gi;
      let inputMatch: RegExpExecArray | null;

      while ((inputMatch = inputRegex.exec(formBody)) !== null) {
        const inputAttrs = inputMatch[1] || '';
        const nameMatch = /name=["']([^"']+)["']/i.exec(inputAttrs);
        const typeMatch = /type=["']([^"']+)["']/i.exec(inputAttrs);
        const valueMatch = /value=["']([^"']*)["']/i.exec(inputAttrs);

        if (nameMatch) {
          const name = nameMatch[1].trim();
          const type = typeMatch ? typeMatch[1].trim().toLowerCase() : 'text';
          const value = valueMatch ? valueMatch[1].trim() : '';
          if (type !== 'submit' && type !== 'button' && type !== 'image') {
            inputs.push({ name, type, value });
          }
        }
      }

      if (inputs.length > 0) {
        forms.push({ action, method, inputs });
      }
    }

    return forms;
  }

  /**
   * Actively audits endpoints and discovered forms for reflected XSS
   */
  public static async auditFormsAndParams(
    targetUrl: string,
    discoveredUrls: string[],
    htmlContents: string[],
    sessionCookie?: string,
    authHeader?: string,
    isProd = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const testedKeys = new Set<string>();

    const headers: Record<string, string> = {
      'User-Agent': 'Sential-Security-Scanner/2.0 (Form-Fuzzer; Safe-Audit)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    };
    if (sessionCookie) headers['Cookie'] = sessionCookie;
    if (authHeader) headers['Authorization'] = authHeader;
    if (isProd) headers['X-Sential-Security-Scan'] = 'Authorized-Audit-Engine';

    // 1. Gather all forms from HTML content
    const allForms: DiscoveredForm[] = [];
    for (const html of htmlContents) {
      if (html && html.length > 50) {
        allForms.push(...this.extractForms(html, targetUrl));
      }
    }

    // 2. Gather URL query parameters from discovered URLs
    const queryTargets: Array<{ url: string; param: string }> = [];
    for (const u of [targetUrl, ...discoveredUrls]) {
      try {
        const parsed = new URL(u);
        for (const [key] of parsed.searchParams.entries()) {
          queryTargets.push({ url: parsed.origin + parsed.pathname, param: key });
        }
      } catch {}
    }

    // Default common query parameters if none were scraped
    if (queryTargets.length === 0) {
      const commonParams = ['q', 'search', 'query', 'name', 'keyword', 'filter'];
      for (const p of commonParams) {
        queryTargets.push({ url: targetUrl, param: p });
      }
    }

    // Maximum endpoints to fuzz based on environment (Safe rate limit)
    const maxForms = isProd ? 4 : 10;
    const maxParams = isProd ? 6 : 15;

    // A. Test Discovered Forms
    for (const form of allForms.slice(0, maxForms)) {
      for (const input of form.inputs.slice(0, 4)) {
        const testKey = `${form.method} ${form.action} ${input.name}`;
        if (testedKeys.has(testKey)) continue;
        testedKeys.add(testKey);

        try {
          let resText = '';
          let resStatus = 0;
          let rawRequest = '';

          if (form.method === 'POST') {
            const formData = new URLSearchParams();
            for (const other of form.inputs) {
              formData.append(other.name, other.name === input.name ? this.CANARY : (other.value || 'test'));
            }
            rawRequest = `POST ${form.action} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n${formData.toString()}`;

            const response = await fetch(form.action, {
              method: 'POST',
              headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
              body: formData.toString(),
              signal: AbortSignal.timeout(5000),
            });
            resStatus = response.status;
            resText = await response.text();
          } else {
            const target = new URL(form.action);
            target.searchParams.set(input.name, this.CANARY);
            rawRequest = `GET ${target.toString()} HTTP/1.1`;

            const response = await fetch(target.toString(), {
              method: 'GET',
              headers,
              signal: AbortSignal.timeout(5000),
            });
            resStatus = response.status;
            resText = await response.text();
          }

          // Check if canary is reflected without escaping
          if (resText.includes(this.UNESCAPED_MARKER)) {
            const idx = resText.indexOf(this.UNESCAPED_MARKER);
            const snippet = resText.substring(Math.max(0, idx - 40), Math.min(resText.length, idx + 80));

            findings.push({
              title: `Reflected Cross-Site Scripting (XSS) in Form Input '${input.name}'`,
              severity: 'HIGH',
              confidence: 'CONFIRMED',
              verificationStatus: 'VERIFIED',
              category: 'INJECTION',
              sourceRuleId: 'form-fuzzer.reflected-xss',
              targetUrl: form.action,
              evidenceSummary: `Active canary probe reflected unescaped in response (Status ${resStatus}): ${snippet.trim()}`,
              rawSnippet: `Request:\n${rawRequest}\n\nResponse Snippet:\n${snippet}`,
              remediation: 'Implement contextual output encoding (e.g. DOMPurify or framework auto-escaping) and enforce Content-Security-Policy (CSP).',
              cwe: 'CWE-79',
            });
            break; // Stop fuzzing other inputs of this vulnerable form
          }
        } catch {
          // Timeout or connection error
        }
      }
    }

    // B. Test URL Query Parameters
    for (const target of queryTargets.slice(0, maxParams)) {
      const testKey = `GET ${target.url} ${target.param}`;
      if (testedKeys.has(testKey)) continue;
      testedKeys.add(testKey);

      try {
        const u = new URL(target.url);
        u.searchParams.set(target.param, this.CANARY);
        const rawRequest = `GET ${u.toString()} HTTP/1.1`;

        const response = await fetch(u.toString(), {
          method: 'GET',
          headers,
          signal: AbortSignal.timeout(5000),
        });

        const resText = await response.text();
        if (resText.includes(this.UNESCAPED_MARKER)) {
          const idx = resText.indexOf(this.UNESCAPED_MARKER);
          const snippet = resText.substring(Math.max(0, idx - 40), Math.min(resText.length, idx + 80));

          findings.push({
            title: `Reflected Cross-Site Scripting (XSS) in Parameter '${target.param}'`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'INJECTION',
            sourceRuleId: 'form-fuzzer.reflected-xss-param',
            targetUrl: u.toString(),
            evidenceSummary: `Canary reflection in URL parameter '${target.param}': ${snippet.trim()}`,
            rawSnippet: `Request:\n${rawRequest}\n\nResponse Snippet:\n${snippet}`,
            remediation: 'Encode user input using HTML entities or use safe textContent sinks instead of innerHTML.',
            cwe: 'CWE-79',
          });
        }
      } catch {}
    }

    return findings;
  }
}
