import { safeFetchText } from './crawler.service';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface DetectionMatcher {
  type: 'status' | 'word' | 'regex';
  status?: number[];
  words?: string[];
  regex?: string[];
  condition?: 'and' | 'or';
  part?: 'body' | 'header';
}

export interface DetectionTemplate {
  id: string;
  info: {
    name: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    author?: string;
    description: string;
    remediation?: string;
    cwe?: string;
  };
  requests: Array<{
    method: 'GET' | 'POST' | 'HEAD';
    path: string[];
    headers?: Record<string, string>;
    matchersCondition?: 'and' | 'or';
    matchers: DetectionMatcher[];
  }>;
}

export class YamlTemplateEngineService {
  private static readonly BUILTIN_TEMPLATES: DetectionTemplate[] = [
    {
      id: 'git-config-exposure',
      info: {
        name: 'Exposed Git Repository Configuration (.git/config)',
        severity: 'HIGH',
        description: 'The .git/config file was found exposed to the public internet, disclosing repository URLs, branch names, and sensitive commit histories.',
        remediation: 'Block HTTP access to the .git directory in web server configurations (e.g. NGINX location ~ /\\.git).',
        cwe: 'CWE-200',
      },
      requests: [
        {
          method: 'GET',
          path: ['/.git/config'],
          matchersCondition: 'and',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'word', words: ['[core]', 'repositoryformatversion'], condition: 'and' },
          ],
        },
      ],
    },
    {
      id: 'env-file-leak',
      info: {
        name: 'Exposed Environment File (.env)',
        severity: 'CRITICAL',
        description: 'The production .env file is publicly accessible, leaking database passwords, API tokens, and private application secrets.',
        remediation: 'Move .env outside public web roots and configure web servers to reject requests to hidden dotfiles.',
        cwe: 'CWE-312',
      },
      requests: [
        {
          method: 'GET',
          path: ['/.env', '/.env.local'],
          matchersCondition: 'and',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'regex', regex: ['(DB_PASSWORD|APP_KEY|DATABASE_URL|SECRET_KEY)\\s*='], condition: 'or' },
          ],
        },
      ],
    },
    {
      id: 'spring-boot-actuator',
      info: {
        name: 'Unprotected Spring Boot Actuator Endpoints',
        severity: 'HIGH',
        description: 'Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump) are exposed without authentication, exposing internal configuration and heap memory.',
        remediation: 'Secure actuator endpoints with Spring Security and disable sensitive management endpoints in application.properties.',
        cwe: 'CWE-306',
      },
      requests: [
        {
          method: 'GET',
          path: ['/actuator/env', '/actuator'],
          matchersCondition: 'and',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'word', words: ['activeProfiles', 'propertySources'], condition: 'or' },
          ],
        },
      ],
    },
    {
      id: 'phpinfo-disclosure',
      info: {
        name: 'Exposed PHP Information Script (phpinfo.php)',
        severity: 'MEDIUM',
        description: 'A phpinfo diagnostic script is exposed publicly, detailing PHP version, internal IP addresses, environment variables, and module configurations.',
        remediation: 'Delete phpinfo scripts from production servers.',
        cwe: 'CWE-200',
      },
      requests: [
        {
          method: 'GET',
          path: ['/phpinfo.php', '/info.php'],
          matchersCondition: 'and',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'word', words: ['PHP Version', 'System', 'Configuration File'], condition: 'and' },
          ],
        },
      ],
    },
  ];

  /**
   * Execute built-in and custom templates against a target
   */
  public static async executeTemplates(
    targetUrl: string,
    customTemplates: DetectionTemplate[] = []
  ): Promise<RawToolFinding[]> {
    const origin = new URL(targetUrl).origin;
    const allTemplates = [...this.BUILTIN_TEMPLATES, ...customTemplates];
    const findings: RawToolFinding[] = [];

    for (const template of allTemplates) {
      for (const req of template.requests) {
        for (const subPath of req.path) {
          try {
            const probeUrl = new URL(subPath, origin);
            const targetUrlStr = probeUrl.toString();
            const res = await safeFetchText(probeUrl, 4000, {
              ...(req.headers || {}),
              Accept: '*/*',
            });

            const matched = this.evaluateMatchers(res, req.matchers, req.matchersCondition || 'and');

            if (matched) {
              findings.push({
                title: template.info.name,
                severity: template.info.severity as any,
                confidence: 'CONFIRMED',
                category: 'CUSTOM_TEMPLATE_MATCH',
                sourceRuleId: `template.${template.id}`,
                targetUrl: targetUrlStr,
                evidenceSummary: `${template.info.description} Discovered at: ${targetUrlStr} (HTTP ${res.statusCode}).`,
                remediation: template.info.remediation || 'Remediate according to security best practices.',
                cwe: template.info.cwe || 'CWE-200',
              });
              break; // Matched one path in this request
            }
          } catch {}
        }
      }
    }

    return findings;
  }

  private static evaluateMatchers(
    res: { statusCode: number; body: string; responseTime: number; finalUrl: string },
    matchers: DetectionMatcher[],
    condition: 'and' | 'or'
  ): boolean {
    const results = matchers.map((m) => {
      if (m.type === 'status' && m.status) {
        return m.status.includes(res.statusCode);
      }

      const content = res.body;

      if (m.type === 'word' && m.words) {
        const cond = m.condition || 'and';
        if (cond === 'and') {
          return m.words.every((w) => content.includes(w));
        } else {
          return m.words.some((w) => content.includes(w));
        }
      }

      if (m.type === 'regex' && m.regex) {
        const cond = m.condition || 'or';
        if (cond === 'and') {
          return m.regex.every((r) => new RegExp(r, 'i').test(content));
        } else {
          return m.regex.some((r) => new RegExp(r, 'i').test(content));
        }
      }

      return false;
    });

    if (condition === 'and') {
      return results.every(Boolean);
    } else {
      return results.some(Boolean);
    }
  }

  public static getBuiltinTemplates(): DetectionTemplate[] {
    return this.BUILTIN_TEMPLATES;
  }
}
