export interface SarifSecurityGateOptions {
  maxCritical?: number;
  maxHigh?: number;
  failOnMedium?: boolean;
}

export interface SarifSecurityGateResult {
  passed: boolean;
  exitCode: number;
  reason: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
}

export class SarifExporterService {
  /**
   * Generates standard OASIS SARIF 2.1.0 JSON representation from scan findings
   */
  public static exportToSarif(scanId: number, targetUrl: string, findings: any[]): Record<string, any> {
    const rulesMap = new Map<string, any>();
    const results: any[] = [];

    for (const f of findings) {
      const ruleId = f.sourceRuleId || f.cwe || `SENTIAL-${f.category || 'VULN'}`;
      const level = this.mapSeverityToSarifLevel(f.severity);

      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: f.title.replace(/[^a-zA-Z0-9_-]/g, '_'),
          shortDescription: { text: f.title },
          fullDescription: { text: f.description || f.title },
          help: { text: f.remediation || 'Remediate vulnerability according to standard OWASP guidelines.' },
          properties: {
            category: f.category,
            cwe: f.cwe,
            cvssScore: f.cvssScore,
            tags: ['security', f.category?.toLowerCase() || 'vulnerability', f.cwe?.toLowerCase() || 'cwe'],
          },
        });
      }

      const locationUri = f.evidences?.[0]?.url || f.targetUrl || targetUrl;
      const startLine = f.evidences?.[0]?.lineStart || 1;

      results.push({
        ruleId,
        level,
        message: {
          text: `${f.title}: ${f.description || f.evidenceSummary || 'Vulnerability detected by Sential AI'}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: locationUri,
              },
              region: {
                startLine: typeof startLine === 'number' ? startLine : 1,
              },
            },
          },
        ],
        properties: {
          severity: f.severity,
          confidence: f.confidence,
          cwe: f.cwe,
          verificationStatus: f.verificationStatus,
        },
      });
    }

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Sential AI Security Platform',
              version: '2.6.0',
              informationUri: 'https://sential.ai',
              rules: Array.from(rulesMap.values()),
            },
          },
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: new Date().toISOString(),
            },
          ],
          results,
        },
      ],
    };
  }

  /**
   * Evaluates CI/CD Security Gate policy
   */
  public static evaluateSecurityGate(findings: any[], options: SarifSecurityGateOptions = {}): SarifSecurityGateResult {
    const maxCritical = options.maxCritical ?? 0;
    const maxHigh = options.maxHigh ?? 0;
    const failOnMedium = options.failOnMedium ?? false;

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    for (const f of findings) {
      const sev = (f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else low++;
    }

    const total = critical + high + medium + low;
    const violations: string[] = [];

    if (critical > maxCritical) {
      violations.push(`Found ${critical} CRITICAL vulnerabilities (Threshold: ${maxCritical})`);
    }
    if (high > maxHigh) {
      violations.push(`Found ${high} HIGH vulnerabilities (Threshold: ${maxHigh})`);
    }
    if (failOnMedium && medium > 0) {
      violations.push(`Found ${medium} MEDIUM vulnerabilities (Policy fails on any medium)`);
    }

    const passed = violations.length === 0;

    return {
      passed,
      exitCode: passed ? 0 : 1,
      reason: passed ? 'All security gate thresholds satisfied.' : `Security Gate Failed: ${violations.join('; ')}`,
      counts: {
        critical,
        high,
        medium,
        low,
        total,
      },
    };
  }

  private static mapSeverityToSarifLevel(severity: string): 'error' | 'warning' | 'note' | 'none' {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL' || s === 'HIGH') return 'error';
    if (s === 'MEDIUM') return 'warning';
    if (s === 'LOW') return 'note';
    return 'none';
  }
}
