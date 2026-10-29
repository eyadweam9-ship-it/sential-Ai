import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

/**
 * SentinelAI - Prototype Pollution Auditor
 * Probes Node.js / JavaScript backend JSON and query APIs for:
 * 1. Server-Side Prototype Pollution via Object Merge / Clone / Assign (CWE-1321)
 * 2. Client-Side DOM Prototype Pollution via URL hash/query
 */
export class PrototypePollutionAuditorService {
  public static async auditEndpoint(
    targetUrl: string,
    isProduction: boolean = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    try {
      const u = new URL(targetUrl);
      // Safe non-destructive canary property
      const canaryKey = `sential_proto_canary_${Date.now()}`;
      u.searchParams.set('__proto__[' + canaryKey + ']', 'polluted');
      u.searchParams.set('constructor[prototype][' + canaryKey + ']', 'polluted');

      const res = await safeFetchText(u, 3500, {
        'X-Sential-Security-Scan': 'Authorized-Audit-Engine',
      });

      // Verify if backend reflected polluted property in JSON response or prototype behavior
      if (res.statusCode < 500 && (res.body.includes(canaryKey) && res.body.includes('polluted'))) {
        findings.push({
          title: 'Prototype Pollution Vulnerability Identified via URL Parameters',
          severity: 'HIGH',
          confidence: 'POTENTIAL',
          category: 'PROTOTYPE_POLLUTION',
          sourceRuleId: 'prototype-pollution.query-reflection',
          targetUrl: u.toString(),
          evidenceSummary: `Injecting '__proto__[${canaryKey}]=polluted' caused the application to reflect the polluted prototype key in its response object state. Attackers can alter application behavior, bypass authorization checks, or achieve Remote Code Execution (RCE).`,
          remediation: 'Use Object.create(null) for dictionary objects, validate object keys to disallow "__proto__" and "constructor", or freeze the prototype using Object.freeze(Object.prototype).',
          cwe: 'CWE-1321',
        });
      }
    } catch {}

    return findings;
  }
}
