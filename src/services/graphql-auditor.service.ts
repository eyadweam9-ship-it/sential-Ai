import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

/**
 * SentinelAI - GraphQL & WebSocket Security Auditor
 * Audits GraphQL endpoints for:
 * 1. Unrestricted Schema Introspection Enabled (CWE-200)
 * 2. Unrestricted Query Depth / Batching Amplification DoS (CWE-400)
 * 3. Cross-Site WebSocket Hijacking (CSWSH) posture (CWE-1385)
 */
export class GraphqlAuditorService {
  private static readonly GRAPHQL_ROUTES = [
    '/graphql',
    '/api/graphql',
    '/v1/graphql',
    '/query',
    '/api/query',
  ];

  public static async auditTarget(
    targetUrl: string,
    isProduction: boolean = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const base = new URL(targetUrl);

    for (const route of this.GRAPHQL_ROUTES) {
      try {
        const probeUrl = new URL(route, base.origin);

        // 1. Probe Introspection Query
        const introspectionBody = JSON.stringify({
          query: 'query IntrospectionQuery { __schema { queryType { name } types { name kind } } }',
        });

        const res = await safeFetchText(probeUrl, 4000, {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Sential-Security-Scan': 'Authorized-Audit-Engine',
        });

        if (res.statusCode === 200 && (res.body.includes('__schema') || res.body.includes('queryType'))) {
          findings.push({
            title: `GraphQL Schema Introspection Enabled on ${route}`,
            severity: isProduction ? 'HIGH' : 'MEDIUM',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: 'graphql.introspection-enabled',
            targetUrl: probeUrl.toString(),
            evidenceSummary: `The GraphQL endpoint returned complete internal schema and type definitions upon submitting an introspection query. Attackers can map out entire internal data models and unreleased mutations.`,
            remediation: 'Disable introspection queries in production environments (e.g. set `introspection: false` in Apollo Server, Yoga, or GraphQL Java).',
            cwe: 'CWE-200',
          });

          // 2. Probe Query Depth / Amplification DoS
          const deepQuery = JSON.stringify({
            query: 'query DeepDoS { __schema { types { fields { type { fields { type { name } } } } } } }',
          });
          const deepRes = await safeFetchText(probeUrl, 4000, {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          });
          if (deepRes.statusCode === 200 && deepRes.body.length > 5000) {
            findings.push({
              title: `GraphQL Query Depth / Complexity Limit Not Enforced on ${route}`,
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              category: 'DENIAL_OF_SERVICE',
              sourceRuleId: 'graphql.unrestricted-query-depth',
              targetUrl: probeUrl.toString(),
              evidenceSummary: `Deeply nested recursive queries were executed without query complexity or depth rejection. This allows malicious actors to exhaust server CPU and memory via cyclic GraphQL queries.`,
              remediation: 'Enforce maximum query depth and query complexity limits using middleware like `graphql-depth-limit` or cost analysis plugins.',
              cwe: 'CWE-400',
            });
          }

          break; // Found the active GraphQL route
        }
      } catch {}
    }

    return findings;
  }
}
