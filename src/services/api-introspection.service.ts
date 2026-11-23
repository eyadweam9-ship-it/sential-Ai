import { safeFetchText } from './crawler.service';
import { RawToolFinding } from '../tools/security-tool.interface';
import { ApiSpecImporterService, ApiEndpointSpec } from './api-spec-importer.service';

export interface IntrospectionDiscovery {
  type: 'SWAGGER_OPENAPI' | 'GRAPHQL';
  url: string;
  endpointsCount: number;
  endpoints: ApiEndpointSpec[];
  schemaSnippet?: string;
  findings: RawToolFinding[];
}

export class ApiIntrospectionService {
  private static readonly SWAGGER_ROUTES = [
    '/swagger.json',
    '/openapi.json',
    '/v2/api-docs',
    '/v3/api-docs',
    '/api-docs',
    '/api/swagger.json',
    '/docs/swagger.json',
  ];

  /**
   * Probes and audits an origin for exposed OpenAPI / Swagger / API definitions
   */
  public static async probeAndAudit(baseUrl: string): Promise<IntrospectionDiscovery | null> {
    const origin = new URL(baseUrl).origin;

    for (const route of this.SWAGGER_ROUTES) {
      try {
        const probeUrl = new URL(route, origin);
        const targetUrl = probeUrl.toString();
        const res = await safeFetchText(probeUrl, 4000, {
          Accept: 'application/json, text/plain, */*',
        });

        if (res.statusCode === 200 && res.body.length > 50) {
          const bodyTrimmed = res.body.trim();
          if (bodyTrimmed.startsWith('{') && (bodyTrimmed.includes('"swagger"') || bodyTrimmed.includes('"openapi"') || bodyTrimmed.includes('"paths"'))) {
            const parsed = ApiSpecImporterService.parseSpec(bodyTrimmed, origin);
            const findings: RawToolFinding[] = [];

            // 1. Finding: OpenAPI / Swagger Public Exposure (CWE-200)
            findings.push({
              title: `Public OpenAPI / Swagger Specification Exposed on ${route}`,
              severity: 'MEDIUM',
              confidence: 'CONFIRMED',
              category: 'INFORMATION_DISCLOSURE',
              sourceRuleId: 'api.swagger-exposed',
              targetUrl,
              evidenceSummary: `The API definition file was publicly accessible at ${targetUrl}, revealing ${parsed.endpoints.length} endpoints and internal schema parameters.`,
              remediation: 'Restrict access to Swagger/OpenAPI documentation to authenticated internal developers or VPN only.',
              cwe: 'CWE-200',
            });

            // 2. Finding: Sensitive Admin / Internal Endpoints in public spec
            const adminEndpoints = parsed.endpoints.filter(
              (e) => e.path.toLowerCase().includes('/admin') || e.path.toLowerCase().includes('/internal') || e.path.toLowerCase().includes('/debug')
            );

            if (adminEndpoints.length > 0) {
              findings.push({
                title: `Potentially Unprotected Admin / Internal Endpoints Exposed in API Spec (${adminEndpoints.length} routes)`,
                severity: 'HIGH',
                confidence: 'POTENTIAL',
                category: 'BROKEN_ACCESS_CONTROL',
                sourceRuleId: 'api.exposed-admin-routes',
                targetUrl,
                evidenceSummary: `The exposed API specification advertises privileged routes: ${adminEndpoints.map((e) => e.path).slice(0, 5).join(', ')}`,
                remediation: 'Ensure all administrative endpoints enforce strict role-based access control (RBAC) and remove unpublished routes from public schemas.',
                cwe: 'CWE-306',
              });
            }

            // 3. Finding: High-Risk IDOR / BOLA Paths detected
            const idorPaths = parsed.endpoints.filter((e) =>
              /\{[a-zA-Z0-9_-]*(id|account|user|order|tenant)[a-zA-Z0-9_-]*\}/i.test(e.path)
            );

            if (idorPaths.length > 0) {
              findings.push({
                title: `High-Risk BOLA / IDOR Endpoints Identified in Spec (${idorPaths.length} routes)`,
                severity: 'MEDIUM',
                confidence: 'POTENTIAL',
                category: 'BROKEN_OBJECT_LEVEL_AUTHORIZATION',
                sourceRuleId: 'api.bola-path-parameters',
                targetUrl,
                evidenceSummary: `Endpoints accept direct object identifier path parameters: ${idorPaths.map((e) => e.path).slice(0, 5).join(', ')}`,
                remediation: 'Implement server-side user-context ownership verification (e.g. session user ID vs requested resource owner).',
                cwe: 'CWE-639',
              });
            }

            return {
              type: 'SWAGGER_OPENAPI',
              url: targetUrl,
              endpointsCount: parsed.endpoints.length,
              endpoints: parsed.endpoints,
              schemaSnippet: bodyTrimmed.substring(0, 500),
              findings,
            };
          }
        }
      } catch {}
    }

    return null;
  }
}
