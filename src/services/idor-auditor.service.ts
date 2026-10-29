import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

/**
 * SentinelAI - IDOR & Business Logic Auditor
 * Tests endpoints for Broken Object Level Authorization (BOLA / IDOR):
 * 1. Sequential integer parameter tampering (/api/users/1 -> /api/users/2) (CWE-639)
 * 2. Predictable Resource Identifier enumeration
 */
export class IdorAuditorService {
  public static async auditEndpoint(
    endpointUrl: string,
    sessionCookie?: string,
    authHeader?: string
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    try {
      const u = new URL(endpointUrl);
      const headers: Record<string, string> = {
        'X-Sential-Security-Scan': 'Authorized-Audit-Engine',
      };
      if (sessionCookie) headers['Cookie'] = sessionCookie;
      if (authHeader) headers['Authorization'] = authHeader;

      // Detect sequential IDs in URL path (e.g. /users/42, /orders/1001)
      const pathSegments = u.pathname.split('/');
      let idIndex = -1;
      let originalId = -1;

      for (let i = 0; i < pathSegments.length; i++) {
        const seg = pathSegments[i];
        if (/^\d{1,8}$/.test(seg)) {
          idIndex = i;
          originalId = parseInt(seg, 10);
          break;
        }
      }

      if (idIndex !== -1 && originalId > 0) {
        // Probe sibling ID: originalId + 1
        const tamperedSegments = [...pathSegments];
        tamperedSegments[idIndex] = String(originalId + 1);
        const tamperedUrl = new URL(u.toString());
        tamperedUrl.pathname = tamperedSegments.join('/');

        const originalRes = await safeFetchText(u, 3500, headers);
        const tamperedRes = await safeFetchText(tamperedUrl, 3500, headers);

        // If both return 200 with substantial body and different content length, potential IDOR / BOLA exists
        if (
          originalRes.statusCode === 200 &&
          tamperedRes.statusCode === 200 &&
          tamperedRes.body.length > 50 &&
          Math.abs(originalRes.body.length - tamperedRes.body.length) > 0
        ) {
          findings.push({
            title: `Potential Insecure Direct Object Reference (IDOR) on ${u.pathname}`,
            severity: 'HIGH',
            confidence: 'POTENTIAL',
            category: 'BROKEN_ACCESS_CONTROL',
            sourceRuleId: 'idor.sequential-tampering',
            targetUrl: tamperedUrl.toString(),
            evidenceSummary: `Tampering path ID from "${originalId}" to "${originalId + 1}" successfully returned HTTP 200 with data for another record without authorization failure.`,
            remediation: 'Implement robust object-level permission checks verifying that the authenticated user owns or is authorized to access the requested resource ID. Use non-sequential UUIDs (v4) for record identifiers.',
            cwe: 'CWE-639',
          });
        }
      }
    } catch {}

    return findings;
  }
}
