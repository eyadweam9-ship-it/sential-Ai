import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

/**
 * SentinelAI - IDOR & Multi-User Business Logic Auditor
 * 1. Sequential integer parameter tampering (/api/users/1 -> /api/users/2) (CWE-639)
 * 2. Multi-User Dual-Session BOLA Matrix (User B session attempting access to User A objects)
 * 3. Predictable Resource Identifier enumeration
 */
export class IdorAuditorService {
  /**
   * Audits an endpoint for basic sequential IDOR tampering
   */
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

  /**
   * Multi-User Dual-Session BOLA Verification Matrix
   * Tests cross-account access where User B attempts to access a resource explicitly owned by User A.
   */
  public static async auditDualSessionMatrix(
    resourceEndpointUrl: string,
    userASessionToken: string,
    userBSessionToken: string,
    userAIdentifier?: string
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    try {
      const u = new URL(resourceEndpointUrl);

      // Step 1: User A accesses their own resource
      const userAHeaders: Record<string, string> = {
        'Authorization': userASessionToken.startsWith('Bearer ') ? userASessionToken : `Bearer ${userASessionToken}`,
        'Cookie': userASessionToken,
        'X-Sential-Audit': 'User-A-Owner',
      };
      const userARes = await safeFetchText(u, 4000, userAHeaders);

      // Step 2: User B accesses User A's resource
      const userBHeaders: Record<string, string> = {
        'Authorization': userBSessionToken.startsWith('Bearer ') ? userBSessionToken : `Bearer ${userBSessionToken}`,
        'Cookie': userBSessionToken,
        'X-Sential-Audit': 'User-B-Attacker',
      };
      const userBRes = await safeFetchText(u, 4000, userBHeaders);

      // Evaluation: User B should be denied (401, 403, or 404)
      if (userARes.statusCode === 200 && userBRes.statusCode === 200 && userBRes.body.length > 40) {
        let isBreached = true;
        let evidenceNote = `User B accessed resource "${u.pathname}" belonging to User A and received HTTP 200 without permission denial.`;

        if (userAIdentifier && !userBRes.body.includes(userAIdentifier)) {
          isBreached = false;
        }

        if (isBreached) {
          findings.push({
            title: `Confirmed Broken Object Level Authorization (BOLA / IDOR) on ${u.pathname}`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'BROKEN_ACCESS_CONTROL',
            sourceRuleId: 'bola.multi-user-matrix',
            targetUrl: u.toString(),
            evidenceSummary: `${evidenceNote} Response payload size: ${userBRes.body.length} bytes.`,
            remediation: 'Enforce strict server-side Object Level Authorization: ensure the authenticated subject ID in JWT/session matches the owner ID of the requested entity before querying the persistence layer.',
            cwe: 'CWE-639',
          });
        }
      }
    } catch {}

    return findings;
  }
}
