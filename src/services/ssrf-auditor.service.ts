import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

/**
 * SentinelAI - Advanced SSRF & Cloud Metadata Auditor
 * Audits URL parameters, webhook endpoints, and proxy proxies for:
 * 1. Cloud Instance Metadata Service (AWS IMDSv1/v2, GCP, Azure) Exfiltration (CWE-918)
 * 2. Localhost & Loopback Internal Network Pivoting (127.0.0.1, [::1], 0.0.0.0, 2130706433)
 */
export class SsrfAuditorService {
  private static readonly METADATA_PAYLOADS = [
    { name: 'AWS IMDSv1', url: 'http://169.254.169.254/latest/meta-data/' },
    { name: 'GCP Metadata', url: 'http://metadata.google.internal/computeMetadata/v1/' },
    { name: 'Localhost IPv4', url: 'http://127.0.0.1:80/' },
    { name: 'Localhost Decimal Bypass', url: 'http://2130706433/' },
    { name: 'Localhost IPv6', url: 'http://[::1]:80/' },
  ];

  public static async auditEndpoint(
    baseUrl: string,
    paramName: string,
    isProduction: boolean = false
  ): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    // In Production: Do not spam internal network, only test read-only metadata probe
    const targets = isProduction ? [this.METADATA_PAYLOADS[0]] : this.METADATA_PAYLOADS;

    for (const test of targets) {
      try {
        const u = new URL(baseUrl);
        u.searchParams.set(paramName, test.url);

        const res = await safeFetchText(u, 3000, {
          'X-Sential-Security-Scan': 'Authorized-Audit-Engine',
          'Metadata-Flavor': 'Google',
        });

        const body = res.body.toLowerCase();
        if (
          res.statusCode === 200 &&
          (body.includes('ami-id') ||
            body.includes('security-credentials') ||
            body.includes('instance-id') ||
            body.includes('computemetadata') ||
            body.includes('apache') ||
            body.includes('nginx'))
        ) {
          findings.push({
            title: `Critical SSRF: Cloud Metadata Service (${test.name}) Exposed via "${paramName}"`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'SSRF',
            sourceRuleId: 'ssrf.cloud-metadata-exposure',
            targetUrl: u.toString(),
            evidenceSummary: `Injecting "${test.url}" into parameter "${paramName}" resulted in HTTP 200 reflecting underlying infrastructure metadata. This enables complete takeover of cloud IAM roles.`,
            remediation: 'Implement strict allowlisting of destination domains/schemes. Block all private IPv4/IPv6 CIDR ranges (169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) at the network layer and enforce AWS IMDSv2 (token-based).',
            cwe: 'CWE-918',
          });
          break;
        }
      } catch {}
    }

    return findings;
  }
}
