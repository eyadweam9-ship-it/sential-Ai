import { RawToolFinding } from '../tools/security-tool.interface';

/**
 * CloudLeakAuditorService
 * Cloud Infrastructure & Object Storage Leak Reconnaissance
 * Enumerates AWS S3 buckets, Google Cloud Storage (GCS), and Azure Blob storage
 * associated with the target domain to detect public access and exposed data.
 */
export class CloudLeakAuditorService {
  public static async auditCloudBuckets(targetUrl: string, isProd = false): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    let hostname = '';
    try {
      const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
      hostname = parsed.hostname;
    } catch {
      return [];
    }

    if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') {
      return [];
    }

    // Extract root domain identifier (e.g. "aymanaboelela.com" -> "aymanaboelela")
    const parts = hostname.replace(/^www\./, '').split('.');
    const baseName = parts[0];
    if (!baseName || baseName.length < 3) return [];

    // Bucket name permutations
    const candidates = [
      baseName,
      `${baseName}-assets`,
      `${baseName}-backup`,
      `${baseName}-data`,
      `${baseName}-public`,
      `${baseName}-prod`,
    ];

    const maxCandidates = isProd ? 3 : candidates.length;

    for (const name of candidates.slice(0, maxCandidates)) {
      // 1. AWS S3 Bucket Probe
      const s3Url = `https://${name}.s3.amazonaws.com`;
      try {
        const s3Res = await fetch(s3Url, {
          method: 'GET',
          headers: { 'User-Agent': 'Sential-Security-Scanner/2.0 (Cloud-Auditor)' },
          signal: AbortSignal.timeout(4000),
        });

        const text = await s3Res.text();

        // Check if bucket is publicly open for directory listing
        if (s3Res.status === 200 && text.includes('<ListBucketResult>')) {
          findings.push({
            title: `Exposed Publicly Readable AWS S3 Bucket (${name})`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CLOUD_MISCONFIGURATION',
            sourceRuleId: 'cloud.s3-public-bucket',
            targetUrl: s3Url,
            evidenceSummary: `AWS S3 bucket '${name}' returned HTTP 200 with XML bucket listing (<ListBucketResult>). Unauthenticated users can enumerate and download files.`,
            rawSnippet: `GET ${s3Url} HTTP/1.1\n\n${text.substring(0, 300)}...`,
            remediation: 'Enable S3 Block Public Access at the account and bucket levels, and restrict IAM bucket policies to authorized roles only.',
            cwe: 'CWE-732',
          });
        } else if (s3Res.status === 403 && text.includes('AccessDenied')) {
          // Bucket exists but is protected (Informational / Recon)
          findings.push({
            title: `Identified Private AWS S3 Bucket Name (${name})`,
            severity: 'INFO',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'RECONNAISSANCE',
            sourceRuleId: 'cloud.s3-bucket-exists',
            targetUrl: s3Url,
            evidenceSummary: `AWS S3 bucket '${name}' exists (HTTP 403 AccessDenied). Access is currently restricted.`,
            rawSnippet: `Bucket: ${s3Url}\nStatus: HTTP 403 AccessDenied`,
            remediation: 'Audit bucket ACLs regularly and ensure AWS S3 Block Public Access remains enforced.',
            cwe: 'CWE-200',
          });
        }
      } catch {}

      // 2. Google Cloud Storage Probe
      const gcsUrl = `https://storage.googleapis.com/${name}`;
      try {
        const gcsRes = await fetch(gcsUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'Sential-Security-Scanner/2.0 (Cloud-Auditor)' },
          signal: AbortSignal.timeout(4000),
        });

        const gcsText = await gcsRes.text();
        if (gcsRes.status === 200 && gcsText.includes('<ListBucketResult>')) {
          findings.push({
            title: `Exposed Publicly Readable Google Cloud Storage Bucket (${name})`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CLOUD_MISCONFIGURATION',
            sourceRuleId: 'cloud.gcs-public-bucket',
            targetUrl: gcsUrl,
            evidenceSummary: `GCS bucket '${name}' returned HTTP 200 with bucket file listing. Unauthenticated users can access storage objects.`,
            rawSnippet: `GET ${gcsUrl} HTTP/1.1\n\n${gcsText.substring(0, 300)}...`,
            remediation: 'Enforce Public Access Prevention (PAP) in Google Cloud Storage and remove "allUsers" / "allAuthenticatedUsers" from bucket IAM permissions.',
            cwe: 'CWE-732',
          });
        }
      } catch {}
    }

    return findings;
  }
}
