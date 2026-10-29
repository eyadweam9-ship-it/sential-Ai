import crypto from 'crypto';
import { RawToolFinding } from '../tools/security-tool.interface';

/**
 * SentinelAI - Advanced JWT Security Auditor
 * Audits JWT implementations for:
 * 1. Algorithm 'none' Signature Bypass (CWE-347)
 * 2. Weak HMAC Shared Secret dictionary brute-force (CWE-522 / CWE-328)
 * 3. Plaintext PII / Credential Exposure in unencrypted JWT payload (CWE-312)
 * 4. Missing Expiration (exp) claim (CWE-613)
 */
export class JwtAuditorService {
  private static readonly COMMON_SECRETS = [
    'secret', 'jwtsecret', '123456', 'password', 'admin', 'key',
    'supersecret', 'test', 'development', 'secretkey', 'authsecret'
  ];

  public static async auditTokens(tokens: string[], targetUrl?: string): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];
    const seen = new Set<string>();

    for (const rawToken of tokens) {
      if (!rawToken || typeof rawToken !== 'string') continue;
      const cleanToken = rawToken.replace(/^Bearer\s+/i, '').trim();
      const parts = cleanToken.split('.');
      if (parts.length < 2 || parts.length > 3) continue;
      if (seen.has(cleanToken)) continue;
      seen.add(cleanToken);

      try {
        const headerJson = Buffer.from(parts[0], 'base64url').toString('utf8');
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
        const header = JSON.parse(headerJson);
        const payload = JSON.parse(payloadJson);

        // 1. Check alg: "none"
        if (header.alg && header.alg.toLowerCase() === 'none') {
          findings.push({
            title: 'Critical JWT Authentication Bypass: Algorithm "none" Accepted',
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'AUTHENTICATION_BYPASS',
            sourceRuleId: 'jwt.algo-none-bypass',
            targetUrl,
            evidenceSummary: `The JWT header specifies {"alg": "${header.alg}"}. This allows malicious actors to forge arbitrary administrative tokens with zero cryptographic signature verification.`,
            remediation: 'Explicitly reject tokens with alg: "none" in the JWT verification library. Enforce an allowlist of cryptographic algorithms (e.g. RS256 or HS256).',
            cwe: 'CWE-347',
          });
        }

        // 2. Check Weak HMAC Secret if HS256 / HS384 / HS512
        if (header.alg && header.alg.startsWith('HS') && parts[2]) {
          const signature = Buffer.from(parts[2], 'base64url');
          const dataToSign = `${parts[0]}.${parts[1]}`;

          for (const candidateSecret of this.COMMON_SECRETS) {
            const hmac = crypto.createHmac('sha256', candidateSecret);
            hmac.update(dataToSign);
            const testSig = hmac.digest();
            if (crypto.timingSafeEqual(signature, testSig)) {
              findings.push({
                title: 'High Severity: Trivial Weak HMAC Secret Key in JWT',
                severity: 'HIGH',
                confidence: 'CONFIRMED',
                category: 'BROKEN_CRYPTOGRAPHY',
                sourceRuleId: 'jwt.weak-hmac-secret',
                targetUrl,
                evidenceSummary: `The application signs JWTs using the trivially guessable secret key: "${candidateSecret}". Attackers can forge valid administrative session tokens at will.`,
                remediation: 'Generate a cryptographically random, high-entropy secret key of at least 256 bits (32+ bytes) stored strictly in protected environment variables.',
                cwe: 'CWE-522',
              });
              break;
            }
          }
        }

        // 3. Plaintext PII / Password in Payload
        const payloadStr = JSON.stringify(payload).toLowerCase();
        if (payloadStr.includes('password') || payloadStr.includes('passwd') || payloadStr.includes('secret') || payloadStr.includes('ssn') || payloadStr.includes('credit_card')) {
          findings.push({
            title: 'Sensitive Plaintext Credentials or PII Stored in JWT Payload',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: 'jwt.plaintext-sensitive-data',
            targetUrl,
            evidenceSummary: 'JWT payloads are base64-encoded and completely readable by any client, intermediary proxy, or browser extension. Plaintext credentials or secrets were identified in the payload claims.',
            remediation: 'Never place passwords, secrets, or sensitive PII inside JWT payloads. Only store minimal non-sensitive identifiers (e.g. subject UUID, tenant ID).',
            cwe: 'CWE-312',
          });
        }

        // 4. Missing Expiration Claim
        if (!payload.exp) {
          findings.push({
            title: 'JWT Token Missing Expiration (exp) Lifetime Restriction',
            severity: 'LOW',
            confidence: 'HIGH',
            category: 'SECURITY_MISCONFIGURATION',
            sourceRuleId: 'jwt.missing-exp-claim',
            targetUrl,
            evidenceSummary: 'The audited JWT does not contain an "exp" (expiration time) claim, resulting in indefinite session validity if intercepted.',
            remediation: 'Always specify a short-lived "exp" claim (e.g. 15 to 60 minutes) combined with revocable refresh tokens.',
            cwe: 'CWE-613',
          });
        }
      } catch {}
    }

    return findings;
  }
}
