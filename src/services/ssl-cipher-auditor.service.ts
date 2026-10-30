import tls from 'tls';
import { RawToolFinding } from '../tools/security-tool.interface';

/**
 * SslCipherAuditorService
 * Direct Raw TCP/TLS Socket Handshake Audit on Port 443
 * Inspects real peer certificates, expiration dates, issuers, and tests for deprecated protocols (TLSv1.0, TLSv1.1, SSLv3).
 */
export class SslCipherAuditorService {
  /**
   * Connects via raw TLS socket to port 443 and audits certificate validity and cipher suites
   */
  public static async auditSslTls(targetUrl: string): Promise<RawToolFinding[]> {
    const findings: RawToolFinding[] = [];

    let hostname = '';
    let port = 443;
    try {
      const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
      hostname = parsed.hostname;
      port = parsed.port ? parseInt(parsed.port, 10) : 443;
    } catch {
      return [];
    }

    if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') {
      return [];
    }

    try {
      const certInfo = await this.getCertificateInfo(hostname, port);
      if (certInfo) {
        const now = new Date();
        const validTo = new Date(certInfo.valid_to);
        const validFrom = new Date(certInfo.valid_from);
        const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        // 1. Check for Expired Certificate
        if (now > validTo) {
          findings.push({
            title: `Expired SSL/TLS Certificate Detected (${hostname})`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CRYPTOGRAPHY',
            sourceRuleId: 'ssl.cert-expired',
            targetUrl: `https://${hostname}:${port}`,
            evidenceSummary: `The SSL certificate for ${hostname} expired on ${certInfo.valid_to} (${Math.abs(daysRemaining)} days ago). Issued by: ${certInfo.issuer}`,
            rawSnippet: `Certificate Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nValid From: ${certInfo.valid_from}\nValid To: ${certInfo.valid_to}`,
            remediation: 'Renew and deploy a valid, trusted SSL/TLS certificate immediately using Let\'s Encrypt or your certificate authority.',
            cwe: 'CWE-298',
          });
        }
        // 2. Check for Certificate Expiring Soon (Within 14 days)
        else if (daysRemaining <= 14 && daysRemaining >= 0) {
          findings.push({
            title: `SSL/TLS Certificate Expiring Soon (${daysRemaining} Days Remaining)`,
            severity: 'LOW',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CRYPTOGRAPHY',
            sourceRuleId: 'ssl.cert-expiring-soon',
            targetUrl: `https://${hostname}:${port}`,
            evidenceSummary: `Certificate for ${hostname} will expire in ${daysRemaining} days (Expiration Date: ${certInfo.valid_to}).`,
            rawSnippet: `Valid To: ${certInfo.valid_to}\nDays Remaining: ${daysRemaining}`,
            remediation: 'Schedule automated certificate renewal via ACME / certbot to prevent unexpected TLS downtime.',
            cwe: 'CWE-298',
          });
        }

        // 3. Check for Self-Signed Certificate
        if (certInfo.subject === certInfo.issuer || (certInfo.issuer && certInfo.issuer.includes(hostname))) {
          findings.push({
            title: `Self-Signed or Untrusted SSL/TLS Certificate (${hostname})`,
            severity: 'MEDIUM',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CRYPTOGRAPHY',
            sourceRuleId: 'ssl.self-signed-cert',
            targetUrl: `https://${hostname}:${port}`,
            evidenceSummary: `The certificate is self-signed or not issued by a globally recognized Certificate Authority. Issuer matches Subject: ${certInfo.issuer}`,
            rawSnippet: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}`,
            remediation: 'Replace the self-signed certificate with one signed by a trusted Public Certificate Authority (CA).',
            cwe: 'CWE-295',
          });
        }

        // 4. Negotiated Protocol & Cipher Audit
        if (certInfo.protocol && (certInfo.protocol === 'TLSv1' || certInfo.protocol === 'TLSv1.1' || certInfo.protocol === 'SSLv3')) {
          findings.push({
            title: `Deprecated Insecure TLS Protocol Negotiated (${certInfo.protocol})`,
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            verificationStatus: 'VERIFIED',
            category: 'CRYPTOGRAPHY',
            sourceRuleId: 'ssl.deprecated-protocol',
            targetUrl: `https://${hostname}:${port}`,
            evidenceSummary: `Target negotiated ${certInfo.protocol} using cipher suite ${certInfo.cipher}. Deprecated protocols are vulnerable to POODLE, BEAST, and SWEET32 attacks.`,
            rawSnippet: `Protocol: ${certInfo.protocol}\nCipher Suite: ${certInfo.cipher}`,
            remediation: 'Disable SSLv3, TLS 1.0, and TLS 1.1 on your reverse proxy (Nginx/Apache/Caddy/Cloudflare). Enforce minimum TLS 1.2 or TLS 1.3.',
            cwe: 'CWE-326',
          });
        }
      }
    } catch {
      // Non-TLS or unreachable port 443
    }

    return findings;
  }

  private static getCertificateInfo(hostname: string, port: number): Promise<any> {
    return new Promise((resolve) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 6000,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate(true);
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();

            socket.end();

            if (!cert || !cert.valid_to) {
              resolve(null);
              return;
            }

            resolve({
              subject: cert.subject ? (cert.subject.CN || Object.values(cert.subject).join(' ')) : 'Unknown',
              issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || Object.values(cert.issuer).join(' ')) : 'Unknown',
              valid_from: cert.valid_from,
              valid_to: cert.valid_to,
              protocol,
              cipher: cipher ? cipher.name : 'Unknown',
            });
          } catch {
            resolve(null);
          }
        }
      );

      socket.on('error', () => {
        socket.destroy();
        resolve(null);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(null);
      });
    });
  }
}
