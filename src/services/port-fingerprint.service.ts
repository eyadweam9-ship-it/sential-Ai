import net from 'net';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface ScannedPort {
  port: number;
  service: string;
  isOpen: boolean;
  banner?: string;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface PortScanResult {
  host: string;
  openPorts: ScannedPort[];
  totalScanned: number;
  findings: RawToolFinding[];
}

export class PortFingerprintService {
  private static readonly TARGET_PORTS = [
    { port: 21, service: 'FTP', risk: 'HIGH' as const },
    { port: 22, service: 'SSH', risk: 'MEDIUM' as const },
    { port: 23, service: 'Telnet', risk: 'CRITICAL' as const },
    { port: 80, service: 'HTTP', risk: 'LOW' as const },
    { port: 443, service: 'HTTPS', risk: 'LOW' as const },
    { port: 3306, service: 'MySQL', risk: 'HIGH' as const },
    { port: 5432, service: 'PostgreSQL', risk: 'HIGH' as const },
    { port: 6379, service: 'Redis', risk: 'CRITICAL' as const },
    { port: 8080, service: 'HTTP-Alt', risk: 'MEDIUM' as const },
    { port: 8443, service: 'HTTPS-Alt', risk: 'MEDIUM' as const },
    { port: 9200, service: 'ElasticSearch', risk: 'CRITICAL' as const },
    { port: 27017, service: 'MongoDB', risk: 'CRITICAL' as const },
  ];

  /**
   * Fast asynchronous port & banner scanning
   */
  public static async scanHost(host: string, timeoutMs: number = 1500): Promise<PortScanResult> {
    const cleanHost = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const openPorts: ScannedPort[] = [];
    const findings: RawToolFinding[] = [];

    const checks = this.TARGET_PORTS.map((target) => {
      return new Promise<void>((resolve) => {
        const socket = new net.Socket();
        let isOpen = false;
        let banner = '';

        socket.setTimeout(timeoutMs);

        socket.on('connect', () => {
          isOpen = true;
          // Send probe for Redis / HTTP if applicable
          if (target.port === 6379) {
            socket.write('*1\r\n$4\r\nPING\r\n');
          } else if (target.port === 80 || target.port === 8080) {
            socket.write(`HEAD / HTTP/1.0\r\nHost: ${cleanHost}\r\n\r\n`);
          }
        });

        socket.on('data', (data) => {
          banner = data.toString('utf8', 0, Math.min(data.length, 256)).trim();
          socket.destroy();
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve();
        });

        socket.on('error', () => {
          socket.destroy();
          resolve();
        });

        socket.on('close', () => {
          if (isOpen) {
            openPorts.push({
              port: target.port,
              service: target.service,
              isOpen: true,
              banner: banner || undefined,
              risk: target.risk,
            });
          }
          resolve();
        });

        try {
          socket.connect(target.port, cleanHost);
        } catch {
          resolve();
        }
      });
    });

    await Promise.allSettled(checks);

    // Evaluate findings
    for (const p of openPorts) {
      if (['Redis', 'MongoDB', 'ElasticSearch'].includes(p.service)) {
        findings.push({
          title: `Directly Exposed Database Port: ${p.service} (Port ${p.port})`,
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'EXPOSED_INFRASTRUCTURE',
          sourceRuleId: `network.exposed-db-${p.port}`,
          targetUrl: `tcp://${cleanHost}:${p.port}`,
          evidenceSummary: `The ${p.service} port ${p.port} is open to the public internet.${p.banner ? ` Banner: "${p.banner}"` : ''} Attackers can execute unauthenticated remote code, wipe collections, or exfiltrate databases.`,
          remediation: `Bind ${p.service} to 127.0.0.1 or internal VPC only. Block port ${p.port} in the firewall security group.`,
          cwe: 'CWE-306',
        });
      } else if (p.service === 'Telnet') {
        findings.push({
          title: `Insecure Cleartext Telnet Service Exposed (Port 23)`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'INSECURE_COMMUNICATION',
          sourceRuleId: 'network.exposed-telnet-23',
          targetUrl: `tcp://${cleanHost}:23`,
          evidenceSummary: 'Cleartext Telnet protocol detected. Credentials and session traffic can be intercepted via network sniffing.',
          remediation: 'Disable Telnet service immediately and migrate to SSHv2 with key-based authentication.',
          cwe: 'CWE-319',
        });
      } else if (['MySQL', 'PostgreSQL'].includes(p.service)) {
        findings.push({
          title: `Publicly Exposed SQL Database: ${p.service} (Port ${p.port})`,
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          category: 'EXPOSED_INFRASTRUCTURE',
          sourceRuleId: `network.exposed-sql-${p.port}`,
          targetUrl: `tcp://${cleanHost}:${p.port}`,
          evidenceSummary: `Database server port ${p.port} (${p.service}) accepted external TCP connection. This exposes the database to brute-force and zero-day exploitation.`,
          remediation: 'Restrict database ingress to application servers via firewall / security groups.',
          cwe: 'CWE-284',
        });
      }
    }

    return {
      host: cleanHost,
      openPorts,
      totalScanned: this.TARGET_PORTS.length,
      findings,
    };
  }
}
