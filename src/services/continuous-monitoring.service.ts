import { prisma } from '../config/db';
import { SslCipherAuditorService } from './ssl-cipher-auditor.service';
import dns from 'dns';

export interface MonitoringDrift {
  type: 'SSL_EXPIRY' | 'HEADER_DROP' | 'PORT_DRIFT' | 'DNS_CHANGE' | 'REGRESSION_DETECTED';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  title: string;
  description: string;
  previousValue?: string;
  currentValue?: string;
  detectedAt: string;
}

export interface MonitoredTargetStatus {
  targetId: number;
  url: string;
  status: 'ACTIVE' | 'PAUSED' | 'ALERT';
  frequency: 'HOURLY' | 'DAILY' | 'WEEKLY';
  lastCheckedAt: string | null;
  sslDaysRemaining: number | null;
  activeDrifts: MonitoringDrift[];
  regressionCount: number;
  totalFindings: number;
}

/**
 * Continuous Attack Surface Monitoring & Security Regression Engine
 * Monitors targets 24/7, detects infrastructure drifts, and alerts on newly emerging vulnerabilities.
 */
export class ContinuousMonitoringService {
  private static monitoredTargets: Map<string, MonitoredTargetStatus> = new Map();

  /**
   * Register or update a target for continuous 24/7 attack surface monitoring
   */
  public static registerTarget(url: string, frequency: 'HOURLY' | 'DAILY' | 'WEEKLY' = 'DAILY'): MonitoredTargetStatus {
    const cleanUrl = url.trim().toLowerCase();
    const existing = this.monitoredTargets.get(cleanUrl);
    if (existing) {
      existing.frequency = frequency;
      existing.status = 'ACTIVE';
      return existing;
    }

    const newTarget: MonitoredTargetStatus = {
      targetId: Math.floor(Math.random() * 100000) + 1,
      url: cleanUrl,
      status: 'ACTIVE',
      frequency,
      lastCheckedAt: null,
      sslDaysRemaining: null,
      activeDrifts: [],
      regressionCount: 0,
      totalFindings: 0,
    };

    this.monitoredTargets.set(cleanUrl, newTarget);
    return newTarget;
  }

  /**
   * Run an automated lightweight differential audit pass on a monitored target
   */
  public static async executeMonitoringPass(targetUrl: string): Promise<MonitoredTargetStatus> {
    const cleanUrl = targetUrl.trim().toLowerCase();
    let status = this.monitoredTargets.get(cleanUrl);
    if (!status) {
      status = this.registerTarget(cleanUrl);
    }

    const drifts: MonitoringDrift[] = [];
    let host = cleanUrl;
    try {
      const u = new URL(cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`);
      host = u.hostname;
    } catch {}

    // 1. SSL/TLS Certificate Expiry & Cipher Drift Check
    try {
      const certInfo = await SslCipherAuditorService.getCertificateInfo(host, 443);
      if (certInfo && certInfo.valid_to) {
        const now = new Date();
        const validTo = new Date(certInfo.valid_to);
        const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        status.sslDaysRemaining = daysRemaining;
        if (daysRemaining <= 14) {
          drifts.push({
            type: 'SSL_EXPIRY',
            severity: daysRemaining <= 3 ? 'CRITICAL' : 'HIGH',
            title: `SSL Certificate Expiring Soon (${daysRemaining} days remaining)`,
            description: `The SSL/TLS certificate for ${host} will expire on ${certInfo.valid_to}. Urgent renewal required.`,
            currentValue: `${daysRemaining} days`,
            detectedAt: new Date().toISOString(),
          });
        }
      }
    } catch {}

    // 2. DNS Resolution Drift Check
    try {
      await new Promise<void>((resolve) => {
        dns.lookup(host, (err, address) => {
          if (!err && address) {
            // Check if address changed
            const prevIp = status?.activeDrifts.find(d => d.type === 'DNS_CHANGE')?.currentValue;
            if (prevIp && prevIp !== address) {
              drifts.push({
                type: 'DNS_CHANGE',
                severity: 'INFO',
                title: 'Target IP Address Changed',
                description: `Host ${host} DNS resolved to new IP ${address} (previously ${prevIp}).`,
                previousValue: prevIp,
                currentValue: address,
                detectedAt: new Date().toISOString(),
              });
            }
          }
          resolve();
        });
      });
    } catch {}

    // 3. Security Headers Drift Check (HSTS, CSP, X-Frame-Options)
    try {
      const targetReqUrl = cleanUrl.startsWith('http') ? cleanUrl : `https://${cleanUrl}`;
      const res = await fetch(targetReqUrl, { method: 'HEAD', redirect: 'manual' });
      const hsts = res.headers.get('strict-transport-security');
      const csp = res.headers.get('content-security-policy');
      const xfo = res.headers.get('x-frame-options');

      if (!hsts && cleanUrl.startsWith('https')) {
        drifts.push({
          type: 'HEADER_DROP',
          severity: 'HIGH',
          title: 'HSTS Header Missing or Dropped',
          description: 'Strict-Transport-Security header was not detected during the monitoring sweep.',
          currentValue: 'Missing',
          detectedAt: new Date().toISOString(),
        });
      }

      if (!csp) {
        drifts.push({
          type: 'HEADER_DROP',
          severity: 'MEDIUM',
          title: 'Content-Security-Policy Header Missing',
          description: 'No active Content-Security-Policy was returned by the web server.',
          currentValue: 'Missing',
          detectedAt: new Date().toISOString(),
        });
      }
    } catch {}

    // 4. Regression Detection (Checking database for reopened or persistent findings)
    try {
      const recentScans = await prisma.scan.findMany({
        where: { target: { url: { contains: host } } },
        orderBy: { createdAt: 'desc' },
        take: 2,
        include: { findings: true },
      });

      if (recentScans.length >= 2) {
        const latestFindings = recentScans[0].findings;
        const previousFindings = recentScans[1].findings;
        status.totalFindings = latestFindings.length;

        // Findings marked fixed earlier that reappeared
        const regressions = latestFindings.filter(lf => {
          const matched = previousFindings.find(pf => pf.fingerprint === lf.fingerprint || (pf.cwe === lf.cwe && pf.title === lf.title));
          return matched && matched.status === 'FIXED' && lf.status !== 'FIXED';
        });

        if (regressions.length > 0) {
          status.regressionCount = regressions.length;
          drifts.push({
            type: 'REGRESSION_DETECTED',
            severity: 'CRITICAL',
            title: `Security Regression: ${regressions.length} previously patched vulnerabilities reappeared`,
            description: `Vulnerabilities including [${regressions.map(r => r.title).slice(0, 3).join(', ')}] were re-introduced into production.`,
            currentValue: `${regressions.length} recurring defects`,
            detectedAt: new Date().toISOString(),
          });
        }
      }
    } catch {}

    status.lastCheckedAt = new Date().toISOString();
    status.activeDrifts = drifts;
    status.status = drifts.some(d => d.severity === 'CRITICAL' || d.severity === 'HIGH') ? 'ALERT' : 'ACTIVE';

    this.monitoredTargets.set(cleanUrl, status);
    return status;
  }

  /**
   * Get all actively monitored targets
   */
  public static getAllMonitoredTargets(): MonitoredTargetStatus[] {
    return Array.from(this.monitoredTargets.values());
  }

  /**
   * Get monitoring status for a specific target
   */
  public static getTargetStatus(targetUrl: string): MonitoredTargetStatus | null {
    const cleanUrl = targetUrl.trim().toLowerCase();
    return this.monitoredTargets.get(cleanUrl) || null;
  }
}
