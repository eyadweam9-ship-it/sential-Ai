import dns from 'dns';
import { promisify } from 'util';
import { safeFetchText } from './crawler.service';
import { RawToolFinding } from '../tools/security-tool.interface';

const resolveDnsAsync = promisify(dns.resolve4);

export interface DiscoveredSubdomain {
  subdomain: string;
  ip?: string;
  category: 'ADMIN' | 'API' | 'DEV_STAGING' | 'AUTH' | 'ASSETS' | 'MAIL' | 'GENERAL';
  source: 'CERTIFICATE_TRANSPARENCY' | 'DNS_BRUTEFORCE' | 'HEURISTIC';
  isLive: boolean;
}

export interface SubdomainReconResult {
  domain: string;
  totalFound: number;
  liveCount: number;
  subdomains: DiscoveredSubdomain[];
  findings: RawToolFinding[];
}

export class SubdomainReconService {
  private static readonly COMMON_PREFIXES = [
    'www', 'api', 'admin', 'dev', 'staging', 'test', 'auth', 'mail',
    'portal', 'app', 'vpn', 'dashboard', 'gateway', 'cdn', 'demo'
  ];

  /**
   * Enumerate subdomains passively via Certificate Transparency logs + DNS verification
   */
  public static async enumerate(domain: string, maxLimit = 50): Promise<SubdomainReconResult> {
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase();
    const discoveredMap = new Map<string, DiscoveredSubdomain>();
    const findings: RawToolFinding[] = [];

    // 1. Passive CT Query via crt.sh
    try {
      const ctUrl = new URL(`https://crt.sh/?q=%.${encodeURIComponent(cleanDomain)}&output=json`);
      const res = await safeFetchText(ctUrl, 6000, {
        'User-Agent': 'Sential-Recon/2.0',
        Accept: 'application/json',
      });

      if (res.statusCode === 200 && res.body.trim().startsWith('[')) {
        const ctEntries = JSON.parse(res.body);
        for (const entry of ctEntries) {
          if (!entry.name_value) continue;
          const names = String(entry.name_value).split('\n');
          for (let name of names) {
            name = name.trim().toLowerCase();
            if (name.startsWith('*.')) name = name.substring(2);
            if (name.endsWith(`.${cleanDomain}`) || name === cleanDomain) {
              if (!discoveredMap.has(name) && discoveredMap.size < maxLimit) {
                discoveredMap.set(name, {
                  subdomain: name,
                  category: this.categorize(name),
                  source: 'CERTIFICATE_TRANSPARENCY',
                  isLive: false,
                });
              }
            }
          }
        }
      }
    } catch {}

    // 2. Fallback / supplementary dictionary verification if CT yielded few results
    if (discoveredMap.size < 5) {
      for (const prefix of this.COMMON_PREFIXES) {
        const candidate = `${prefix}.${cleanDomain}`;
        if (!discoveredMap.has(candidate)) {
          discoveredMap.set(candidate, {
            subdomain: candidate,
            category: this.categorize(candidate),
            source: 'DNS_BRUTEFORCE',
            isLive: false,
          });
        }
      }
    }

    // 3. Resolve DNS for top candidates (up to 20 to avoid slowing down)
    const list = Array.from(discoveredMap.values()).slice(0, 25);
    let liveCount = 0;

    await Promise.allSettled(
      list.map(async (item) => {
        try {
          const ips = await resolveDnsAsync(item.subdomain);
          if (ips && ips.length > 0) {
            item.ip = ips[0];
            item.isLive = true;
            liveCount++;
          }
        } catch {
          item.isLive = false;
        }
      })
    );

    // 4. Generate Security Findings for risky subdomains
    const devStaging = list.filter((s) => s.isLive && s.category === 'DEV_STAGING');
    if (devStaging.length > 0) {
      findings.push({
        title: `Publicly Accessible Development/Staging Subdomains Detected (${devStaging.length} hosts)`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        category: 'ATTACK_SURFACE_EXPOSURE',
        sourceRuleId: 'recon.exposed-dev-environment',
        targetUrl: `https://${cleanDomain}`,
        evidenceSummary: `Active non-production environments found: ${devStaging.map((s) => `${s.subdomain} (${s.ip})`).join(', ')}. Development environments frequently lack WAFs, have debug mode enabled, or expose sensitive test credentials.`,
        remediation: 'Restrict access to non-production environments using IP allowlists, VPN, or HTTP basic authentication.',
        cwe: 'CWE-200',
      });
    }

    const adminSubdomains = list.filter((s) => s.isLive && s.category === 'ADMIN');
    if (adminSubdomains.length > 0) {
      findings.push({
        title: `Public Administrative Subdomain Exposed (${adminSubdomains.length} hosts)`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        category: 'ATTACK_SURFACE_EXPOSURE',
        sourceRuleId: 'recon.exposed-admin-portal',
        targetUrl: `https://${cleanDomain}`,
        evidenceSummary: `Publicly resolvable admin portals: ${adminSubdomains.map((s) => s.subdomain).join(', ')}`,
        remediation: 'Enforce MFA and place administrative portals behind an internal zero-trust proxy (e.g. Cloudflare Access).',
        cwe: 'CWE-284',
      });
    }

    return {
      domain: cleanDomain,
      totalFound: list.length,
      liveCount,
      subdomains: list,
      findings,
    };
  }

  private static categorize(subdomain: string): DiscoveredSubdomain['category'] {
    const s = subdomain.toLowerCase();
    if (s.includes('admin') || s.includes('manage') || s.includes('cpanel') || s.includes('internal')) return 'ADMIN';
    if (s.includes('api') || s.includes('gateway') || s.includes('graphql')) return 'API';
    if (s.includes('dev') || s.includes('staging') || s.includes('test') || s.includes('qa') || s.includes('uat')) return 'DEV_STAGING';
    if (s.includes('auth') || s.includes('sso') || s.includes('login') || s.includes('idp')) return 'AUTH';
    if (s.includes('cdn') || s.includes('static') || s.includes('assets') || s.includes('media')) return 'ASSETS';
    if (s.includes('mail') || s.includes('smtp') || s.includes('mx')) return 'MAIL';
    return 'GENERAL';
  }
}
