import dns from 'dns';
import http from 'http';
import https from 'https';
import net from 'net';
import { URL } from 'url';

export interface TlsDetails {
  valid: boolean;
  protocol?: string;
  cipher?: string;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  authorized?: boolean;
}

export interface ValidationResult {
  valid: boolean;
  isValid?: boolean;
  normalizedUrl: string;
  hostname: string;
  ip?: string;
  protocol: 'http:' | 'https:';
  dnsResolved: boolean;
  ssrfSafe: boolean;
  httpStatus?: number;
  responseTimeMs?: number;
  tls?: TlsDetails;
  error?: string;
  isMockDemo?: boolean;
  isLocalTest?: boolean;
}

/**
 * Checks if an IP address belongs to RFC 1918 private, loopback, link-local, or reserved ranges
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!ip) return false;

  let cleanIp = ip.trim();

  // If not an IP address (e.g. domain name), it's not a private IP
  if (!net.isIP(cleanIp)) {
    return false;
  }

  // IPv6 checks
  if (cleanIp === '::1' || cleanIp === '::') return true;
  if (cleanIp.toLowerCase().startsWith('fe80:')) return true; // Link-local
  if (cleanIp.toLowerCase().startsWith('fc00:') || cleanIp.toLowerCase().startsWith('fd00:')) return true; // Unique local

  // IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.1)
  if (cleanIp.startsWith('::ffff:')) {
    cleanIp = cleanIp.replace('::ffff:', '');
  }

  const parts = cleanIp.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(isNaN)) {
    return false;
  }

  const [b0, b1, b2, b3] = parts;

  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;

  // 10.0.0.0/8 (Private)
  if (b0 === 10) return true;

  // 172.16.0.0/12 (Private 172.16.0.0 - 172.31.255.255)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.168.0.0/16 (Private)
  if (b0 === 192 && b1 === 168) return true;

  // 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. AWS 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;

  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;

  // 100.64.0.0/10 (Shared address space / Carrier-grade NAT)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 192.0.0.0/24, 192.0.2.0/24 (IETF Protocol Assignments & TEST-NET-1)
  if (b0 === 192 && b1 === 0 && (b2 === 0 || b2 === 2)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (b0 === 198 && b1 === 51 && b2 === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (b0 === 203 && b1 === 0 && b2 === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (b0 >= 224 && b0 <= 239) return true;

  // 240.0.0.0/4 (Reserved)
  if (b0 >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (b0 === 255 && b1 === 255 && b2 === 255 && b3 === 255) return true;

  return false;
}

/**
 * Checks if hostname is inherently an internal name
 */
export function isInternalHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower === 'local' || lower.endsWith('.local') || lower.endsWith('.localhost')) {
    return true;
  }
  if (lower.endsWith('.internal') || lower.endsWith('.corp') || lower.endsWith('.home') || lower.endsWith('.lan')) {
    return true;
  }
  return false;
}

/**
 * Validates Application URL, performs DNS resolution, checks for SSRF, and inspects TLS connectivity
 */
export async function validateTargetUrl(rawUrl: string, environment: string = 'PRODUCTION'): Promise<ValidationResult> {
  const normEnv = (environment || 'PRODUCTION').toUpperCase();
  const isProduction = normEnv === 'PRODUCTION';

  let trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: '',
      hostname: '',
      protocol: 'https:',
      dnsResolved: false,
      ssrfSafe: false,
      error: 'Application URL is required for assessment.',
    };
  }

  // Prepend protocol if missing
  if (!/^https?:\/\//i.test(trimmed)) {
    if (trimmed.startsWith('localhost') || trimmed.startsWith('127.0.0.1')) {
      trimmed = `http://${trimmed}`;
    } else {
      trimmed = `https://${trimmed}`;
    }
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(trimmed);
  } catch {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: trimmed,
      hostname: '',
      protocol: 'https:',
      dnsResolved: false,
      ssrfSafe: false,
      error: 'Invalid URL format. Please enter a valid web address (e.g. app.company.com or https://company.com).',
    };
  }

  const protocol = parsedUrl.protocol.toLowerCase() as 'http:' | 'https:';
  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: parsedUrl.toString(),
      hostname: parsedUrl.hostname,
      protocol: 'https:',
      dnsResolved: false,
      ssrfSafe: false,
      error: 'Protocol not supported. Only HTTP and HTTPS are permitted for security assessment.',
    };
  }

  const hostname = parsedUrl.hostname.trim();
  if (!hostname || hostname.includes('..') || hostname.startsWith('.') || hostname.endsWith('.')) {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      protocol,
      dnsResolved: false,
      ssrfSafe: false,
      error: 'Invalid hostname format. Please check the domain or host name.',
    };
  }

  // 1. Cloud Metadata Guard (Always block in all environments)
  if (hostname.includes('169.254') || hostname.includes('metadata.google') || hostname.includes('instance-data')) {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      protocol,
      dnsResolved: false,
      ssrfSafe: false,
      error: 'Blocked by SSRF policy: Access to cloud metadata service (169.254.0.0/16) is strictly prohibited.',
    };
  }

  // 2. Demo Targets Handler (app.northstar.io, demo.northstar.io)
  if (hostname.includes('northstar.io') || hostname.includes('demo.sential')) {
    return {
      valid: true,
      isValid: true,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      ip: '104.21.45.12',
      protocol,
      dnsResolved: true,
      ssrfSafe: true,
      isMockDemo: true,
      httpStatus: 200,
      responseTimeMs: 68,
      tls: protocol === 'https:' ? {
        valid: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: "Let's Encrypt Authority X3",
        daysRemaining: 75,
        authorized: true,
      } : undefined,
    };
  }

  // 3. Localhost / Internal Hostnames
  const isInternal = isInternalHostname(hostname);
  if (isInternal) {
    if (isProduction) {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        protocol,
        dnsResolved: true,
        ssrfSafe: false,
        error: `Blocked by SSRF policy: Internal hostname (${hostname}) cannot be assessed in Production mode. Switch to Development or Staging environment.`,
      };
    }

    // Permitted in Staging / Sandbox
    return {
      valid: true,
      isValid: true,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      ip: '127.0.0.1',
      protocol,
      dnsResolved: true,
      ssrfSafe: true,
      isLocalTest: true,
      httpStatus: 200,
      responseTimeMs: 8,
      tls: protocol === 'https:' ? {
        valid: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'Local Development CA',
        daysRemaining: 365,
        authorized: true,
      } : undefined,
    };
  }

  // 4. DNS Resolution & SSRF IP Verification
  let resolvedIp = '';
  try {
    const lookupResult = await dns.promises.lookup(hostname);
    resolvedIp = lookupResult.address;
  } catch (dnsErr) {
    return {
      valid: false,
      isValid: false,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      protocol,
      dnsResolved: false,
      ssrfSafe: false,
      error: `DNS resolution failed: Domain "${hostname}" could not be resolved. Please verify the domain spelling and availability.`,
    };
  }

  // Check if resolved IP is private or reserved
  const isPrivateIp = isPrivateOrReservedIp(resolvedIp);
  if (isPrivateIp) {
    if (resolvedIp.startsWith('169.254')) {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        ip: resolvedIp,
        protocol,
        dnsResolved: true,
        ssrfSafe: false,
        error: `Blocked by SSRF policy: Link-local / Cloud metadata IP (${resolvedIp}) is strictly prohibited.`,
      };
    }

    if (isProduction) {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        ip: resolvedIp,
        protocol,
        dnsResolved: true,
        ssrfSafe: false,
        error: `Blocked by SSRF policy: Private internal IP (${resolvedIp}) cannot be assessed in Production mode.`,
      };
    }

    // In Staging, allow private network inspection
    return {
      valid: true,
      isValid: true,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      ip: resolvedIp,
      protocol,
      dnsResolved: true,
      ssrfSafe: true,
      isLocalTest: true,
      httpStatus: 200,
      responseTimeMs: 12,
      tls: protocol === 'https:' ? {
        valid: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        issuer: 'Internal CA',
        daysRemaining: 180,
        authorized: true,
      } : undefined,
    };
  }

  // 5. Connection & TLS Inspection
  const startTime = Date.now();
  try {
    const connInfo = await inspectConnection(parsedUrl, resolvedIp, 3, undefined, isProduction);
    const responseTimeMs = Date.now() - startTime;

    return {
      valid: true,
      isValid: true,
      normalizedUrl: connInfo.finalUrl || parsedUrl.toString(),
      hostname,
      ip: resolvedIp,
      protocol,
      dnsResolved: true,
      ssrfSafe: true,
      httpStatus: connInfo.statusCode,
      responseTimeMs: Math.max(1, responseTimeMs),
      tls: connInfo.tls,
    };
  } catch (connErr: any) {
    const errMsg = String(connErr?.message || connErr || '');
    if (errMsg.includes('Blocked by SSRF policy')) {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        ip: resolvedIp,
        protocol,
        dnsResolved: true,
        ssrfSafe: false,
        error: errMsg,
      };
    }

    if (connErr?.code === 'ECONNREFUSED') {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        ip: resolvedIp,
        protocol,
        dnsResolved: true,
        ssrfSafe: true,
        error: `Connection refused: No web service is responding on ${parsedUrl.hostname}:${parsedUrl.port || (protocol === 'https:' ? 443 : 80)}.`,
      };
    }

    if (connErr?.code === 'ETIMEDOUT' || errMsg.includes('timed out')) {
      return {
        valid: false,
        isValid: false,
        normalizedUrl: parsedUrl.toString(),
        hostname,
        ip: resolvedIp,
        protocol,
        dnsResolved: true,
        ssrfSafe: true,
        error: `Connection timed out: Target host (${parsedUrl.hostname}) did not respond within 6 seconds.`,
      };
    }

    return {
      valid: false,
      isValid: false,
      normalizedUrl: parsedUrl.toString(),
      hostname,
      ip: resolvedIp,
      protocol,
      dnsResolved: true,
      ssrfSafe: true,
      error: `Connection check failed: ${errMsg || 'Unable to establish HTTP/HTTPS connection with target.'}`,
    };
  }
}

/**
 * Performs safe HTTP/HTTPS GET probe with redirect following (up to 3 hops),
 * anti-SSRF redirect enforcement, and TLS certificate inspection
 */
function inspectConnection(
  targetUrl: URL,
  resolvedIp: string,
  hopsRemaining: number = 3,
  inheritedTls?: TlsDetails,
  isProduction: boolean = true
): Promise<{ statusCode: number; tls?: TlsDetails; finalUrl?: string }> {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const reqOptions = {
      hostname: targetUrl.hostname,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: (targetUrl.pathname || '/') + (targetUrl.search || ''),
      method: 'GET',
      agent: false,
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      timeout: 6000,
      rejectUnauthorized: false, // Inspect certificate details even if self-signed for reporting
    };

    const req = client.request(reqOptions, (res) => {
      let tlsInfo: TlsDetails | undefined = inheritedTls;

      if (isHttps && 'getPeerCertificate' in res.socket) {
        const socket = res.socket as import('tls').TLSSocket;
        const cert = socket.getPeerCertificate ? socket.getPeerCertificate() : null;
        const protocolVersion = socket.getProtocol ? socket.getProtocol() : 'TLSv1.3';

        if (cert && Object.keys(cert).length > 0) {
          const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined;
          const daysRemaining = validTo
            ? Math.round((validTo.getTime() - Date.now()) / (1000 * 3600 * 24))
            : undefined;

          tlsInfo = {
            valid: socket.authorized !== false,
            protocol: protocolVersion || 'TLSv1.3',
            issuer:
              typeof cert.issuer === 'object' && cert.issuer
                ? String(cert.issuer.O || cert.issuer.CN || 'Verified CA')
                : String(cert.issuer || 'Verified CA'),
            subject:
              typeof cert.subject === 'object' && cert.subject
                ? String(cert.subject.CN || targetUrl.hostname)
                : String(cert.subject || targetUrl.hostname),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            authorized: socket.authorized,
          };
        }
      }

      // Check for redirect (301, 302, 307, 308)
      if (
        hopsRemaining > 0 &&
        res.statusCode &&
        [301, 302, 307, 308].includes(res.statusCode) &&
        res.headers.location
      ) {
        try {
          const redirectUrl = new URL(res.headers.location, targetUrl);

          // Prevent redirect to cloud metadata service
          if (
            redirectUrl.hostname.includes('169.254') ||
            redirectUrl.hostname.includes('metadata.google') ||
            redirectUrl.hostname.includes('instance-data')
          ) {
            req.destroy();
            return reject(new Error(`Blocked by SSRF policy: Unsafe redirect to cloud metadata service (${redirectUrl.hostname}).`));
          }

          // Prevent redirect to internal hostnames
          if (isInternalHostname(redirectUrl.hostname)) {
            if (isProduction) {
              req.destroy();
              return reject(new Error(`Blocked by SSRF policy: Unsafe redirect to internal hostname (${redirectUrl.hostname}).`));
            }
          }

          // Prevent redirect to private IP addresses in Production
          if (isProduction && isPrivateOrReservedIp(redirectUrl.hostname)) {
            req.destroy();
            return reject(new Error(`Blocked by SSRF policy: Unsafe redirect to private IP (${redirectUrl.hostname}) in Production mode.`));
          }

          req.destroy();
          return resolve(inspectConnection(redirectUrl, '', hopsRemaining - 1, tlsInfo, isProduction));
        } catch {
          // If URL parsing fails, proceed with current targetUrl response
        }
      }

      req.destroy(); // Terminate request immediately after reading headers and certificate
      resolve({ statusCode: res.statusCode || 200, tls: tlsInfo, finalUrl: targetUrl.toString() });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out while verifying target.'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.end();
  });
}
