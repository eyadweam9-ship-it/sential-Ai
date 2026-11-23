import crypto from 'crypto';
import http from 'http';
import https from 'https';

export interface EndpointFingerprint {
  url: string;
  etag?: string;
  lastModified?: string;
  contentHash: string;
  statusCode: number;
  contentLength: number;
  lastScannedAt: number;
}

export interface DeltaScanResult {
  url: string;
  status: 'NEW' | 'MODIFIED' | 'UNMODIFIED';
  reason: string;
  fingerprint: EndpointFingerprint;
}

export class DeltaScannerService {
  private static instance: DeltaScannerService;
  // In-memory fingerprint cache keyed by URL
  private fingerprints = new Map<string, EndpointFingerprint>();

  private constructor() {}

  public static getInstance(): DeltaScannerService {
    if (!DeltaScannerService.instance) {
      DeltaScannerService.instance = new DeltaScannerService();
    }
    return DeltaScannerService.instance;
  }

  /**
   * Evaluates whether an endpoint needs a full scan or can be skipped via incremental delta
   */
  public async evaluateEndpoint(targetUrl: string): Promise<DeltaScanResult> {
    const previous = this.fingerprints.get(targetUrl);
    const current = await this.probeFingerprint(targetUrl);

    if (!previous) {
      this.fingerprints.set(targetUrl, current);
      return {
        url: targetUrl,
        status: 'NEW',
        reason: 'First time scanned (No previous baseline found)',
        fingerprint: current,
      };
    }

    // Check ETag
    if (previous.etag && current.etag && previous.etag === current.etag) {
      return {
        url: targetUrl,
        status: 'UNMODIFIED',
        reason: `ETag matched previous baseline: ${current.etag}`,
        fingerprint: current,
      };
    }

    // Check Last-Modified
    if (previous.lastModified && current.lastModified && previous.lastModified === current.lastModified) {
      return {
        url: targetUrl,
        status: 'UNMODIFIED',
        reason: `Last-Modified timestamp unchanged: ${current.lastModified}`,
        fingerprint: current,
      };
    }

    // Check Content Hash
    if (previous.contentHash === current.contentHash && current.contentHash !== '') {
      return {
        url: targetUrl,
        status: 'UNMODIFIED',
        reason: 'Content SHA-256 hash identical to previous scan',
        fingerprint: current,
      };
    }

    // Otherwise it has modified
    this.fingerprints.set(targetUrl, current);
    return {
      url: targetUrl,
      status: 'MODIFIED',
      reason: 'Content or response headers modified since last scan',
      fingerprint: current,
    };
  }

  /**
   * Fast probe to gather endpoint metadata and content hash
   */
  private async probeFingerprint(targetUrl: string): Promise<EndpointFingerprint> {
    return new Promise<EndpointFingerprint>((resolve) => {
      try {
        const parsed = new URL(targetUrl);
        const isHttps = parsed.protocol === 'https:';
        const client = isHttps ? https : http;

        const req = client.request(
          targetUrl,
          {
            method: 'GET',
            timeout: 5000,
            headers: {
              'User-Agent': 'Sential-AI-DeltaScanner/2.0',
              Accept: '*/*',
            },
          },
          (res) => {
            let data = '';
            res.on('data', (chunk) => {
              if (data.length < 200000) {
                // Read up to 200KB for fingerprinting
                data += chunk.toString();
              }
            });

            res.on('end', () => {
              const hash = crypto.createHash('sha256').update(data).digest('hex');
              resolve({
                url: targetUrl,
                etag: res.headers.etag as string | undefined,
                lastModified: res.headers['last-modified'] as string | undefined,
                contentHash: hash,
                statusCode: res.statusCode || 200,
                contentLength: Number(res.headers['content-length'] || data.length),
                lastScannedAt: Date.now(),
              });
            });
          }
        );

        req.on('error', () => {
          resolve({
            url: targetUrl,
            contentHash: '',
            statusCode: 0,
            contentLength: 0,
            lastScannedAt: Date.now(),
          });
        });

        req.on('timeout', () => {
          req.destroy();
          resolve({
            url: targetUrl,
            contentHash: '',
            statusCode: 408,
            contentLength: 0,
            lastScannedAt: Date.now(),
          });
        });

        req.end();
      } catch {
        resolve({
          url: targetUrl,
          contentHash: '',
          statusCode: 500,
          contentLength: 0,
          lastScannedAt: Date.now(),
        });
      }
    });
  }

  public getCacheStats(): { totalCached: number; urls: string[] } {
    return {
      totalCached: this.fingerprints.size,
      urls: Array.from(this.fingerprints.keys()),
    };
  }

  public clearCache() {
    this.fingerprints.clear();
  }
}
