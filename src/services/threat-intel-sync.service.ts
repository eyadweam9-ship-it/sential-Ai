import dns from 'dns';
import fs from 'fs';
import path from 'path';

// Force IPv4 first to prevent Windows dual-stack IPv6 DNS resolution timeouts
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {}

export interface DependencyItem {
  name: string;
  version: string;
  ecosystem?: 'npm' | 'PyPI' | 'Packagist' | 'Go' | 'Maven' | 'crates.io' | 'NuGet' | string;
}

export interface ThreatIntelAdvisory {
  id: string;
  aliases: string[];
  summary: string;
  details?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cweIds: string[];
  cvssScore?: number;
  fixedVersion?: string;
  affectedPackage: string;
  ecosystem: string;
  targetVersion: string;
  references: string[];
  publishedAt?: string;
}

export interface ThreatIntelScanResult {
  dependenciesScanned: number;
  vulnerableDependenciesCount: number;
  totalAdvisoriesFound: number;
  advisories: ThreatIntelAdvisory[];
  fromCacheCount: number;
  fromLiveApiCount: number;
  durationMs: number;
}

interface CacheEntry {
  advisory: ThreatIntelAdvisory;
  timestamp: number;
}

export class ThreatIntelSyncService {
  private cachePath: string;
  private memoryCache: Map<string, CacheEntry> = new Map();
  private isCacheLoaded = false;
  private readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  constructor() {
    this.cachePath = path.join(process.cwd(), 'storage', 'cache', 'threat_intel_cache.json');
    this.loadCache();
  }

  private loadCache(): void {
    try {
      if (fs.existsSync(this.cachePath)) {
        const raw = fs.readFileSync(this.cachePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (typeof parsed === 'object' && parsed !== null) {
          for (const [key, val] of Object.entries(parsed)) {
            this.memoryCache.set(key, val as CacheEntry);
          }
        }
      }
      this.isCacheLoaded = true;
    } catch {
      this.isCacheLoaded = true;
    }
  }

  private saveCache(): void {
    try {
      const cacheDir = path.dirname(this.cachePath);
      if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true });
      }
      const serializable: Record<string, CacheEntry> = {};
      for (const [k, v] of this.memoryCache.entries()) {
        serializable[k] = v;
      }
      fs.writeFileSync(this.cachePath, JSON.stringify(serializable, null, 2), 'utf8');
    } catch {}
  }

  /**
   * Infer ecosystem from package manifest filename
   */
  public inferEcosystemFromFilename(filename: string): string {
    const lower = path.basename(filename).toLowerCase();
    if (lower === 'package.json' || lower === 'package-lock.json' || lower === 'yarn.lock' || lower === 'pnpm-lock.yaml') {
      return 'npm';
    }
    if (lower === 'requirements.txt' || lower === 'pipfile' || lower === 'pipfile.lock' || lower === 'pyproject.toml') {
      return 'PyPI';
    }
    if (lower === 'composer.json' || lower === 'composer.lock') {
      return 'Packagist';
    }
    if (lower === 'go.mod' || lower === 'go.sum') {
      return 'Go';
    }
    if (lower === 'pom.xml' || lower.endsWith('.gradle') || lower.endsWith('.gradle.kts')) {
      return 'Maven';
    }
    if (lower === 'cargo.toml' || lower === 'cargo.lock') {
      return 'crates.io';
    }
    return 'npm';
  }

  /**
   * Extract dependencies list from manifest file content
   */
  public parseManifest(filename: string, content: string): DependencyItem[] {
    const ecosystem = this.inferEcosystemFromFilename(filename);
    const deps: DependencyItem[] = [];

    try {
      if (ecosystem === 'npm') {
        const json = JSON.parse(content);
        const allDeps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
        for (const [name, rawVer] of Object.entries(allDeps)) {
          const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, '');
          if (cleanVer && cleanVer !== '*' && cleanVer !== 'latest') {
            deps.push({ name, version: cleanVer, ecosystem: 'npm' });
          }
        }
      } else if (ecosystem === 'PyPI') {
        const lines = content.split('\n');
        for (const rawLine of lines) {
          const line = rawLine.trim().split('#')[0].trim();
          if (!line || line.startsWith('-')) continue;
          const match = line.match(/^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)(.+)$/);
          if (match) {
            deps.push({ name: match[1].trim(), version: match[2].trim(), ecosystem: 'PyPI' });
          }
        }
      } else if (ecosystem === 'Packagist') {
        const json = JSON.parse(content);
        const allReqs = { ...(json.require || {}), ...(json['require-dev'] || {}) };
        for (const [name, rawVer] of Object.entries(allReqs)) {
          if (name === 'php' || name.startsWith('ext-')) continue;
          const cleanVer = String(rawVer).replace(/^[\^~>=<\s]+/, '');
          if (cleanVer && cleanVer !== '*') {
            deps.push({ name, version: cleanVer, ecosystem: 'Packagist' });
          }
        }
      } else if (ecosystem === 'Go') {
        const lines = content.split('\n');
        let inRequireBlock = false;
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (line.startsWith('require (')) {
            inRequireBlock = true;
            continue;
          }
          if (inRequireBlock && line === ')') {
            inRequireBlock = false;
            continue;
          }
          if (line.startsWith('require ')) {
            const parts = line.replace('require ', '').trim().split(/\s+/);
            if (parts.length >= 2) {
              deps.push({ name: parts[0], version: parts[1].replace(/^v/, ''), ecosystem: 'Go' });
            }
          } else if (inRequireBlock) {
            const parts = line.split(/\s+/);
            if (parts.length >= 2) {
              deps.push({ name: parts[0], version: parts[1].replace(/^v/, ''), ecosystem: 'Go' });
            }
          }
        }
      }
    } catch {}

    return deps;
  }

  /**
   * Fetch full advisory details for a given vulnerability ID (with cache)
   */
  public async getAdvisoryDetails(
    vulnId: string,
    packageName: string,
    targetVersion: string,
    ecosystem: string
  ): Promise<ThreatIntelAdvisory | null> {
    const cacheKey = `adv:${vulnId}`;
    const now = Date.now();

    if (this.memoryCache.has(cacheKey)) {
      const entry = this.memoryCache.get(cacheKey)!;
      if (now - entry.timestamp < this.CACHE_TTL_MS) {
        return {
          ...entry.advisory,
          affectedPackage: packageName,
          targetVersion,
          ecosystem,
        };
      }
    }

    try {
      const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'SentinelAI-ThreatIntel/2.0',
        },
        signal: AbortSignal.timeout(6000),
      });

      if (!res.ok) return null;
      const data: any = await res.json();

      // Determine severity
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
      if (data.database_specific?.severity) {
        const dbSev = String(data.database_specific.severity).toUpperCase();
        if (dbSev.includes('CRITICAL')) severity = 'CRITICAL';
        else if (dbSev.includes('HIGH')) severity = 'HIGH';
        else if (dbSev.includes('MODERATE') || dbSev.includes('MEDIUM')) severity = 'MEDIUM';
        else if (dbSev.includes('LOW')) severity = 'LOW';
      }

      // Extract fixed version
      let fixedVersion: string | undefined;
      if (Array.isArray(data.affected)) {
        for (const aff of data.affected) {
          if (Array.isArray(aff.ranges)) {
            for (const r of aff.ranges) {
              if (Array.isArray(r.events)) {
                for (const ev of r.events) {
                  if (ev.fixed) {
                    fixedVersion = ev.fixed;
                    break;
                  }
                }
              }
              if (fixedVersion) break;
            }
          }
          if (fixedVersion) break;
        }
      }

      // Extract CWE IDs
      const cweIds: string[] = [];
      if (Array.isArray(data.database_specific?.cwe_ids)) {
        cweIds.push(...data.database_specific.cwe_ids);
      }

      // Extract references
      const references: string[] = [];
      if (Array.isArray(data.references)) {
        references.push(...data.references.map((r: any) => (typeof r === 'string' ? r : r.url)).filter(Boolean));
      }

      const advisory: ThreatIntelAdvisory = {
        id: data.id || vulnId,
        aliases: Array.isArray(data.aliases) ? data.aliases : [],
        summary: data.summary || data.details?.slice(0, 120) || `Vulnerability in ${packageName}`,
        details: data.details,
        severity,
        cweIds: cweIds.length > 0 ? cweIds : ['CWE-1395'],
        fixedVersion,
        affectedPackage: packageName,
        ecosystem,
        targetVersion,
        references: references.slice(0, 5),
        publishedAt: data.published,
      };

      this.memoryCache.set(cacheKey, { advisory, timestamp: now });
      return advisory;
    } catch {
      return null;
    }
  }

  /**
   * Batch scan dependencies using OSV.dev querybatch API
   */
  public async batchScanDependencies(
    dependencies: DependencyItem[],
    concurrency = 40
  ): Promise<ThreatIntelScanResult> {
    const startTime = Date.now();
    const advisories: ThreatIntelAdvisory[] = [];
    let fromCacheCount = 0;
    let fromLiveApiCount = 0;

    if (!dependencies || dependencies.length === 0) {
      return {
        dependenciesScanned: 0,
        vulnerableDependenciesCount: 0,
        totalAdvisoriesFound: 0,
        advisories: [],
        fromCacheCount: 0,
        fromLiveApiCount: 0,
        durationMs: 0,
      };
    }

    const vulnerablePackages = new Set<string>();

    // Chunk into batches of up to `concurrency` (e.g. 40 items per querybatch request)
    const chunks: DependencyItem[][] = [];
    for (let i = 0; i < dependencies.length; i += concurrency) {
      chunks.push(dependencies.slice(i, i + concurrency));
    }

    for (const chunk of chunks) {
      const queries = chunk.map(d => ({
        package: {
          name: d.name,
          ecosystem: d.ecosystem || 'npm',
        },
        version: d.version,
      }));

      try {
        const res = await fetch('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'SentinelAI-ThreatIntel/2.0',
          },
          body: JSON.stringify({ queries }),
          signal: AbortSignal.timeout(10_000),
        });

        if (res.ok) {
          const data: any = await res.json();
          if (Array.isArray(data.results)) {
            // Process each query result
            for (let idx = 0; idx < data.results.length; idx++) {
              const resItem = data.results[idx];
              const depItem = chunk[idx];

              if (resItem.vulns && Array.isArray(resItem.vulns) && resItem.vulns.length > 0) {
                vulnerablePackages.add(`${depItem.ecosystem}:${depItem.name}`);

                // Fetch details for top 5 vulnerabilities per package to avoid rate limiting
                for (const v of resItem.vulns.slice(0, 5)) {
                  const cacheKey = `adv:${v.id}`;
                  if (this.memoryCache.has(cacheKey)) {
                    fromCacheCount++;
                    const cached = this.memoryCache.get(cacheKey)!.advisory;
                    advisories.push({
                      ...cached,
                      affectedPackage: depItem.name,
                      targetVersion: depItem.version,
                      ecosystem: depItem.ecosystem || 'npm',
                    });
                  } else {
                    fromLiveApiCount++;
                    const detail = await this.getAdvisoryDetails(
                      v.id,
                      depItem.name,
                      depItem.version,
                      depItem.ecosystem || 'npm'
                    );
                    if (detail) {
                      advisories.push(detail);
                    }
                  }
                }
              }
            }
          }
        }
      } catch (err) {
        console.warn('[ThreatIntelSync] Batch query skipped due to network/timeout:', (err as Error).message);
      }
    }

    // Persist any new cached advisories
    this.saveCache();

    return {
      dependenciesScanned: dependencies.length,
      vulnerableDependenciesCount: vulnerablePackages.size,
      totalAdvisoriesFound: advisories.length,
      advisories,
      fromCacheCount,
      fromLiveApiCount,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Search an advisory or CVE directly by identifier (e.g. CVE-2023-45857 or GHSA-8hc4-vh64-cxmj)
   */
  public async searchVulnerability(identifier: string): Promise<ThreatIntelAdvisory | null> {
    const cleanId = identifier.trim().toUpperCase();
    const cacheKey = `adv:${cleanId}`;

    if (this.memoryCache.has(cacheKey)) {
      return this.memoryCache.get(cacheKey)!.advisory;
    }

    try {
      const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cleanId)}`, {
        method: 'GET',
        headers: { 'User-Agent': 'SentinelAI-ThreatIntel/2.0' },
        signal: AbortSignal.timeout(6000),
      });

      if (!res.ok) return null;
      const data: any = await res.json();

      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
      if (data.database_specific?.severity) {
        const dbSev = String(data.database_specific.severity).toUpperCase();
        if (dbSev.includes('CRITICAL')) severity = 'CRITICAL';
        else if (dbSev.includes('HIGH')) severity = 'HIGH';
        else if (dbSev.includes('MODERATE') || dbSev.includes('MEDIUM')) severity = 'MEDIUM';
        else if (dbSev.includes('LOW')) severity = 'LOW';
      }

      const adv: ThreatIntelAdvisory = {
        id: data.id || cleanId,
        aliases: Array.isArray(data.aliases) ? data.aliases : [],
        summary: data.summary || data.details?.slice(0, 140) || cleanId,
        details: data.details,
        severity,
        cweIds: Array.isArray(data.database_specific?.cwe_ids) ? data.database_specific.cwe_ids : ['CWE-1395'],
        affectedPackage: data.affected?.[0]?.package?.name || 'Unknown',
        ecosystem: data.affected?.[0]?.package?.ecosystem || 'Generic',
        targetVersion: '*',
        references: Array.isArray(data.references) ? data.references.map((r: any) => (typeof r === 'string' ? r : r.url)).slice(0, 5) : [],
        publishedAt: data.published,
      };

      this.memoryCache.set(cacheKey, { advisory: adv, timestamp: Date.now() });
      this.saveCache();
      return adv;
    } catch {
      return null;
    }
  }

  /**
   * Return sync engine statistics
   */
  public getStats() {
    return {
      status: 'ONLINE',
      cachedAdvisoriesCount: this.memoryCache.size,
      cacheTtlHours: this.CACHE_TTL_MS / (1000 * 60 * 60),
      upstreamSources: [
        'Google Open Source Vulnerabilities (OSV.dev)',
        'GitHub Security Advisories (GHSA)',
        'National Vulnerability Database (NVD / CVE)',
        'PyPA Security Database (PyPI)',
        'Go Vulnerability Database',
        'RustSec Advisory Database',
        'FriendsOfPHP / Packagist Advisory Database',
      ],
      supportedEcosystems: ['npm', 'PyPI', 'Packagist', 'Go', 'Maven', 'crates.io', 'NuGet'],
    };
  }
}

export const threatIntelSyncService = new ThreatIntelSyncService();
