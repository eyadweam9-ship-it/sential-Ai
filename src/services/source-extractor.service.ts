import fs from 'fs';
import path from 'path';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface SourceExtractionResult {
  extractedDir?: string;
  extractedFilesCount: number;
  mapSourcesFound: boolean;
  exposedGit: boolean;
  exposedBackups: string[];
  findings: RawToolFinding[];
}

/**
 * Probes for exposed JavaScript Source Maps (.js.map), exposed .git repositories,
 * and exposed backup archives from a live target URL.
 * If source maps or archives are found, reconstructs original source code files
 * into a local workspace directory so SAST engines (Semgrep, CodeQL, Gitleaks, Checkov)
 * can deeply audit the target's underlying source code.
 */
export async function extractSourcesFromTarget(
  targetUrlStr: string,
  scanId: number
): Promise<SourceExtractionResult> {
  const result: SourceExtractionResult = {
    extractedFilesCount: 0,
    mapSourcesFound: false,
    exposedGit: false,
    exposedBackups: [],
    findings: [],
  };

  let targetUrl: URL;
  try {
    targetUrl = new URL(targetUrlStr);
  } catch {
    targetUrl = new URL(`https://${targetUrlStr}`);
  }

  const outputDir = path.join(process.cwd(), 'storage', 'extracted-sources', `scan-${scanId}`);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // 1. Probe for Exposed Git Repository (.git/config)
  try {
    const gitConfigUrl = new URL('/.git/config', targetUrl);
    const gitRes = await fetch(gitConfigUrl.toString(), {
      headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
      signal: AbortSignal.timeout(4000),
    });

    if (gitRes.status === 200) {
      const gitText = await gitRes.text();
      if (gitText.includes('[core]') || gitText.includes('repositoryformatversion')) {
        result.exposedGit = true;
        result.findings.push({
          title: 'Exposed Git Version Control Repository (.git)',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          category: 'INFORMATION_DISCLOSURE',
          sourceRuleId: 'recon.git-repo-exposure',
          targetUrl: gitConfigUrl.toString(),
          evidenceSummary: 'The /.git/ directory is publicly accessible. Attackers can clone and inspect the entire repository history, commit logs, and source code.',
          rawSnippet: gitText.slice(0, 300),
          remediation: 'Configure the web server (Nginx/Apache/Cloudflare) to deny public HTTP access to all hidden dot-directories and /.git/* files.',
          cwe: 'CWE-200',
        });
      }
    }
  } catch {}

  // 2. Probe for Common Source Code Backup Archives (/backup.zip, /source.zip, etc.)
  const commonBackupPaths = ['/backup.zip', '/source.zip', '/app.zip', '/src.zip', '/archive.tar.gz'];
  for (const bPath of commonBackupPaths) {
    try {
      const bUrl = new URL(bPath, targetUrl);
      const bRes = await fetch(bUrl.toString(), {
        method: 'HEAD',
        headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
        signal: AbortSignal.timeout(3000),
      });

      if (bRes.status === 200) {
        const cType = bRes.headers.get('content-type') || '';
        const cLen = parseInt(bRes.headers.get('content-length') || '0', 10);
        if (cType.includes('zip') || cType.includes('tar') || cType.includes('octet-stream') || cLen > 1000) {
          result.exposedBackups.push(bPath);
          result.findings.push({
            title: `Exposed Source Code Archive (${bPath})`,
            severity: 'CRITICAL',
            confidence: 'CONFIRMED',
            category: 'INFORMATION_DISCLOSURE',
            sourceRuleId: 'recon.exposed-backup-archive',
            targetUrl: bUrl.toString(),
            evidenceSummary: `Publicly downloadable archive file "${bPath}" discovered on web root (${Math.round(cLen / 1024)} KB).`,
            rawSnippet: `HTTP HEAD ${bPath}\nStatus: 200 OK\nContent-Type: ${cType}\nContent-Length: ${cLen} bytes`,
            remediation: 'Immediately remove temporary backup and archive files from production web-accessible root directories.',
            cwe: 'CWE-530',
          });
        }
      }
    } catch {}
  }

  // 3. Probe and Extract JavaScript Source Maps (.js.map)
  try {
    const rootRes = await fetch(targetUrl.toString(), {
      headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
      signal: AbortSignal.timeout(5000),
    });

    if (rootRes.ok) {
      const html = await rootRes.text();
      // Extract script src attributes
      const scriptRegex = /<script\b[^>]*\bsrc=['"]([^'"]+)['"]/gi;
      let match: RegExpExecArray | null;
      const scriptUrls: string[] = [];

      while ((match = scriptRegex.exec(html)) !== null) {
        const src = match[1];
        if (src && !src.startsWith('data:') && !src.startsWith('chrome-extension')) {
          try {
            const resolved = new URL(src, targetUrl).toString();
            if (new URL(resolved).hostname === targetUrl.hostname) {
              scriptUrls.push(resolved);
            }
          } catch {}
        }
      }

      // Add common sourcemap paths
      const mapCandidates = new Set<string>();
      for (const sUrl of scriptUrls.slice(0, 8)) {
        mapCandidates.add(`${sUrl}.map`);
      }
      mapCandidates.add(new URL('/main.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/app.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/bundle.js.map', targetUrl).toString());

      for (const mapUrl of mapCandidates) {
        if (result.extractedFilesCount >= 50) break;
        try {
          const mapRes = await fetch(mapUrl, {
            headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
            signal: AbortSignal.timeout(4000),
          });

          if (mapRes.status === 200) {
            const rawMapText = await mapRes.text();
            if (rawMapText.startsWith('{') && rawMapText.includes('"sources"') && rawMapText.includes('"sourcesContent"')) {
              try {
                const mapJson = JSON.parse(rawMapText);
                if (Array.isArray(mapJson.sources) && Array.isArray(mapJson.sourcesContent)) {
                  result.mapSourcesFound = true;

                  for (let i = 0; i < mapJson.sources.length; i++) {
                    const sourceRelPath = mapJson.sources[i];
                    const sourceCode = mapJson.sourcesContent[i];

                    if (sourceRelPath && typeof sourceCode === 'string' && sourceCode.trim().length > 10) {
                      // Normalize safe relative file path
                      const cleanRel = sourceRelPath
                        .replace(/^webpack:\/\/\/?/, '')
                        .replace(/^\.\.\//, '')
                        .replace(/^[/\\]+/, '')
                        .replace(/[:*?"<>|]/g, '_');

                      const destPath = path.join(outputDir, cleanRel);
                      const destDir = path.dirname(destPath);
                      if (!fs.existsSync(destDir)) {
                        fs.mkdirSync(destDir, { recursive: true });
                      }

                      fs.writeFileSync(destPath, sourceCode, 'utf8');
                      result.extractedFilesCount++;
                    }
                  }

                  if (result.extractedFilesCount > 0) {
                    result.extractedDir = outputDir;
                    result.findings.push({
                      title: 'Exposed Production JavaScript Source Map (.js.map)',
                      severity: 'HIGH',
                      confidence: 'CONFIRMED',
                      category: 'INFORMATION_DISCLOSURE',
                      sourceRuleId: 'recon.sourcemap-exposure',
                      targetUrl: mapUrl,
                      evidenceSummary: `Publicly readable source map discovered at ${mapUrl}. Successfully reconstructed ${result.extractedFilesCount} original unminified source code files for deep SAST inspection.`,
                      rawSnippet: `Source Map: ${mapUrl}\nExtracted Files: ${result.extractedFilesCount}\nSample Components: ${mapJson.sources.slice(0, 5).join(', ')}`,
                      remediation: 'Disable production source map generation in build tools (e.g. set `productionSourceMap: false` in webpack/vite/next.config.js) or block access to *.map files in web server rules.',
                      cwe: 'CWE-540',
                    });
                  }
                }
              } catch {}
            }
          }
        } catch {}
      }
    }
  } catch {}

  return result;
}
