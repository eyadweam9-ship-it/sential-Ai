import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import AdmZip from 'adm-zip';
import { RawToolFinding } from '../tools/security-tool.interface';

export interface SourceExtractionResult {
  extractedDir?: string;
  extractedFilesCount: number;
  mapSourcesFound: boolean;
  exposedGit: boolean;
  exposedBackups: string[];
  isGitRepoCloned: boolean;
  findings: RawToolFinding[];
}

/**
 * Autonomous Source Code Extractor from URL
 * 1. Clones GitHub / GitLab / Bitbucket repositories directly when a repo link is provided.
 * 2. On live web URLs:
 *    - Reconstructs unminified original source files via JavaScript Source Maps (.js.map)
 *    - Probes for exposed .git version control repositories
 *    - Probes for downloadable source backup archives (/backup.zip, etc.)
 *    - Scrapes and de-bundles client-side scripts & inline script tags into local files
 * Enables 100% full SAST, Taint Flow, and AI Reasoning solely from a URL input!
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
    isGitRepoCloned: false,
    findings: [],
  };

  const outputDir = path.join(process.cwd(), 'storage', 'extracted-sources', `scan-${scanId}`);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const normalizedUrl = targetUrlStr.trim();

  // =========================================================================
  // 1. Git Repository Auto-Cloner (GitHub / GitLab / Bitbucket / .git)
  // =========================================================================
  const isGitRepo =
    /github\.com\/[^\/]+\/[^\/]+/i.test(normalizedUrl) ||
    /gitlab\.com\/[^\/]+\/[^\/]+/i.test(normalizedUrl) ||
    /bitbucket\.org\/[^\/]+\/[^\/]+/i.test(normalizedUrl) ||
    normalizedUrl.endsWith('.git');

  if (isGitRepo) {
    console.log(`[SourceExtractor] Detected Git Repository URL: ${normalizedUrl}. Initiating automated clone...`);
    
    // Clean URL: remove /tree/main, /blob/main, etc.
    let cleanGitUrl = normalizedUrl
      .replace(/\/tree\/[^\/]+.*$/i, '')
      .replace(/\/blob\/[^\/]+.*$/i, '')
      .replace(/\.git$/i, '');

    if (!cleanGitUrl.startsWith('http')) {
      cleanGitUrl = `https://${cleanGitUrl}`;
    }

    let cloneSuccess = false;

    // Strategy A: Local git clone --depth 1
    try {
      execSync(`git clone --depth 1 "${cleanGitUrl}" "${outputDir}"`, {
        timeout: 45000,
        stdio: 'pipe',
      });
      cloneSuccess = true;
      console.log(`[SourceExtractor] Successfully cloned repository via git CLI into ${outputDir}`);
    } catch (gitErr) {
      console.warn(`[SourceExtractor] git clone notice: ${(gitErr as Error).message}. Attempting ZIP archive fallback...`);
    }

    // Strategy B: Download ZIP archive via Codeload / API fallback
    if (!cloneSuccess && cleanGitUrl.includes('github.com')) {
      const match = cleanGitUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/i);
      if (match) {
        const owner = match[1];
        const repo = match[2];
        const branches = ['main', 'master', 'dev'];

        for (const branch of branches) {
          try {
            const zipUrl = `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${branch}`;
            const zipRes = await fetch(zipUrl, {
              headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
              signal: AbortSignal.timeout(15000),
            });

            if (zipRes.ok) {
              const arrayBuf = await zipRes.arrayBuffer();
              const zipBuffer = Buffer.from(arrayBuf);
              const zip = new AdmZip(zipBuffer);
              zip.extractAllTo(outputDir, true);
              cloneSuccess = true;
              console.log(`[SourceExtractor] Successfully downloaded and extracted GitHub archive for branch: ${branch}`);
              break;
            }
          } catch {}
        }
      }
    }

    if (cloneSuccess) {
      const totalFiles = countExtractedFiles(outputDir);
      if (totalFiles > 0) {
        result.isGitRepoCloned = true;
        result.extractedDir = outputDir;
        result.extractedFilesCount = totalFiles;

        result.findings.push({
          title: 'Source Code Repository Cloned for Full SAST & Taint Analysis',
          severity: 'LOW',
          confidence: 'CONFIRMED',
          category: 'RECON_DISCOVERY',
          sourceRuleId: 'recon.git-repo-cloned',
          targetUrl: cleanGitUrl,
          evidenceSummary: `Successfully extracted complete source tree from repository ${cleanGitUrl} (${totalFiles} source files). Full inter-procedural taint flow, AST signatures, and AI reasoning enabled.`,
          rawSnippet: `Repository: ${cleanGitUrl}\nTotal Classified Source Files: ${totalFiles}\nTarget Workspace: ${outputDir}`,
          remediation: 'Ensure private repository access tokens and secrets are not publicly exposed in committed files.',
          cwe: 'CWE-200',
        });

        return result;
      }
    }
  }

  // =========================================================================
  // 2. Live Web URL Source Code Extraction
  // =========================================================================
  let targetUrl: URL;
  try {
    targetUrl = new URL(normalizedUrl);
  } catch {
    targetUrl = new URL(`https://${normalizedUrl}`);
  }

  // Step A: Probe for Exposed Git Repository (/.git/config)
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
          evidenceSummary: 'The /.git/ directory is publicly accessible on the web root. Attackers can clone and inspect the entire repository history, commits, credentials, and source code.',
          rawSnippet: gitText.slice(0, 300),
          remediation: 'Configure the web server (Nginx/Apache/Cloudflare) to deny public HTTP access to all hidden dot-directories and /.git/* files.',
          cwe: 'CWE-200',
        });

        // Save .git/config into local target tree
        const gitDir = path.join(outputDir, '.git');
        fs.mkdirSync(gitDir, { recursive: true });
        fs.writeFileSync(path.join(gitDir, 'config'), gitText, 'utf8');
        result.extractedFilesCount++;
      }
    }
  } catch {}

  // Step B: Probe for Common Source Code Backup Archives
  const commonBackupPaths = [
    '/backup.zip',
    '/source.zip',
    '/app.zip',
    '/src.zip',
    '/code.zip',
    '/www.zip',
    '/site.zip',
    '/archive.tar.gz',
  ];

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

          // Download and extract if under 50MB
          if (cLen > 0 && cLen < 50 * 1024 * 1024 && cType.includes('zip')) {
            try {
              const fullRes = await fetch(bUrl.toString(), { signal: AbortSignal.timeout(15000) });
              if (fullRes.ok) {
                const buf = Buffer.from(await fullRes.arrayBuffer());
                const zip = new AdmZip(buf);
                zip.extractAllTo(outputDir, true);
                console.log(`[SourceExtractor] Successfully downloaded and extracted ${bPath}`);
              }
            } catch {}
          }
        }
      }
    } catch {}
  }

  // Step B2: Probe for Exposed Stored Data Files (Config, Databases, Logs & Diagnostics)
  const sensitiveStoredPaths = [
    { p: '/.env', sig: /DB_|PASSWORD|SECRET|KEY|APP_ENV/i, cat: 'ENVIRONMENT_SECRETS', title: 'Exposed Environment File (.env)' },
    { p: '/.env.local', sig: /DB_|PASSWORD|SECRET|KEY/i, cat: 'ENVIRONMENT_SECRETS', title: 'Exposed Local Environment File (.env.local)' },
    { p: '/.env.backup', sig: /DB_|PASSWORD|SECRET|KEY/i, cat: 'ENVIRONMENT_SECRETS', title: 'Exposed Environment Backup (.env.backup)' },
    { p: '/dump.sql', sig: /CREATE\s+TABLE|INSERT\s+INTO/i, cat: 'DATABASE_LEAK', title: 'Exposed Database SQL Dump (dump.sql)' },
    { p: '/backup.sql', sig: /CREATE\s+TABLE|INSERT\s+INTO/i, cat: 'DATABASE_LEAK', title: 'Exposed Database Backup Dump (backup.sql)' },
    { p: '/database.sqlite', sig: /SQLite format 3/i, cat: 'DATABASE_LEAK', title: 'Exposed Live SQLite Database File' },
    { p: '/app.log', sig: /\[ERROR\]|\[INFO\]|at\s+\w+\s+\(|Stack trace/i, cat: 'SERVER_LOG_LEAK', title: 'Exposed Application Debug Log (app.log)' },
    { p: '/debug.log', sig: /\[ERROR\]|\[DEBUG\]|SQL/i, cat: 'SERVER_LOG_LEAK', title: 'Exposed System Debug Log (debug.log)' },
    { p: '/actuator/heapdump', sig: /heap|azure|vault|token/i, cat: 'MEMORY_LEAK', title: 'Exposed Cloud Actuator Heapdump' },
    { p: '/actuator/env', sig: /propertySources|environment/i, cat: 'ENVIRONMENT_SECRETS', title: 'Exposed Spring Actuator Environment Variables' },
    { p: '/phpinfo.php', sig: /PHP Version|Configuration File|phpinfo\(\)/i, cat: 'CONFIGURATION_EXPOSURE', title: 'Exposed PHP Information Telemetry (phpinfo.php)' },
  ];

  await Promise.allSettled(
    sensitiveStoredPaths.map(async item => {
      try {
        const itemUrl = new URL(item.p, targetUrl);
        const res = await fetch(itemUrl.toString(), {
          headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
          signal: AbortSignal.timeout(3500),
        });

        if (res.status === 200) {
          const text = await res.text();
          // Verify signature and ensure it's not a generic SPA/HTML 404 page
          if (item.sig.test(text) && (!text.includes('<!DOCTYPE html>') || item.p === '/phpinfo.php')) {
            const fileName = path.basename(item.p) || 'exposed_data.txt';
            const savePath = path.join(outputDir, fileName.startsWith('.') ? fileName : `exposed_${fileName}`);
            fs.writeFileSync(savePath, text, 'utf8');
            result.extractedFilesCount++;

            result.findings.push({
              title: item.title,
              severity: 'CRITICAL',
              confidence: 'CONFIRMED',
              category: 'INFORMATION_DISCLOSURE',
              sourceRuleId: `recon.exposed-stored-data.${item.cat.toLowerCase()}`,
              targetUrl: itemUrl.toString(),
              evidenceSummary: `Publicly accessible stored sensitive data file discovered at ${item.p}. File contains active credentials, database queries, or server memory telemetry.`,
              rawSnippet: text.slice(0, 300),
              remediation: `Deny public access to ${item.p} in web server configurations and ensure sensitive database and environment files reside outside the document root.`,
              cwe: 'CWE-200',
            });
          }
        }
      } catch {}
    })
  );

  // Step C: Probe and Extract JavaScript Source Maps (.js.map)
  const scriptUrls: string[] = [];
  const inlineScripts: string[] = [];

  try {
    const rootRes = await fetch(targetUrl.toString(), {
      headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
      signal: AbortSignal.timeout(6000),
    });

    if (rootRes.ok) {
      const html = await rootRes.text();

      // Extract external script tags: <script src="...">
      const scriptRegex = /<script\b[^>]*\bsrc=['"]([^'"]+)['"]/gi;
      let match: RegExpExecArray | null;

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

      // Extract inline scripts: <script>...</script>
      const inlineRegex = /<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
      let inlineMatch: RegExpExecArray | null;
      while ((inlineMatch = inlineRegex.exec(html)) !== null) {
        const scriptBody = (inlineMatch[1] || '').trim();
        if (scriptBody.length > 40 && !scriptBody.includes('GoogleAnalyticsObject')) {
          inlineScripts.push(scriptBody);
        }
      }

      // Add common sourcemap paths
      const mapCandidates = new Set<string>();
      for (const sUrl of scriptUrls.slice(0, 10)) {
        mapCandidates.add(`${sUrl}.map`);
      }
      mapCandidates.add(new URL('/main.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/app.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/bundle.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/static/js/main.js.map', targetUrl).toString());
      mapCandidates.add(new URL('/_next/static/chunks/main.js.map', targetUrl).toString());

      for (const mapUrl of mapCandidates) {
        if (result.extractedFilesCount >= 60) break;
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

  // =========================================================================
  // Step D: Client-Side Scripts Scraping & De-bundling (Always-Active Fallback)
  // =========================================================================
  // If fewer than 5 files were recovered from maps/backups, download client-side scripts
  const scriptsDir = path.join(outputDir, 'client-scripts');
  fs.mkdirSync(scriptsDir, { recursive: true });

  let scrapedScriptsCount = 0;

  // 1. Download external JS scripts
  for (let idx = 0; idx < Math.min(scriptUrls.length, 12); idx++) {
    const sUrl = scriptUrls[idx];
    try {
      const sRes = await fetch(sUrl, {
        headers: { 'User-Agent': 'SentinelAI-Security-Auditor/2.0' },
        signal: AbortSignal.timeout(5000),
      });
      if (sRes.ok) {
        const jsContent = await sRes.text();
        if (jsContent.length > 50) {
          const parsed = new URL(sUrl);
          const baseName = path.basename(parsed.pathname) || `script_${idx}.js`;
          const safeName = `${idx}_${baseName.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
          fs.writeFileSync(path.join(scriptsDir, safeName), jsContent, 'utf8');
          scrapedScriptsCount++;
        }
      }
    } catch {}
  }

  // 2. Save inline HTML scripts
  for (let idx = 0; idx < inlineScripts.length; idx++) {
    const content = inlineScripts[idx];
    fs.writeFileSync(path.join(scriptsDir, `inline_script_${idx + 1}.js`), content, 'utf8');
    scrapedScriptsCount++;
  }

  if (scrapedScriptsCount > 0) {
    result.extractedFilesCount += scrapedScriptsCount;
    result.findings.push({
      title: 'Client-Side Scripts Scraped for Static Analysis',
      severity: 'LOW',
      confidence: 'CONFIRMED',
      category: 'RECON_DISCOVERY',
      sourceRuleId: 'recon.client-scripts-scraped',
      targetUrl: targetUrl.toString(),
      evidenceSummary: `Scraped ${scrapedScriptsCount} client-side JavaScript files and inline scripts from ${targetUrl.toString()}. Scripts indexed for SAST secret discovery and DOM XSS analysis.`,
      rawSnippet: `Target URL: ${targetUrl.toString()}\nScraped Scripts: ${scrapedScriptsCount}\nLocation: storage/extracted-sources/scan-${scanId}/client-scripts/`,
      remediation: 'Audit client-side scripts to ensure sensitive API keys, internal endpoints, and logic are not exposed.',
      cwe: 'CWE-200',
    });
  }

  // Final check: if any source files exist in outputDir, designate it as extractedDir
  const totalInWorkspace = countExtractedFiles(outputDir);
  if (totalInWorkspace > 0) {
    result.extractedDir = outputDir;
    result.extractedFilesCount = totalInWorkspace;
  }

  return result;
}

function countExtractedFiles(dir: string): number {
  let count = 0;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.name === '.git') continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        count += countExtractedFiles(full);
      } else if (/\.(js|ts|jsx|tsx|py|php|json|html|vue|sql|env)$/i.test(ent.name)) {
        count++;
      }
    }
  } catch {}
  return count;
}
