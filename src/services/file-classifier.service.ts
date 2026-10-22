import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface FileClassificationItem {
  relativePath: string;
  absolutePath: string;
  sizeBytes: number;
  extension: string;
  category: 'SOURCE_CODE' | 'DEPENDENCY_MANIFEST' | 'INFRASTRUCTURE_IAC' | 'SECRET_CONFIG' | 'ARCHIVE' | 'BINARY_EXECUTABLE' | 'MEDIA_DOCUMENT' | 'UNKNOWN';
  language?: string;
  isSuspicious: boolean;
  suspicionReason?: string;
  lineCount?: number;
  sha256?: string;
}

export interface ProjectClassificationReport {
  scannedDirectory: string;
  totalFilesIndexed: number;
  totalLinesOfCode: number;
  categoryCounts: Record<string, number>;
  languageCounts: Record<string, { files: number; lines: number }>;
  manifests: string[];
  iacFiles: string[];
  configFiles: string[];
  binaries: string[];
  suspiciousFiles: Array<{ path: string; reason: string }>;
  recommendedToolEngines: string[];
  skippedToolEngines: Array<{ tool: string; reason: string }>;
}

const EXT_LANG_MAP: Record<string, string> = {
  '.php': 'PHP',
  '.phtml': 'PHP',
  '.php4': 'PHP',
  '.php5': 'PHP',
  '.php7': 'PHP',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.cjs': 'JavaScript',
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.py': 'Python',
  '.pyw': 'Python',
  '.go': 'Go',
  '.java': 'Java',
  '.rb': 'Ruby',
  '.c': 'C',
  '.cpp': 'C++',
  '.h': 'C/C++ Header',
  '.cs': 'C#',
  '.html': 'HTML',
  '.htm': 'HTML',
  '.vue': 'Vue',
  '.sql': 'SQL',
  '.sh': 'Shell',
  '.bash': 'Shell',
};

const MANIFEST_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'composer.json',
  'composer.lock',
  'requirements.txt',
  'pipfile',
  'pipfile.lock',
  'poetry.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'cargo.toml',
  'cargo.lock',
  'go.mod',
  'go.sum',
  'gemfile',
  'gemfile.lock',
]);

const IAC_PATTERNS = [
  /^dockerfile/i,
  /^docker-compose.*\.ya?ml$/i,
  /\.tf$/i,
  /\.tfvars$/i,
  /k8s.*\.ya?ml$/i,
  /deployment.*\.ya?ml$/i,
  /service.*\.ya?ml$/i,
  /helm.*\.ya?ml$/i,
];

const CONFIG_SECRET_PATTERNS = [
  /^\.env/i,
  /config\.php$/i,
  /database\.php$/i,
  /db\.php$/i,
  /wp-config\.php$/i,
  /settings\.py$/i,
  /application.*\.ya?ml$/i,
  /application.*\.properties$/i,
  /secrets?\.ya?ml$/i,
];

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.elf',
  '.msi',
  '.bat',
  '.cmd',
  '.ps1',
  '.vbs',
  '.apk',
  '.ipa',
  '.jar',
  '.war',
]);

const IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'vendor',
  'bower_components',
  'third_party',
  'thirdparty',
  'packages',
  'libs',
  'bundle',
  '.venv',
  'venv',
  'env',
  'coverage',
  '.system_generated',
  '__pycache__',
]);

/**
 * Classifies all files in a source code directory
 * Provides intelligent routing for SAST, SCA, IaC, and Secret engines.
 */
export async function classifyProjectFiles(dirPath: string): Promise<ProjectClassificationReport> {
  const items: FileClassificationItem[] = [];
  let totalLines = 0;

  function walk(currentDir: string, depth = 0) {
    if (depth > 14 || !fs.existsSync(currentDir)) return;
    if (items.length >= 6000) return; // safeguard cap

    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!IGNORED_DIRS.has(entry.name.toLowerCase())) {
            walk(path.join(currentDir, entry.name), depth + 1);
          }
        } else if (entry.isFile()) {
          const fullPath = path.join(currentDir, entry.name);
          const relPath = path.relative(dirPath, fullPath).replace(/\\/g, '/');
          const ext = path.extname(entry.name).toLowerCase();
          const baseLower = entry.name.toLowerCase();

          try {
            const stat = fs.statSync(fullPath);
            let category: FileClassificationItem['category'] = 'UNKNOWN';
            let language: string | undefined;
            let isSuspicious = false;
            let suspicionReason: string | undefined;
            let fileLines = 0;

            // 1. Dependency Manifests
            if (MANIFEST_NAMES.has(baseLower)) {
              category = 'DEPENDENCY_MANIFEST';
            }
            // 2. IaC & Container Configurations
            else if (IAC_PATTERNS.some(p => p.test(baseLower))) {
              category = 'INFRASTRUCTURE_IAC';
            }
            // 3. Secrets & Configuration Files
            else if (CONFIG_SECRET_PATTERNS.some(p => p.test(baseLower))) {
              category = 'SECRET_CONFIG';
            }
            // 4. Executables & Binaries
            else if (EXECUTABLE_EXTENSIONS.has(ext)) {
              category = 'BINARY_EXECUTABLE';
              // Check if an executable is embedded in a web project
              isSuspicious = true;
              suspicionReason = `Compiled binary executable '${entry.name}' found in web repository.`;
            }
            // 5. Source Code
            else if (EXT_LANG_MAP[ext]) {
              category = 'SOURCE_CODE';
              language = EXT_LANG_MAP[ext];
            }
            // 6. Media / Documents & Data Files
            else if (['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.pdf', '.docx', '.xlsx', '.mp4', '.json', '.md', '.txt', '.csv', '.lock'].includes(ext)) {
              category = 'MEDIA_DOCUMENT';
            }

            // Count lines for text files under 2MB
            if ((category === 'SOURCE_CODE' || category === 'DEPENDENCY_MANIFEST' || category === 'INFRASTRUCTURE_IAC' || category === 'SECRET_CONFIG') && stat.size < 2 * 1024 * 1024) {
              try {
                const content = fs.readFileSync(fullPath, 'utf8');
                fileLines = content.split('\n').length;
                totalLines += fileLines;

                // Inspect Magic Bytes / Webshell camouflage
                if (ext === '.jpg' || ext === '.png' || ext === '.gif') {
                  if (content.includes('<?php') || content.includes('eval(') || content.includes('base64_decode')) {
                    isSuspicious = true;
                    suspicionReason = `Webshell signature detected camouflaged inside media file ${entry.name}.`;
                  }
                }
              } catch {}
            }

            items.push({
              relativePath: relPath,
              absolutePath: fullPath,
              sizeBytes: stat.size,
              extension: ext,
              category,
              language,
              isSuspicious,
              suspicionReason,
              lineCount: fileLines,
            });
          } catch {}
        }
      }
    } catch {}
  }

  walk(dirPath, 0);

  // Summarize category and language counts
  const categoryCounts: Record<string, number> = {};
  const languageCounts: Record<string, { files: number; lines: number }> = {};
  const manifests: string[] = [];
  const iacFiles: string[] = [];
  const configFiles: string[] = [];
  const binaries: string[] = [];
  const suspiciousFiles: Array<{ path: string; reason: string }> = [];

  for (const item of items) {
    categoryCounts[item.category] = (categoryCounts[item.category] || 0) + 1;

    if (item.language) {
      if (!languageCounts[item.language]) {
        languageCounts[item.language] = { files: 0, lines: 0 };
      }
      languageCounts[item.language].files++;
      languageCounts[item.language].lines += item.lineCount || 0;
    }

    if (item.category === 'DEPENDENCY_MANIFEST') manifests.push(item.relativePath);
    if (item.category === 'INFRASTRUCTURE_IAC') iacFiles.push(item.relativePath);
    if (item.category === 'SECRET_CONFIG') configFiles.push(item.relativePath);
    if (item.category === 'BINARY_EXECUTABLE') binaries.push(item.relativePath);
    if (item.isSuspicious && item.suspicionReason) {
      suspiciousFiles.push({ path: item.relativePath, reason: item.suspicionReason });
    }
  }

  // Recommended engines based on actual files
  const recommendedToolEngines: string[] = [];
  const skippedToolEngines: Array<{ tool: string; reason: string }> = [];

  // SAST: Semgrep & CodeQL (if code exists)
  if (categoryCounts['SOURCE_CODE'] > 0 || configFiles.length > 0) {
    recommendedToolEngines.push('SEMGREP');
    recommendedToolEngines.push('CODEQL');
  } else {
    skippedToolEngines.push({ tool: 'SEMGREP', reason: 'No source code files detected in repository.' });
    skippedToolEngines.push({ tool: 'CODEQL', reason: 'No supported languages detected for taint analysis.' });
  }

  // Secrets: Gitleaks (always recommended for code or configs)
  recommendedToolEngines.push('GITLEAKS');

  // IaC: Checkov
  if (iacFiles.length > 0) {
    recommendedToolEngines.push('CHECKOV');
  } else {
    skippedToolEngines.push({ tool: 'CHECKOV', reason: 'No IaC manifests (Dockerfile, Kubernetes, Terraform) detected.' });
  }

  // SCA: OSV, Trivy, npm audit
  if (manifests.length > 0) {
    recommendedToolEngines.push('TRIVY');
    recommendedToolEngines.push('OSV_SCANNER');
    if (manifests.some(m => m.toLowerCase().includes('package.json'))) {
      recommendedToolEngines.push('NPM_AUDIT');
    } else {
      skippedToolEngines.push({ tool: 'NPM_AUDIT', reason: 'No package.json manifest found for npm audit.' });
    }
  } else {
    skippedToolEngines.push({ tool: 'TRIVY', reason: 'No dependency manifests found in repository.' });
    skippedToolEngines.push({ tool: 'OSV_SCANNER', reason: 'No package lockfiles found in repository.' });
    skippedToolEngines.push({ tool: 'NPM_AUDIT', reason: 'No npm package.json found in repository.' });
  }

  return {
    scannedDirectory: dirPath,
    totalFilesIndexed: items.length,
    totalLinesOfCode: totalLines,
    categoryCounts,
    languageCounts,
    manifests,
    iacFiles,
    configFiles,
    binaries,
    suspiciousFiles,
    recommendedToolEngines,
    skippedToolEngines,
  };
}
