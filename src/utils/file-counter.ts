import fs from 'fs';
import path from 'path';

export interface CodebaseStats {
  files: number;
  lines: number;
  extensions: Record<string, number>;
}

export function countFilesAndLines(dirPath: string): CodebaseStats {
  const stats: CodebaseStats = { files: 0, lines: 0, extensions: {} };

  function walk(currentDir: string, depth = 0) {
    if (depth > 12 || !fs.existsSync(currentDir)) return;
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.system_generated'].includes(entry.name)) {
          continue;
        }
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath, depth + 1);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase() || path.basename(entry.name);
          stats.files++;
          stats.extensions[ext] = (stats.extensions[ext] || 0) + 1;
          try {
            const content = fs.readFileSync(fullPath, 'utf8');
            stats.lines += content.split('\n').length;
          } catch {}
        }
      }
    } catch {}
  }

  walk(dirPath);
  return stats;
}
