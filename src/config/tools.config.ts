import path from 'path';

export interface ToolConfig {
  enabled: boolean;
  timeoutMs: number;
  maxMemoryMb: number;
  cliPath?: string;
  outputDir: string;
}

export const TOOLS_CONFIG: Record<string, ToolConfig> = {
  OWASP_ZAP: {
    enabled: true,
    timeoutMs: 120_000, // 2 minutes max
    maxMemoryMb: 1024,
    outputDir: path.join(process.cwd(), 'storage', 'tool-results', 'zap'),
  },
  SEMGREP: {
    enabled: true,
    timeoutMs: 90_000, // 90 seconds max
    maxMemoryMb: 512,
    outputDir: path.join(process.cwd(), 'storage', 'tool-results', 'semgrep'),
  },
  GITLEAKS: {
    enabled: true,
    timeoutMs: 60_000,
    maxMemoryMb: 256,
    outputDir: path.join(process.cwd(), 'storage', 'tool-results', 'gitleaks'),
  },
  TRIVY: {
    enabled: true,
    timeoutMs: 90_000,
    maxMemoryMb: 512,
    outputDir: path.join(process.cwd(), 'storage', 'tool-results', 'trivy'),
  },
  NPM_AUDIT: {
    enabled: true,
    timeoutMs: 60_000,
    maxMemoryMb: 256,
    outputDir: path.join(process.cwd(), 'storage', 'tool-results', 'npm-audit'),
  },
};
