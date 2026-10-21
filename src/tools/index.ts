import { SecurityToolAdapter } from './security-tool.interface';
import { ZapAdapter } from './zap.adapter';
import { SemgrepAdapter } from './semgrep.adapter';
import { GitleaksAdapter } from './gitleaks.adapter';
import { TrivyAdapter } from './trivy.adapter';
import { NpmAuditAdapter } from './npm-audit.adapter';

export * from './security-tool.interface';
export * from './zap.adapter';
export * from './semgrep.adapter';
export * from './gitleaks.adapter';
export * from './trivy.adapter';
export * from './npm-audit.adapter';

export const TOOL_ADAPTERS: Record<string, SecurityToolAdapter> = {
  OWASP_ZAP: new ZapAdapter(),
  SEMGREP: new SemgrepAdapter(),
  GITLEAKS: new GitleaksAdapter(),
  TRIVY: new TrivyAdapter(),
  NPM_AUDIT: new NpmAuditAdapter(),
};

export function getToolAdapter(name: string): SecurityToolAdapter | null {
  const norm = name.toUpperCase().replace(/[-\s]/g, '_');
  return TOOL_ADAPTERS[norm] || null;
}

export function getAllToolAdapters(): SecurityToolAdapter[] {
  return Object.values(TOOL_ADAPTERS);
}
