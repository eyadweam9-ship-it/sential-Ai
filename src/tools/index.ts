import { SecurityToolAdapter } from './security-tool.interface';
import { ZapAdapter } from './zap.adapter';
import { NucleiAdapter } from './nuclei.adapter';
import { SemgrepAdapter } from './semgrep.adapter';
import { CodeqlAdapter } from './codeql.adapter';
import { GitleaksAdapter } from './gitleaks.adapter';
import { TrivyAdapter } from './trivy.adapter';
import { OsvScannerAdapter } from './osv-scanner.adapter';
import { CheckovAdapter } from './checkov.adapter';
import { NpmAuditAdapter } from './npm-audit.adapter';
import { WpscanAdapter } from './wpscan.adapter';
import { WhatwebAdapter } from './whatweb.adapter';
import { TestsslAdapter } from './testssl.adapter';

export * from './security-tool.interface';
export * from './zap.adapter';
export * from './nuclei.adapter';
export * from './semgrep.adapter';
export * from './codeql.adapter';
export * from './gitleaks.adapter';
export * from './trivy.adapter';
export * from './osv-scanner.adapter';
export * from './checkov.adapter';
export * from './npm-audit.adapter';
export * from './wpscan.adapter';
export * from './whatweb.adapter';
export * from './testssl.adapter';

export const TOOL_ADAPTERS: Record<string, SecurityToolAdapter> = {
  OWASP_ZAP: new ZapAdapter(),
  NUCLEI: new NucleiAdapter(),
  WPSCAN: new WpscanAdapter(),
  WHATWEB: new WhatwebAdapter(),
  TESTSSL: new TestsslAdapter(),
  SEMGREP: new SemgrepAdapter(),
  CODEQL: new CodeqlAdapter(),
  GITLEAKS: new GitleaksAdapter(),
  TRIVY: new TrivyAdapter(),
  OSV_SCANNER: new OsvScannerAdapter(),
  CHECKOV: new CheckovAdapter(),
  NPM_AUDIT: new NpmAuditAdapter(),
};

export function getToolAdapter(name: string): SecurityToolAdapter | null {
  const norm = name.toUpperCase().replace(/[-\s]/g, '_');
  return TOOL_ADAPTERS[norm] || null;
}

export function getAllToolAdapters(): SecurityToolAdapter[] {
  return Object.values(TOOL_ADAPTERS);
}
