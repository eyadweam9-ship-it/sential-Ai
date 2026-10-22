export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ConfidenceLevel = 'CONFIRMED' | 'POTENTIAL' | 'INFORMATIONAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEEDS_REVIEW' | 'LIKELY_FALSE_POSITIVE';
export type VerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'NEEDS_REVIEW';

export interface ScopeRuleSet {
  includedPaths: string[];
  excludedPaths: string[];
}

export interface ToolInput {
  scanId: number;
  targetId: number;
  targetUrl: string;
  targetType: 'URL' | 'FILE_ZIP' | 'HYBRID';
  environment: 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
  sourcePath?: string;
  scope?: ScopeRuleSet;
  rateLimitRps?: number;
  timeoutMs?: number;
  sessionCookie?: string;
  authHeader?: string;
}

export interface RawToolFinding {
  title: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  verificationStatus?: VerificationStatus;
  category: string;
  sourceRuleId?: string;
  targetUrl?: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  evidenceSummary: string;
  rawSnippet?: string;
  remediation?: string;
  cwe?: string;
  cve?: string;
  relatedFindings?: Array<{ id?: number; tool?: string; title: string }>;
}

export interface ToolExecutionResult {
  toolName: string;
  toolVersion: string;
  success: boolean;
  exitCode: number;
  durationMs: number;
  findings: RawToolFinding[];
  errorSummary?: string;
  resultPath?: string;
  skippedReason?: string;
}

export interface SecurityToolAdapter {
  readonly name: string;
  readonly version: string;
  readonly supportedTargetTypes: Array<'URL' | 'FILE_ZIP' | 'HYBRID'>;

  isAvailable(): Promise<boolean>;
  run(input: ToolInput): Promise<ToolExecutionResult>;
}
