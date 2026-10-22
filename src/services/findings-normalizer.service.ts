import crypto from 'crypto';
import { prisma } from '../config/db';
import { RawToolFinding } from '../tools/security-tool.interface';
import { evaluateFindingRisk } from './severity-engine.service';
import { validateFindingEvidence } from './evidence-validator.service';
import { createFindingFingerprint, normalizeFilePath } from './findings-deduplication.service';

export interface NormalizedFindingResult {
  id: number;
  scanId: number;
  toolName: string;
  sourceRuleId?: string | null;
  title: string;
  description?: string | null;
  severity: string;
  confidence: string;
  category?: string | null;
  fingerprint: string;
  status: string;
  remediation?: string | null;
  cwe?: string | null;
  cve?: string | null;
  cvssScore?: number | null;
  cvssVector?: string | null;
}

export function generateFindingFingerprint(finding: RawToolFinding): string {
  return createFindingFingerprint({
    targetId: finding.targetUrl || 'default',
    ruleId: finding.sourceRuleId || finding.title,
    filePath: finding.filePath || finding.targetUrl,
    startLine: finding.lineStart,
    sink: finding.rawSnippet,
    normalizedEvidence: finding.evidenceSummary,
  });
}

export function sanitizeEvidence(text?: string): string {
  if (!text) return '';
  // Redact credentials, API keys and cloud tokens from evidence
  let sanitized = text
    .replace(/(AKIA[0-9A-Z]{16})/g, '[REDACTED_AWS_KEY]')
    .replace(/(ghp_[A-Za-z0-9]{36})/g, 'ghp_********************************')
    .replace(/(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['"][^'"]+['"]/gi, '$1="[REDACTED]"');

  if (sanitized.length > 2000) {
    sanitized = sanitized.slice(0, 1997) + '...';
  }
  return sanitized;
}

export async function normalizeAndSaveFindings(
  scanId: number,
  toolName: string,
  rawFindings: RawToolFinding[]
): Promise<NormalizedFindingResult[]> {
  const saved: NormalizedFindingResult[] = [];

  for (const raw of rawFindings) {
    // Stage 1: Severity Engine & False Positive Evaluation
    const riskEval = evaluateFindingRisk(raw);

    // Drop proven False Positives so they do not pollute the register or distort risk metrics
    if (riskEval.isFalsePositive || riskEval.workflowStatus === 'FALSE_POSITIVE') {
      continue;
    }

    // Stage 1b: Technical Evidence Validation
    const validation = validateFindingEvidence(raw);
    if (validation.verdict === 'DROP_FALSE_POSITIVE' || validation.status === 'FALSE_POSITIVE') {
      continue;
    }

    const title = validation.adjustedTitle || raw.title;
    const remediation = validation.adjustedRemediation || raw.remediation || null;
    const confidence = validation.confidence === 'CONFIRMED' ? 'CONFIRMED' : riskEval.confidence;
    const status = validation.status === 'CONFIRMED' ? 'CONFIRMED' : riskEval.workflowStatus;
    const severity = validation.adjustedSeverity || riskEval.severity;

    const fingerprint = createFindingFingerprint({
      targetId: scanId,
      ruleId: raw.sourceRuleId || raw.title,
      filePath: raw.filePath || raw.targetUrl,
      startLine: raw.lineStart,
      sink: raw.rawSnippet,
      normalizedEvidence: raw.evidenceSummary,
    });

    // Determine verification status
    const verificationStatus =
      status === 'CONFIRMED'
        ? 'VERIFIED'
        : status === 'NEEDS_REVIEW'
        ? 'NEEDS_REVIEW'
        : 'UNVERIFIED';

    // Create Unified Finding Record
    const findingRecord = await prisma.finding.create({
      data: {
        scanId,
        toolName,
        sourceRuleId: raw.sourceRuleId || null,
        title,
        description: raw.evidenceSummary,
        severity,
        confidence,
        verificationStatus,
        category: raw.category || 'VULNERABILITY',
        fingerprint,
        status,
        remediation,
        cwe: raw.cwe || null,
        cve: raw.cve || null,
        cvssScore: riskEval.cvssScore,
        cvssVector: riskEval.cvssVector,
        relatedFindingsJson: raw.relatedFindings ? JSON.stringify(raw.relatedFindings) : null,
      },
    });

    // Create First FindingOccurrence Record
    await prisma.findingOccurrence.create({
      data: {
        findingId: findingRecord.id,
        scanner: toolName,
        ruleId: raw.sourceRuleId || null,
        filePath: raw.filePath || raw.targetUrl || null,
        lineStart: raw.lineStart || null,
        lineEnd: raw.lineEnd || null,
        snippet: raw.rawSnippet ? sanitizeEvidence(raw.rawSnippet) : null,
        normalizedEvidence: sanitizeEvidence(raw.evidenceSummary),
      },
    }).catch(() => null);

    // Create Linked Evidence Record
    await prisma.findingEvidence.create({
      data: {
        findingId: findingRecord.id,
        url: raw.targetUrl || null,
        filePath: raw.filePath || null,
        lineStart: raw.lineStart || null,
        lineEnd: raw.lineEnd || null,
        evidenceSummary: sanitizeEvidence(raw.evidenceSummary),
        rawSnippet: raw.rawSnippet ? sanitizeEvidence(raw.rawSnippet) : null,
        scanner: toolName,
        ruleId: raw.sourceRuleId || null,
      },
    });

    // Mirror to legacy table for backward compatibility
    await prisma.vulnerability.create({
      data: {
        scanId,
        title,
        description: raw.evidenceSummary,
        severity,
        status,
        remediation,
        filePath: raw.filePath || raw.targetUrl || null,
      },
    }).catch(() => null);

    saved.push(findingRecord);
  }

  return saved;
}
