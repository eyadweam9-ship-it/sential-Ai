import crypto from 'crypto';
import { prisma } from '../config/db';
import { RawToolFinding } from '../tools/security-tool.interface';
import { validateFindingEvidence } from './evidence-validator.service';

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
}

export function generateFindingFingerprint(finding: RawToolFinding): string {
  const loc = (finding.filePath || finding.targetUrl || 'global').trim().toLowerCase();
  const rule = (finding.sourceRuleId || finding.title).trim();
  const line = finding.lineStart || 0;
  const raw = `${finding.category}:${rule}:${loc}:${line}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function sanitizeEvidence(text?: string): string {
  if (!text) return '';
  // Redact potential high entropy keys, passwords, tokens and mask email addresses
  let sanitized = text
    .replace(/((?:password|secret|token|apiKey|auth))\s*[:=]\s*['"]?[a-zA-Z0-9_\-\.]{8,}['"]?/gi, '$1=***REDACTED***')
    .replace(/(AKIA[0-9A-Z]{16})/g, '$1 [REDACTED]')
    .replace(/(ghp_[A-Za-z0-9]{36})/g, 'ghp_********************************')
    .replace(/\b([a-zA-Z0-9._%+-]{1,3})[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g, '$1***@$2');

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
    // Stage 2: Evidence Validation & False Positive Filtering
    const validation = validateFindingEvidence(raw);
    if (validation.verdict === 'DROP_FALSE_POSITIVE') {
      // Discard verified false positives so they never pollute the findings register or distort risk scores
      continue;
    }

    const title = validation.adjustedTitle || raw.title;
    const remediation = validation.adjustedRemediation || raw.remediation || null;
    const confidence = validation.confidence || raw.confidence || 'MEDIUM';
    const status = validation.status || 'OPEN';

    const normalizedRaw: RawToolFinding = {
      ...raw,
      title,
      remediation: remediation || undefined,
      confidence,
    };

    const fingerprint = generateFindingFingerprint(normalizedRaw);

    // Create Unified Finding Record
    const findingRecord = await prisma.finding.create({
      data: {
        scanId,
        toolName,
        sourceRuleId: raw.sourceRuleId || null,
        title,
        description: raw.evidenceSummary,
        severity: raw.severity,
        confidence,
        category: raw.category || 'VULNERABILITY',
        fingerprint,
        status,
        remediation,
        cwe: raw.cwe || null,
        cve: raw.cve || null,
      },
    });

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
      },
    });

    // Also mirror to legacy Vulnerability table for seamless backward compatibility with existing views
    await prisma.vulnerability.create({
      data: {
        scanId,
        title,
        description: raw.evidenceSummary,
        severity: raw.severity,
        status,
        remediation,
        filePath: raw.filePath || raw.targetUrl || null,
      },
    }).catch(() => null);

    saved.push(findingRecord);
  }

  return saved;
}
