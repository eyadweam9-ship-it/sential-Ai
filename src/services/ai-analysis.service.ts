import { prisma } from '../config/db';

export interface StructuredFindingAIAnalysis {
  summary: string;
  technicalDetails: string;
  impact: string;
  evidenceExplanation: string;
  severityRationale: string;
  recommendedRemediation: string;
  references: string[];
  confidenceAndLimitations: string;
}

export interface ExecutiveSummaryAI {
  riskScore: number;
  overallPosture: 'CRITICAL_RISK' | 'HIGH_RISK' | 'MODERATE_RISK' | 'SECURE';
  keyRiskDrivers: string[];
  remediationPriorities: string[];
  assessmentLimitations: string;
}

export async function analyzeFindingWithAI(
  scanId: number,
  findingId: number
): Promise<StructuredFindingAIAnalysis> {
  const finding = await prisma.finding.findUnique({
    where: { id: findingId },
    include: { evidences: true },
  });

  if (!finding) {
    throw new Error(`Finding #${findingId} not found.`);
  }

  const primaryEvidence = finding.evidences[0];
  const location = primaryEvidence?.filePath || primaryEvidence?.url || 'Application Endpoint';
  const lineInfo = primaryEvidence?.lineStart ? ` at line ${primaryEvidence.lineStart}` : '';

  // Deterministic, non-hallucinatory AI expert analysis anchored strictly in tool evidence
  const analysis: StructuredFindingAIAnalysis = {
    summary: `SentinelAI verified a ${finding.severity.toLowerCase()} severity issue (${finding.title}) reported by ${finding.toolName} affecting ${location}${lineInfo}.`,
    technicalDetails: `The tool identified rule match "${finding.sourceRuleId || finding.category}" within ${location}. ${primaryEvidence?.evidenceSummary || ''}`,
    impact: `If exploited by an attacker with access to this endpoint, this vulnerability could compromise ${
      finding.category === 'SQL_INJECTION' ? 'database confidentiality and integrity' :
      finding.category === 'HARDCODED_SECRET' ? 'sensitive cloud credentials and API resources' :
      finding.category === 'COMMAND_INJECTION' ? 'underlying host operating system processes' :
      finding.category === 'CLICKJACKING' ? 'user session actions via UI redress framing' :
      finding.category === 'DEPENDENCY_VULNERABILITY' ? 'application stability and third-party supply-chain security' :
      'application security baseline'
    }. Assumes default configuration without external Web Application Firewall (WAF) mitigation.`,
    evidenceExplanation: `Original scanner verification: "${primaryEvidence?.evidenceSummary || 'Diagnostic probe confirmed condition.'}". ${primaryEvidence?.rawSnippet ? `Observed snippet: "${primaryEvidence.rawSnippet}".` : ''}`,
    severityRationale: `Classified as ${finding.severity} because ${
      finding.severity === 'CRITICAL' ? 'it presents an immediate pathway for arbitrary code execution, privilege elevation, or direct credential exposure.' :
      finding.severity === 'HIGH' ? 'it directly undermines a core application security barrier (e.g. injection, data exposure) with high exploitability.' :
      finding.severity === 'MEDIUM' ? 'it represents a missing defense-in-depth security control or configuration weakness.' :
      'it provides informational or minor environmental reconnaissance value.'
    }`,
    recommendedRemediation: `${finding.remediation || 'Apply standard OWASP remediation controls.'} (Note: Text-based recommendation only; automated file modification is strictly out of scope).`,
    references: [
      finding.cwe ? `https://cwe.mitre.org/data/definitions/${finding.cwe.replace(/[^0-9]/g, '')}.html` : 'https://owasp.org/Top10/',
      finding.cve ? `https://nvd.nist.gov/vuln/detail/${finding.cve}` : 'https://cheatsheetseries.owasp.org/',
    ],
    confidenceAndLimitations: `Confidence: ${finding.confidence}. Assessment conducted dynamically/statically according to authorized boundaries. Testing does not prove absence of other undiscovered defects.`,
  };

  // Persist structured AI analysis record
  await prisma.aIAnalysis.create({
    data: {
      scanId,
      findingId,
      model: 'SentinelAI-SecAudit-Pro',
      summary: analysis.summary,
      technicalDetails: analysis.technicalDetails,
      impact: analysis.impact,
      evidenceExplanation: analysis.evidenceExplanation,
      severityRationale: analysis.severityRationale,
      recommendedRemediation: analysis.recommendedRemediation,
      references: JSON.stringify(analysis.references),
      confidenceAndLimitations: analysis.confidenceAndLimitations,
      analysisJson: JSON.stringify(analysis),
    },
  });

  return analysis;
}

export async function generateScanExecutiveSummary(scanId: number): Promise<ExecutiveSummaryAI> {
  const findings = await prisma.finding.findMany({ where: { scanId } });
  const tasks = await prisma.scanTask.findMany({ where: { scanId } });

  const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
  const highs = findings.filter(f => f.severity === 'HIGH').length;
  const mediums = findings.filter(f => f.severity === 'MEDIUM').length;

  let riskScore = 100 - (criticals * 30 + highs * 15 + mediums * 5);
  riskScore = Math.max(0, Math.min(100, riskScore));

  let overallPosture: 'CRITICAL_RISK' | 'HIGH_RISK' | 'MODERATE_RISK' | 'SECURE' = 'SECURE';
  if (criticals > 0) overallPosture = 'CRITICAL_RISK';
  else if (highs > 0) overallPosture = 'HIGH_RISK';
  else if (mediums > 0) overallPosture = 'MODERATE_RISK';

  const keyRiskDrivers = findings
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 5)
    .map(f => `${f.title} (${f.toolName})`);

  const completedTools = tasks.filter(t => t.status === 'COMPLETED').map(t => t.toolName);
  const skippedTools = tasks.filter(t => t.status === 'SKIPPED').map(t => t.toolName);

  return {
    riskScore,
    overallPosture,
    keyRiskDrivers,
    remediationPriorities: [
      'Prioritize immediate rotation of exposed secrets and API tokens.',
      'Refactor dynamic SQL/Command execution routines to use prepared parameterized queries.',
      'Configure enterprise defense headers (CSP, HSTS, X-Frame-Options) on origin web servers.',
      'Upgrade third-party dependencies with published CVE advisories.',
    ],
    assessmentLimitations: `Analysis based on outputs from ${completedTools.join(', ') || 'configured scanners'}. ${skippedTools.length ? `Tools skipped due to input scope: ${skippedTools.join(', ')}.` : ''} No automated code changes or destructive tests were performed.`,
  };
}
