/**
 * SentinelAI - Standard CVSS v3.1 Base Score Calculator
 * Implements the official FIRST.org CVSS v3.1 specification equation.
 */

export interface CVSSv31Metrics {
  attackVector: 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL';
  attackComplexity: 'LOW' | 'HIGH';
  privilegesRequired: 'NONE' | 'LOW' | 'HIGH';
  userInteraction: 'NONE' | 'REQUIRED';
  scope: 'UNCHANGED' | 'CHANGED';
  confidentiality: 'NONE' | 'LOW' | 'HIGH';
  integrity: 'NONE' | 'LOW' | 'HIGH';
  availability: 'NONE' | 'LOW' | 'HIGH';
}

export interface CVSSv31Result {
  score: number;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vectorString: string;
}

export class CVSSCalculatorService {
  private static roundUp(input: number): number {
    return Math.round(input * 10) / 10;
  }

  public static calculate(metrics: CVSSv31Metrics): CVSSv31Result {
    const avMap = { NETWORK: 0.85, ADJACENT: 0.62, LOCAL: 0.55, PHYSICAL: 0.2 };
    const acMap = { LOW: 0.77, HIGH: 0.44 };
    const uiMap = { NONE: 0.85, REQUIRED: 0.62 };
    const cMap = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };
    const iMap = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };
    const aMap = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };

    const av = avMap[metrics.attackVector];
    const ac = acMap[metrics.attackComplexity];
    const ui = uiMap[metrics.userInteraction];
    const isScopeChanged = metrics.scope === 'CHANGED';

    let pr = 0.85;
    if (metrics.privilegesRequired === 'LOW') {
      pr = isScopeChanged ? 0.68 : 0.62;
    } else if (metrics.privilegesRequired === 'HIGH') {
      pr = isScopeChanged ? 0.5 : 0.27;
    }

    const c = cMap[metrics.confidentiality];
    const i = iMap[metrics.integrity];
    const a = aMap[metrics.availability];

    // ISS: Impact Sub-Score
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);

    let impact = 0;
    if (isScopeChanged) {
      impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    } else {
      impact = 6.42 * iss;
    }

    const exploitability = 8.22 * av * ac * pr * ui;

    let baseScore = 0;
    if (impact <= 0) {
      baseScore = 0;
    } else if (!isScopeChanged) {
      baseScore = Math.min(10, this.roundUp(Math.min(impact + exploitability, 10)));
    } else {
      baseScore = Math.min(10, this.roundUp(Math.min(1.08 * (impact + exploitability), 10)));
    }

    let severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'NONE';
    if (baseScore >= 9.0) severity = 'CRITICAL';
    else if (baseScore >= 7.0) severity = 'HIGH';
    else if (baseScore >= 4.0) severity = 'MEDIUM';
    else if (baseScore >= 0.1) severity = 'LOW';

    const avCode = { NETWORK: 'N', ADJACENT: 'A', LOCAL: 'L', PHYSICAL: 'P' }[metrics.attackVector];
    const acCode = { LOW: 'L', HIGH: 'H' }[metrics.attackComplexity];
    const prCode = { NONE: 'N', LOW: 'L', HIGH: 'H' }[metrics.privilegesRequired];
    const uiCode = { NONE: 'N', REQUIRED: 'R' }[metrics.userInteraction];
    const sCode = isScopeChanged ? 'C' : 'U';
    const cCode = { NONE: 'N', LOW: 'L', HIGH: 'H' }[metrics.confidentiality];
    const iCode = { NONE: 'N', LOW: 'L', HIGH: 'H' }[metrics.integrity];
    const aCode = { NONE: 'N', LOW: 'L', HIGH: 'H' }[metrics.availability];

    const vectorString = `CVSS:3.1/AV:${avCode}/AC:${acCode}/PR:${prCode}/UI:${uiCode}/S:${sCode}/C:${cCode}/I:${iCode}/A:${aCode}`;

    return {
      score: baseScore,
      severity,
      vectorString,
    };
  }
}
