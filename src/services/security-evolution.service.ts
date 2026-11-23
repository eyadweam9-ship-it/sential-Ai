import { prisma } from '../config/db';

export interface ScanEvolutionTrend {
  scanId: number;
  scanDate: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  riskScore: number;
}

export interface SecurityEvolutionReport {
  targetUrl: string;
  totalHistoricalScans: number;
  evolutionTrend: ScanEvolutionTrend[];
  newFindingsCount: number;
  resolvedFindingsCount: number;
  recurrentRegressionsCount: number;
  persistentFindingsCount: number;
  healthTrajectory: 'IMPROVING' | 'DEGRADING' | 'STABLE';
}

/**
 * Security Evolution Engine
 * Tracks finding emergence, resolution, and regression history across successive scans.
 */
export class SecurityEvolutionService {
  public static async analyzeEvolution(currentScanId: number): Promise<SecurityEvolutionReport> {
    const currentScan = await prisma.scan.findUnique({
      where: { id: currentScanId },
      include: { target: true, findings: true },
    });

    if (!currentScan || !currentScan.target) {
      throw new Error(`Scan #${currentScanId} not found.`);
    }

    const targetId = currentScan.targetId;
    const history = await prisma.scan.findMany({
      where: { targetId },
      orderBy: { createdAt: 'asc' },
      include: { findings: true },
    });

    const evolutionTrend: ScanEvolutionTrend[] = history.map(s => {
      const crit = s.findings.filter(f => f.severity === 'CRITICAL').length;
      const high = s.findings.filter(f => f.severity === 'HIGH').length;
      const med = s.findings.filter(f => f.severity === 'MEDIUM').length;
      const score = Math.max(10, 100 - (crit * 25 + high * 15 + med * 5));
      return {
        scanId: s.id,
        scanDate: s.createdAt.toISOString(),
        totalFindings: s.findings.length,
        criticalCount: crit,
        highCount: high,
        riskScore: score,
      };
    });

    let newCount = 0;
    let recurrentCount = 0;
    let persistentCount = 0;

    const previousScans = history.filter(s => s.id !== currentScanId);
    if (previousScans.length > 0) {
      const immediatePrev = previousScans[previousScans.length - 1];
      for (const currF of currentScan.findings) {
        const foundInPrev = immediatePrev.findings.find(pf => pf.cwe === currF.cwe && pf.title === currF.title);
        if (!foundInPrev) {
          // Check if it existed in an even older scan and was fixed (Regression)
          const foundInAncient = previousScans.slice(0, -1).some(oldS => oldS.findings.some(of => of.cwe === currF.cwe && of.status === 'FIXED'));
          if (foundInAncient) {
            recurrentCount++;
          } else {
            newCount++;
          }
        } else {
          persistentCount++;
        }
      }
    } else {
      newCount = currentScan.findings.length;
    }

    // Trajectory calculation
    let trajectory: 'IMPROVING' | 'DEGRADING' | 'STABLE' = 'STABLE';
    if (evolutionTrend.length >= 2) {
      const latestScore = evolutionTrend[evolutionTrend.length - 1].riskScore;
      const previousScore = evolutionTrend[evolutionTrend.length - 2].riskScore;
      if (latestScore > previousScore + 5) trajectory = 'IMPROVING';
      else if (latestScore < previousScore - 5) trajectory = 'DEGRADING';
    }

    return {
      targetUrl: currentScan.target.url,
      totalHistoricalScans: history.length,
      evolutionTrend,
      newFindingsCount: newCount,
      resolvedFindingsCount: Math.max(0, (previousScans[previousScans.length - 1]?.findings.length || 0) - persistentCount),
      recurrentRegressionsCount: recurrentCount,
      persistentFindingsCount: persistentCount,
      healthTrajectory: trajectory,
    };
  }
}
