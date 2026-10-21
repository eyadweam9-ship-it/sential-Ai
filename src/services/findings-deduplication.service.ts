import { prisma } from '../config/db';

export interface DeduplicationSummary {
  totalBefore: number;
  totalUnique: number;
  mergedDuplicates: number;
}

export interface CrossScanComparison {
  targetId: number;
  currentScanId: number;
  previousScanId: number | null;
  newFindingsCount: number;
  recurrentFindingsCount: number;
  fixedFindingsCount: number;
  newFindings: any[];
  fixedFindings: any[];
  recurrentFindings: any[];
}

export async function deduplicateScanFindings(scanId: number): Promise<DeduplicationSummary> {
  const allFindings = await prisma.finding.findMany({
    where: { scanId },
    include: { evidences: true },
    orderBy: { id: 'asc' },
  });

  const totalBefore = allFindings.length;
  const seenFingerprints = new Map<string, typeof allFindings[0]>();
  let mergedCount = 0;

  for (const f of allFindings) {
    if (!seenFingerprints.has(f.fingerprint)) {
      seenFingerprints.set(f.fingerprint, f);
    } else {
      // Merge: attach evidence to the canonical finding and remove duplicate finding record
      const canonical = seenFingerprints.get(f.fingerprint)!;
      for (const ev of f.evidences) {
        await prisma.findingEvidence.update({
          where: { id: ev.id },
          data: { findingId: canonical.id },
        });
      }
      await prisma.finding.delete({ where: { id: f.id } });
      mergedCount++;
    }
  }

  return {
    totalBefore,
    totalUnique: seenFingerprints.size,
    mergedDuplicates: mergedCount,
  };
}

export async function compareWithPreviousScan(
  targetId: number,
  currentScanId: number
): Promise<CrossScanComparison> {
  // Find the immediately preceding scan on the same target
  const previousScan = await prisma.scan.findFirst({
    where: {
      targetId,
      id: { lt: currentScanId },
      status: { in: ['COMPLETED', 'PARTIAL'] },
    },
    orderBy: { id: 'desc' },
  });

  if (!previousScan) {
    const current = await prisma.finding.findMany({ where: { scanId: currentScanId } });
    return {
      targetId,
      currentScanId,
      previousScanId: null,
      newFindingsCount: current.length,
      recurrentFindingsCount: 0,
      fixedFindingsCount: 0,
      newFindings: current,
      fixedFindings: [],
      recurrentFindings: [],
    };
  }

  const [currentFindings, prevFindings] = await Promise.all([
    prisma.finding.findMany({ where: { scanId: currentScanId } }),
    prisma.finding.findMany({ where: { scanId: previousScan.id } }),
  ]);

  const prevMap = new Map(prevFindings.map(f => [f.fingerprint, f]));
  const currentMap = new Map(currentFindings.map(f => [f.fingerprint, f]));

  const newFindings = currentFindings.filter(f => !prevMap.has(f.fingerprint));
  const recurrentFindings = currentFindings.filter(f => prevMap.has(f.fingerprint));
  const fixedFindings = prevFindings.filter(f => !currentMap.has(f.fingerprint));

  return {
    targetId,
    currentScanId,
    previousScanId: previousScan.id,
    newFindingsCount: newFindings.length,
    recurrentFindingsCount: recurrentFindings.length,
    fixedFindingsCount: fixedFindings.length,
    newFindings,
    fixedFindings,
    recurrentFindings,
  };
}
