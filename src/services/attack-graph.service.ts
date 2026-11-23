import { prisma } from '../config/db';

export interface GraphNode {
  id: string;
  label: string;
  type: 'ENTRYPOINT' | 'VULNERABILITY' | 'ASSET' | 'EXPLOIT_STEP';
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string;
  data?: any;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  active: boolean; // false if severed by simulated fix
}

export interface AttackGraphData {
  scanId: number;
  targetUrl: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  attackPathsCount: number;
  overallRiskScore: number;
}

export interface WhatIfSimulationResult {
  scanId: number;
  fixedFindingIds: number[];
  initialRiskScore: number;
  projectedRiskScore: number;
  riskReductionPercentage: number;
  severedPathsCount: number;
  remainingPathsCount: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Interactive Attack Graph & What-If Simulation Engine
 * Generates topological attack graphs linking entry points to crown jewel assets,
 * and simulates counterfactual attack-path closures.
 */
export class AttackGraphService {
  /**
   * Build complete Attack Graph for a scan
   */
  public static async buildAttackGraph(scanId: number): Promise<AttackGraphData> {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: {
        target: true,
        findings: {
          include: { evidences: true },
        },
      },
    });

    if (!scan) {
      throw new Error(`Scan #${scanId} not found.`);
    }

    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];

    // 1. Root Entrypoint Node
    const targetUrl = scan.target?.url || 'https://target.com';
    const entryId = 'node-entry';
    nodes.push({
      id: entryId,
      label: `Target Entry: ${targetUrl}`,
      type: 'ENTRYPOINT',
    });

    // 2. Asset Nodes (Crown Jewels)
    const dbAssetId = 'node-asset-db';
    const s3AssetId = 'node-asset-s3';
    const serverAssetId = 'node-asset-server';

    nodes.push({ id: dbAssetId, label: 'Core Database & User PII', type: 'ASSET' });
    nodes.push({ id: s3AssetId, label: 'Cloud Storage & Backups', type: 'ASSET' });
    nodes.push({ id: serverAssetId, label: 'Host Operating System / RCE', type: 'ASSET' });

    let pathCount = 0;

    // 3. Vulnerability Nodes and Edge Mapping
    for (const f of scan.findings) {
      const vNodeId = `vuln-${f.id}`;
      nodes.push({
        id: vNodeId,
        label: f.title,
        type: 'VULNERABILITY',
        severity: f.severity as any,
        cwe: f.cwe || 'CWE-Unknown',
        data: {
          findingId: f.id,
          confidence: f.confidence,
          category: f.category,
        },
      });

      // Edge from Entrypoint to Vulnerability
      edges.push({
        id: `e-${entryId}-${vNodeId}`,
        source: entryId,
        target: vNodeId,
        label: 'Recon & Input Probe',
        active: true,
      });

      // Chain vulnerability to Assets or Next Steps based on Category
      if (f.category === 'SQL_INJECTION' || f.cwe === 'CWE-89' || f.cwe === 'CWE-639') {
        edges.push({
          id: `e-${vNodeId}-${dbAssetId}`,
          source: vNodeId,
          target: dbAssetId,
          label: 'Direct Data Exfiltration',
          active: true,
        });
        pathCount++;
      } else if (f.category === 'COMMAND_INJECTION' || f.cwe === 'CWE-78' || f.cwe === 'CWE-1336') {
        edges.push({
          id: `e-${vNodeId}-${serverAssetId}`,
          source: vNodeId,
          target: serverAssetId,
          label: 'Arbitrary Code Execution',
          active: true,
        });
        pathCount++;
      } else if (f.cwe === 'CWE-538' || f.cwe === 'CWE-200' || f.title.toLowerCase().includes('cloud') || f.title.toLowerCase().includes('s3')) {
        edges.push({
          id: `e-${vNodeId}-${s3AssetId}`,
          source: vNodeId,
          target: s3AssetId,
          label: 'Public Bucket Access',
          active: true,
        });
        pathCount++;
      } else {
        // Generic impact link
        edges.push({
          id: `e-${vNodeId}-${serverAssetId}`,
          source: vNodeId,
          target: serverAssetId,
          label: 'Lateral Privilege Escalation',
          active: true,
        });
        pathCount++;
      }
    }

    const initialScore = Math.max(15, 100 - (scan.findings.filter(f => f.severity === 'CRITICAL').length * 25 + scan.findings.filter(f => f.severity === 'HIGH').length * 15 + scan.findings.filter(f => f.severity === 'MEDIUM').length * 5));

    return {
      scanId,
      targetUrl,
      nodes,
      edges,
      attackPathsCount: Math.max(pathCount, 1),
      overallRiskScore: initialScore,
    };
  }

  /**
   * "What If Fixed?" Counterfactual Attack-Path Simulator
   * Simulates the impact of fixing a specific set of findings on graph topology and risk score
   */
  public static async simulateWhatIf(scanId: number, findingIdsToFix: number[]): Promise<WhatIfSimulationResult> {
    const graph = await this.buildAttackGraph(scanId);
    const fixedSet = new Set(findingIdsToFix.map(id => `vuln-${id}`));

    let severedCount = 0;
    const simulatedEdges = graph.edges.map(e => {
      if (fixedSet.has(e.source) || fixedSet.has(e.target)) {
        severedCount++;
        return { ...e, active: false };
      }
      return e;
    });

    const activeEdgesCount = simulatedEdges.filter(e => e.active).length;
    const initialScore = graph.overallRiskScore;

    // Projected score increases as severed paths increase
    const potentialGain = 100 - initialScore;
    const fractionFixed = graph.edges.length > 0 ? severedCount / graph.edges.length : 1;
    const projectedScore = Math.min(100, Math.round(initialScore + potentialGain * fractionFixed));
    const riskReduction = Math.round(fractionFixed * 100);

    return {
      scanId,
      fixedFindingIds: findingIdsToFix,
      initialRiskScore: initialScore,
      projectedRiskScore: projectedScore,
      riskReductionPercentage: riskReduction,
      severedPathsCount: severedCount,
      remainingPathsCount: activeEdgesCount,
      nodes: graph.nodes,
      edges: simulatedEdges,
    };
  }
}
