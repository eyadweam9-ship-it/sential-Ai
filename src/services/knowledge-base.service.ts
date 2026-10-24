import fs from 'fs';
import path from 'path';

export interface KbSastRuleDef {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  scope?: 'BACKEND' | 'FRONTEND' | 'GLOBAL';
}

export interface KbDastProbeDef {
  endpoints?: string[];
  test_payloads?: string[];
  expected_signature?: string;
  negative_signature?: string;
}

export interface KbRemediationDef {
  guidance: string;
  vulnerable_code?: string;
  secure_code?: string;
}

export interface KnowledgeBaseEntry {
  id: string;
  name: string;
  category: string;
  cwe_id: string;
  owasp_category: string;
  default_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  cvss_score: number;
  cvss_vector: string;
  description: string;
  root_cause: string;
  sast_detection: {
    rules: KbSastRuleDef[];
    sinks?: string[];
    taint_sources?: string[];
  };
  dast_probing?: KbDastProbeDef;
  remediation: KbRemediationDef;
  business_impact: string;
  references: string[];
}

export interface ExecutableSastRule {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  cwe: string;
  regex: RegExp;
  remediation: string;
  scope: 'BACKEND' | 'FRONTEND' | 'GLOBAL';
}

class KnowledgeBaseService {
  private entries: KnowledgeBaseEntry[] = [];
  private entryById = new Map<string, KnowledgeBaseEntry>();
  private entriesByCwe = new Map<string, KnowledgeBaseEntry[]>();
  private sastRulesCache: ExecutableSastRule[] | null = null;
  private isLoaded = false;

  constructor() {
    this.loadKnowledgeBase();
  }

  public loadKnowledgeBase(): void {
    try {
      const kbPath = path.join(process.cwd(), 'src', 'data', 'sentinelai_vulnerability_knowledge_base.json');
      const distKbPath = path.join(process.cwd(), 'dist', 'data', 'sentinelai_vulnerability_knowledge_base.json');

      const targetPath = fs.existsSync(kbPath)
        ? kbPath
        : fs.existsSync(distKbPath)
        ? distKbPath
        : null;

      if (!targetPath) {
        console.warn('[SentinelAI KB] Knowledge Base JSON file not found on disk, running with embedded fallbacks.');
        return;
      }

      const content = fs.readFileSync(targetPath, 'utf8');
      const parsed: KnowledgeBaseEntry[] = JSON.parse(content);

      if (Array.isArray(parsed)) {
        this.entries = parsed;
        this.entryById.clear();
        this.entriesByCwe.clear();
        this.sastRulesCache = null;

        for (const entry of this.entries) {
          this.entryById.set(entry.id, entry);

          const cweNorm = (entry.cwe_id || '').toUpperCase().trim();
          if (cweNorm) {
            if (!this.entriesByCwe.has(cweNorm)) {
              this.entriesByCwe.set(cweNorm, []);
            }
            this.entriesByCwe.get(cweNorm)!.push(entry);
          }
        }

        this.isLoaded = true;
        console.log(`[SentinelAI KB] Successfully loaded ${this.entries.length} comprehensive vulnerability definitions from Knowledge Base.`);
      }
    } catch (err) {
      console.error('[SentinelAI KB] Failed to parse sentinelai_vulnerability_knowledge_base.json:', err);
    }
  }

  public getAllEntries(): KnowledgeBaseEntry[] {
    if (!this.isLoaded) this.loadKnowledgeBase();
    return this.entries;
  }

  public getEntryById(id: string): KnowledgeBaseEntry | undefined {
    if (!this.isLoaded) this.loadKnowledgeBase();
    return this.entryById.get(id);
  }

  public getEntriesByCwe(cwe: string): KnowledgeBaseEntry[] {
    if (!this.isLoaded) this.loadKnowledgeBase();
    const cweNorm = (cwe || '').toUpperCase().trim();
    return this.entriesByCwe.get(cweNorm) || [];
  }

  public getPrimaryEntryByCwe(cwe: string): KnowledgeBaseEntry | undefined {
    const list = this.getEntriesByCwe(cwe);
    return list[0];
  }

  public getExecutableSastRules(): ExecutableSastRule[] {
    if (!this.isLoaded) this.loadKnowledgeBase();
    if (this.sastRulesCache) return this.sastRulesCache;

    const rules: ExecutableSastRule[] = [];

    for (const entry of this.entries) {
      if (entry.sast_detection && Array.isArray(entry.sast_detection.rules)) {
        for (const r of entry.sast_detection.rules) {
          try {
            rules.push({
              id: r.id,
              title: r.title,
              severity: r.severity,
              category: entry.category,
              cwe: entry.cwe_id,
              regex: new RegExp(r.pattern, 'i'),
              remediation: entry.remediation.guidance,
              scope: r.scope || 'BACKEND',
            });
          } catch (e) {
            console.warn(`[SentinelAI KB] Invalid regex pattern for rule ${r.id}:`, r.pattern);
          }
        }
      }
    }

    this.sastRulesCache = rules;
    return rules;
  }

  public getRemediationDiff(cweOrTitle: string): KbRemediationDef | null {
    if (!this.isLoaded) this.loadKnowledgeBase();
    const target = (cweOrTitle || '').toLowerCase();

    // 1. Direct CWE match
    for (const [cwe, entries] of this.entriesByCwe) {
      if (target.includes(cwe.toLowerCase()) && entries[0]?.remediation) {
        return entries[0].remediation;
      }
    }

    // 2. Name / Category match
    for (const entry of this.entries) {
      if (target.includes(entry.name.toLowerCase()) || entry.name.toLowerCase().includes(target)) {
        return entry.remediation;
      }
    }

    return null;
  }
}

export const knowledgeBaseService = new KnowledgeBaseService();
