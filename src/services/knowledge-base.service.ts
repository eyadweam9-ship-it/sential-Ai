import fs from 'fs';
import path from 'path';

export interface KbSastRuleDef {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pattern: string;
  scope?: 'BACKEND' | 'FRONTEND' | 'GLOBAL' | 'DOCKERFILE' | 'DOCKER_COMPOSE' | 'KUBERNETES' | 'TERRAFORM' | 'CI_CD' | string;
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
  scope: string;
}

class KnowledgeBaseService {
  private entries: KnowledgeBaseEntry[] = [];
  private entryById = new Map<string, KnowledgeBaseEntry>();
  private entriesByCwe = new Map<string, KnowledgeBaseEntry[]>();
  private sastRulesCache: ExecutableSastRule[] | null = null;
  private rulesByScope = new Map<string, ExecutableSastRule[]>();
  private isLoaded = false;

  constructor() {
    this.loadKnowledgeBase();
  }

  public loadKnowledgeBase(): void {
    try {
      const candidatePaths = [
        path.join(__dirname, '..', 'data', 'sentinelai_vulnerability_knowledge_base.json'),
        path.join(__dirname, '..', '..', 'src', 'data', 'sentinelai_vulnerability_knowledge_base.json'),
        path.join(process.cwd(), 'src', 'data', 'sentinelai_vulnerability_knowledge_base.json'),
        path.join(process.cwd(), 'dist', 'data', 'sentinelai_vulnerability_knowledge_base.json'),
        'D:\\Sential AI\\src\\data\\sentinelai_vulnerability_knowledge_base.json',
      ];
      const targetPath = candidatePaths.find(p => fs.existsSync(p)) || null;

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
    this.rulesByScope.clear();
    for (const r of rules) {
      const scope = (r.scope || 'BACKEND').toUpperCase();
      if (!this.rulesByScope.has(scope)) {
        this.rulesByScope.set(scope, []);
      }
      this.rulesByScope.get(scope)!.push(r);
    }
    return rules;
  }

  public getRulesForScope(scope: string): ExecutableSastRule[] {
    if (!this.sastRulesCache) this.getExecutableSastRules();
    return this.rulesByScope.get(scope.toUpperCase()) || [];
  }

  public getRulesForFile(filePath: string): ExecutableSastRule[] {
    if (!this.sastRulesCache) this.getExecutableSastRules();
    const lower = filePath.toLowerCase();
    const ext = path.extname(lower);
    const base = path.basename(lower);

    if (base === 'dockerfile' || base.startsWith('dockerfile.')) {
      return [...this.getRulesForScope('DOCKERFILE'), ...this.getRulesForScope('CONTAINER')];
    }
    if (ext === '.tf' || ext === '.tfvars') {
      return this.getRulesForScope('TERRAFORM');
    }
    if (ext === '.yaml' || ext === '.yml') {
      if (lower.includes('.github/') || lower.includes('.gitlab-ci') || base === 'jenkinsfile') {
        return this.getRulesForScope('CI_CD');
      }
      return this.getRulesForScope('KUBERNETES');
    }
    if (ext === '.c' || ext === '.cpp' || ext === '.cc' || ext === '.cxx' || ext === '.h' || ext === '.hpp') {
      return this.getRulesForScope('C_CPP');
    }
    if (ext === '.java' || ext === '.jsp' || ext === '.scala') {
      return this.getRulesForScope('JAVA');
    }
    if (ext === '.py') {
      return this.getRulesForScope('PYTHON');
    }
    if (ext === '.php') {
      return this.getRulesForScope('PHP');
    }
    if (ext === '.html' || lower.includes('client-scripts') || lower.includes('/public/') || lower.includes('\\public\\') || lower.includes('/assets/') || lower.includes('\\assets\\')) {
      return this.getRulesForScope('FRONTEND');
    }

    // Default application code (Node.js / JS / TS / General backend)
    const backendRules = [
      ...this.getRulesForScope('BACKEND'),
      ...this.getRulesForScope('GLOBAL'),
    ];

    if (ext === '.js' || ext === '.jsx' || ext === '.ts' || ext === '.tsx' || ext === '.mjs') {
      return backendRules.filter(r => !r.id.startsWith('python.') && !r.id.startsWith('java.') && !r.id.startsWith('php.') && !r.id.startsWith('c_cpp.'));
    }

    return backendRules;
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
