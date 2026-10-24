import { Router, Request, Response } from 'express';
import { threatIntelSyncService } from '../services/threat-intel-sync.service';
import { knowledgeBaseService } from '../services/knowledge-base.service';

const router = Router();

/**
 * GET /api/threat-intel/stats
 * Overview of Knowledge Base + Live Threat Intel Feeds
 */
router.get('/stats', (req: Request, res: Response) => {
  try {
    const allKb = knowledgeBaseService.getAllEntries();
    const categories: Record<string, number> = {};
    const severities: Record<string, number> = {};

    for (const e of allKb) {
      categories[e.category] = (categories[e.category] || 0) + 1;
      severities[e.default_severity] = (severities[e.default_severity] || 0) + 1;
    }

    const intelStats = threatIntelSyncService.getStats();

    res.json({
      success: true,
      data: {
        knowledgeBase: {
          totalRules: allKb.length,
          categories,
          severities,
          sastExecutableRulesCount: knowledgeBaseService.getExecutableSastRules().length,
        },
        threatIntelligence: intelStats,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/threat-intel/kb
 * Query / filter through the 205 built-in Master Knowledge Base entries
 */
router.get('/kb', (req: Request, res: Response) => {
  try {
    const { category, severity, cwe, q } = req.query;
    let list = knowledgeBaseService.getAllEntries();

    if (category) {
      list = list.filter(e => e.category.toLowerCase() === String(category).toLowerCase());
    }
    if (severity) {
      list = list.filter(e => e.default_severity.toLowerCase() === String(severity).toLowerCase());
    }
    if (cwe) {
      list = list.filter(e => (e.cwe_id || '').toLowerCase().includes(String(cwe).toLowerCase()));
    }
    if (q) {
      const query = String(q).toLowerCase();
      list = list.filter(e =>
        e.name.toLowerCase().includes(query) ||
        e.description.toLowerCase().includes(query) ||
        (e.cwe_id && e.cwe_id.toLowerCase().includes(query)) ||
        e.id.toLowerCase().includes(query)
      );
    }

    res.json({
      success: true,
      count: list.length,
      entries: list.map(e => ({
        id: e.id,
        name: e.name,
        category: e.category,
        cwe_id: e.cwe_id,
        owasp_category: e.owasp_category,
        default_severity: e.default_severity,
        cvss_score: e.cvss_score,
        description: e.description,
        remediation_summary: e.remediation.guidance,
      })),
    });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/threat-intel/kb/:id
 * Retrieve complete KB entry including Before & After Code Diffs & DAST probes
 */
router.get('/kb/:id', (req: Request, res: Response) => {
  try {
    const id = String(req.params.id);
    const entry = knowledgeBaseService.getEntryById(id);
    if (!entry) {
      return res.status(404).json({ success: false, message: `Knowledge Base entry ${id} not found.` });
    }
    res.json({ success: true, entry });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * POST /api/threat-intel/scan-dependencies
 * Real-time batch dependency scanner against live OSV / GitHub Security Advisories
 */
router.post('/scan-dependencies', async (req: Request, res: Response) => {
  try {
    let deps = req.body.dependencies;

    // Support submitting raw manifest content directly
    if (!deps && req.body.manifestContent && req.body.manifestName) {
      deps = threatIntelSyncService.parseManifest(req.body.manifestName, req.body.manifestContent);
    }

    if (!Array.isArray(deps) || deps.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Must provide an array of dependencies [{ name, version, ecosystem }] or manifestContent + manifestName.',
      });
    }

    const scanResult = await threatIntelSyncService.batchScanDependencies(deps);
    res.json({ success: true, scanResult });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

/**
 * GET /api/threat-intel/search?q=CVE-2024-43796
 * Direct CVE or GHSA lookup
 */
router.get('/search', async (req: Request, res: Response) => {
  try {
    const q = req.query.q as string;
    if (!q) {
      return res.status(400).json({ success: false, message: 'Query parameter q is required.' });
    }

    const adv = await threatIntelSyncService.searchVulnerability(q);
    if (!adv) {
      return res.status(404).json({ success: false, message: `Advisory for ${q} not found.` });
    }

    res.json({ success: true, advisory: adv });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

export const threatIntelRouter = router;
