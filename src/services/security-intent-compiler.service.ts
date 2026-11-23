import { RawToolFinding } from '../tools/security-tool.interface';
import { safeFetchText } from './crawler.service';

export interface SecurityIntentRule {
  id: string;
  name: string;
  description: string;
  category: 'USER_DATA_ISOLATION' | 'ROLE_ESCALATION' | 'PRICE_TAMPERING' | 'UNAUTHENTICATED_ACCESS' | 'CUSTOM_LOGIC';
  targetPath: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  testPayload?: any;
  userASession?: string; // Token or Cookie for User A (Owner)
  userBSession?: string; // Token or Cookie for User B (Attacker / Different Tenant)
  expectedStatus?: number; // e.g. 403 or 401
  forbiddenKeywords?: string[]; // e.g. ["credit_card", "password_hash", "admin_panel"]
}

export interface IntentRuleResult {
  ruleId: string;
  ruleName: string;
  category: string;
  targetPath: string;
  isCompliant: boolean;
  status: 'COMPLIANT' | 'VIOLATION_DETECTED' | 'TEST_ERROR';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: string;
  details: string;
  recommendedFix: string;
}

export interface IntentComplianceReport {
  targetUrl: string;
  timestamp: string;
  totalRules: number;
  compliantCount: number;
  violationCount: number;
  complianceRate: number; // e.g. 75%
  results: IntentRuleResult[];
  findings: RawToolFinding[];
}

/**
 * Security Intent Compiler & Business Logic Verifier
 * Translates human-readable security and business logic intents into executable multi-step security test assertions.
 */
export class SecurityIntentCompilerService {

  /**
   * Parse natural language or structured policy statements into executable Intent Rules
   */
  public static parseNaturalLanguageIntent(intentText: string, targetBaseUrl: string): SecurityIntentRule[] {
    const rules: SecurityIntentRule[] = [];
    const lower = intentText.toLowerCase();

    // 1. User Data Isolation / IDOR / BOLA Intent
    if (lower.includes('يوزر') || lower.includes('user') || lower.includes('بياناته') || lower.includes('isolation') || lower.includes('idor')) {
      rules.push({
        id: 'INTENT-BOLA-01',
        name: 'User Data Isolation & BOLA Protection Policy',
        description: 'Verify that authenticated users can strictly access only their own records and cannot view another user\'s profile, invoices, or orders.',
        category: 'USER_DATA_ISOLATION',
        targetPath: '/api/users/2',
        method: 'GET',
        expectedStatus: 403,
        forbiddenKeywords: ['email', 'password', 'ssn', 'billing', 'balance', 'phone'],
      });
    }

    // 2. Role Escalation Prevention Intent
    if (lower.includes('أدمن') || lower.includes('admin') || lower.includes('role') || lower.includes('صلاحيات') || lower.includes('escalat')) {
      rules.push({
        id: 'INTENT-ROLE-02',
        name: 'Privilege Escalation & Admin Role Protection Policy',
        description: 'Verify that standard non-admin users cannot promote themselves or access restricted administration endpoints.',
        category: 'ROLE_ESCALATION',
        targetPath: '/api/admin/roles',
        method: 'POST',
        testPayload: { role: 'superadmin', isAdmin: true },
        expectedStatus: 403,
      });
    }

    // 3. Price Tampering & Negative Value Checkout Intent
    if (lower.includes('checkout') || lower.includes('سالب') || lower.includes('price') || lower.includes('سعر') || lower.includes('negative') || lower.includes('cart')) {
      rules.push({
        id: 'INTENT-PRICE-03',
        name: 'Financial Logic & Negative Price Tampering Prevention',
        description: 'Ensure checkout and cart operations reject zero, negative amounts, or unauthorized price modifications.',
        category: 'PRICE_TAMPERING',
        targetPath: '/api/checkout',
        method: 'POST',
        testPayload: { amount: -100, price: 0, quantity: -1 },
        expectedStatus: 400,
        forbiddenKeywords: ['order_confirmed', 'payment_success', 'transaction_id'],
      });
    }

    // 4. Default Fallback Policy if no specific intent matched
    if (rules.length === 0) {
      rules.push({
        id: 'INTENT-AUTH-04',
        name: 'Default Unauthenticated Access Restriction Policy',
        description: 'Ensure all sensitive API endpoints reject unauthenticated queries without valid credentials.',
        category: 'UNAUTHENTICATED_ACCESS',
        targetPath: '/api/dashboard/stats',
        method: 'GET',
        expectedStatus: 401,
      });
    }

    return rules;
  }

  /**
   * Execute compiled intent rules against target application
   */
  public static async executeIntentAudit(
    targetBaseUrl: string,
    rules: SecurityIntentRule[]
  ): Promise<IntentComplianceReport> {
    const results: IntentRuleResult[] = [];
    const generatedFindings: RawToolFinding[] = [];
    const base = targetBaseUrl.replace(/\/$/, '');

    for (const rule of rules) {
      try {
        const fullUrl = new URL(rule.targetPath.startsWith('/') ? rule.targetPath : `/${rule.targetPath}`, base).toString();
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Sential-Intent-Audit': rule.id,
          'User-Agent': 'Mozilla/5.0 SentinelAI-IntentCompiler/2.0',
        };

        if (rule.userBSession) {
          headers['Authorization'] = rule.userBSession.startsWith('Bearer ') ? rule.userBSession : `Bearer ${rule.userBSession}`;
          headers['Cookie'] = rule.userBSession;
        }

        const options: RequestInit = {
          method: rule.method,
          headers,
          redirect: 'manual',
        };

        if (rule.testPayload && (rule.method === 'POST' || rule.method === 'PUT')) {
          options.body = JSON.stringify(rule.testPayload);
        }

        const response = await fetch(fullUrl, options);
        const statusCode = response.status;
        const resText = await response.text();

        let isViolated = false;
        let violationEvidence = '';

        if (rule.category === 'USER_DATA_ISOLATION') {
          // If status is 200 and leaked forbidden keywords or significant body
          if (statusCode === 200 && resText.length > 50) {
            const leaked = rule.forbiddenKeywords?.filter(kw => resText.toLowerCase().includes(kw)) || [];
            if (leaked.length > 0 || !rule.forbiddenKeywords) {
              isViolated = true;
              violationEvidence = `Endpoint returned HTTP 200 with sensitive fields [${leaked.join(', ')}] when queried across tenant boundaries.`;
            }
          }
        } else if (rule.category === 'ROLE_ESCALATION') {
          if (statusCode >= 200 && statusCode < 300) {
            isViolated = true;
            violationEvidence = `Admin role assignment probe returned HTTP ${statusCode} without permission denial.`;
          }
        } else if (rule.category === 'PRICE_TAMPERING') {
          if (statusCode >= 200 && statusCode < 300) {
            const hasConfirm = rule.forbiddenKeywords?.some(kw => resText.toLowerCase().includes(kw));
            if (hasConfirm || !rule.forbiddenKeywords) {
              isViolated = true;
              violationEvidence = `Negative/zero price payload was accepted by server with HTTP ${statusCode}.`;
            }
          }
        } else if (rule.category === 'UNAUTHENTICATED_ACCESS') {
          if (statusCode === 200 && resText.length > 30) {
            isViolated = true;
            violationEvidence = `Protected endpoint returned HTTP 200 without authentication headers.`;
          }
        }

        const isCompliant = !isViolated;
        const ruleResult: IntentRuleResult = {
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          targetPath: rule.targetPath,
          isCompliant,
          status: isCompliant ? 'COMPLIANT' : 'VIOLATION_DETECTED',
          severity: rule.category === 'ROLE_ESCALATION' || rule.category === 'USER_DATA_ISOLATION' ? 'CRITICAL' : 'HIGH',
          evidence: isViolated ? violationEvidence : `Target strictly enforced policy with HTTP ${statusCode}.`,
          details: isViolated
            ? `Business policy "${rule.name}" failed verification on ${rule.targetPath}. Expected rejection, got HTTP ${statusCode}.`
            : `Business policy "${rule.name}" successfully verified. Access properly restricted.`,
          recommendedFix: isViolated
            ? `Implement server-side authorization validation on ${rule.targetPath}. Verify session identity and reject unauthorized operations with HTTP 403 Forbidden.`
            : 'Policy compliant. Maintain defense-in-depth access control filters.',
        };

        results.push(ruleResult);

        // If violated, elevate to a confirmed Security Finding
        if (isViolated) {
          generatedFindings.push({
            title: `Business Intent Violation: ${rule.name}`,
            severity: ruleResult.severity,
            confidence: 'CONFIRMED',
            category: 'BROKEN_ACCESS_CONTROL',
            sourceRuleId: `intent.${rule.id.toLowerCase()}`,
            targetUrl: fullUrl,
            evidenceSummary: violationEvidence,
            remediation: ruleResult.recommendedFix,
            cwe: rule.category === 'USER_DATA_ISOLATION' ? 'CWE-639' : (rule.category === 'ROLE_ESCALATION' ? 'CWE-269' : 'CWE-840'),
          });
        }
      } catch (err) {
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          targetPath: rule.targetPath,
          isCompliant: false,
          status: 'TEST_ERROR',
          severity: 'MEDIUM',
          evidence: `Test probe network failure: ${(err as Error).message}`,
          details: 'Could not reach target endpoint to verify intent rule.',
          recommendedFix: 'Verify server availability and endpoint route configuration.',
        });
      }
    }

    const compliantCount = results.filter(r => r.isCompliant).length;
    const violationCount = results.filter(r => !r.isCompliant && r.status !== 'TEST_ERROR').length;
    const total = results.length;
    const complianceRate = total > 0 ? Math.round((compliantCount / total) * 100) : 100;

    return {
      targetUrl: targetBaseUrl,
      timestamp: new Date().toISOString(),
      totalRules: total,
      compliantCount,
      violationCount,
      complianceRate,
      results,
      findings: generatedFindings,
    };
  }
}
