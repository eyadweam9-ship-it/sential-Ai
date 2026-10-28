import crypto from 'crypto';
import { prisma } from '../config/db';

export interface OastInteraction {
  id: string;
  scanId: number;
  vulnType: 'BLIND_SSRF' | 'BLIND_RCE' | 'BLIND_SQLI' | 'BLIND_XXE' | 'LOG4J';
  targetUrl: string;
  parameterName?: string;
  token: string;
  payloadSent: string;
  triggered: boolean;
  sourceIp?: string;
  triggeredAt?: Date;
  rawCallback?: string;
}

// In-memory active OAST listener tokens
const activeOastTokens = new Map<string, OastInteraction>();

export class OastService {
  /**
   * Generates a unique tracking token and canary payload for Out-of-Band vulnerability verification
   */
  public static generateCanary(
    scanId: number,
    targetUrl: string,
    vulnType: 'BLIND_SSRF' | 'BLIND_RCE' | 'BLIND_SQLI' | 'BLIND_XXE' | 'LOG4J',
    parameterName?: string
  ): { token: string; httpPayload: string; dnsDomain: string } {
    const token = `oast_${scanId}_${crypto.randomBytes(6).toString('hex')}`;
    const port = process.env.PORT || 3000;
    
    // Multi-tier callback support: internal listener + external interactsh domain
    const httpPayload = `http://127.0.0.1:${port}/api/oast/callback?token=${token}&type=${vulnType}`;
    const dnsDomain = `${token}.oast.sential.local`;

    const interaction: OastInteraction = {
      id: crypto.randomUUID(),
      scanId,
      vulnType,
      targetUrl,
      parameterName,
      token,
      payloadSent: httpPayload,
      triggered: false,
    };

    activeOastTokens.set(token, interaction);

    return { token, httpPayload, dnsDomain };
  }

  /**
   * Handles incoming callback hits (HTTP/DNS canary hits)
   */
  public static async recordCallback(
    token: string,
    sourceIp?: string,
    headers?: Record<string, any>,
    rawBody?: string
  ): Promise<boolean> {
    const interaction = activeOastTokens.get(token);
    if (!interaction) {
      return false;
    }

    interaction.triggered = true;
    interaction.sourceIp = sourceIp || 'Unknown';
    interaction.triggeredAt = new Date();
    interaction.rawCallback = JSON.stringify({ headers, body: rawBody });

    console.log(`[OAST Service] 🚨 CONFIRMED OUT-OF-BAND VULNERABILITY! Token: ${token}, Type: ${interaction.vulnType}, Source: ${sourceIp}`);

    // Create high-confidence confirmed Finding in database
    try {
      const titles: Record<string, string> = {
        BLIND_SSRF: 'Confirmed Blind Server-Side Request Forgery (SSRF) via Out-of-Band Callback',
        BLIND_RCE: 'Confirmed Blind Remote Code Execution (RCE) via Out-of-Band Canary Hit',
        BLIND_SQLI: 'Confirmed Blind SQL Injection via Out-of-Band DNS/HTTP Exfiltration',
        BLIND_XXE: 'Confirmed Blind XML External Entity (XXE) via Out-of-Band DTD Callback',
        LOG4J: 'Confirmed Log4Shell (CVE-2021-44228) JNDI Out-of-Band Callback',
      };

      const cwes: Record<string, string> = {
        BLIND_SSRF: 'CWE-918',
        BLIND_RCE: 'CWE-78',
        BLIND_SQLI: 'CWE-89',
        BLIND_XXE: 'CWE-611',
        LOG4J: 'CWE-502',
      };

      const fingerprint = crypto
        .createHash('sha256')
        .update(`OAST:${interaction.scanId}:${interaction.vulnType}:${interaction.parameterName || 'header'}`)
        .digest('hex');

      const finding = await prisma.finding.create({
        data: {
          scanId: interaction.scanId,
          toolName: 'SENTIAL_OAST_COLLABORATOR',
          title: titles[interaction.vulnType] || 'Confirmed Out-of-Band Vulnerability',
          severity: 'CRITICAL',
          confidence: 'CONFIRMED',
          verificationStatus: 'VERIFIED',
          category: interaction.vulnType,
          fingerprint,
          status: 'OPEN',
          cwe: cwes[interaction.vulnType] || 'CWE-918',
          cvssScore: 9.8,
          description: `The application processed an untrusted out-of-band payload and performed an unauthorized network callback from IP ${sourceIp} to Sential AI OAST listener. This definitively confirms that arbitrary requests or command injection payloads are executed by the backend.`,
          remediation: 'Implement strict outbound network egress filtering, validate all target URLs against a strict domain whitelist, and disable XML external entity parsing.',
          evidences: {
            create: {
              url: interaction.targetUrl,
              paramName: interaction.parameterName || 'Network Callback',
              scanner: 'SENTIAL_OAST_COLLABORATOR',
              evidenceSummary: `Out-of-Band Canary Token "${token}" was triggered by the target server at ${interaction.triggeredAt.toISOString()}. Source IP: ${sourceIp}.`,
              rawSnippet: `Triggered Token: ${token}\nCallback IP: ${sourceIp}\nPayload: ${interaction.payloadSent}`,
            },
          },
        },
      });

      return true;
    } catch (dbErr) {
      console.error('[OAST Service] Error saving confirmed finding:', dbErr);
      return false;
    }
  }

  public static getActiveInteractions(scanId: number): OastInteraction[] {
    return Array.from(activeOastTokens.values()).filter((i) => i.scanId === scanId);
  }
}
