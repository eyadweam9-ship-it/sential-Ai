export interface TokenVerificationResult {
  tokenType: 'GITHUB_TOKEN' | 'SLACK_TOKEN' | 'STRIPE_KEY' | 'AWS_ACCESS_KEY' | 'GENERIC';
  tokenValue: string;
  isLive: boolean;
  verifiedIdentity?: string;
  permissionsScope?: string;
  rawResponse?: string;
}

export class TokenVerifierService {
  /**
   * Safely verifies whether a detected API credential or secret token is currently active
   */
  public static async verifyToken(token: string): Promise<TokenVerificationResult> {
    const trimmed = token.trim();

    // 1. GitHub Personal Access Token or Fine-Grained Token
    if (trimmed.startsWith('ghp_') || trimmed.startsWith('github_pat_') || trimmed.startsWith('gho_')) {
      try {
        const res = await fetch('https://api.github.com/user', {
          headers: {
            'Authorization': `Bearer ${trimmed}`,
            'User-Agent': 'Sential-AI-Secret-Auditor/2.0',
            'Accept': 'application/vnd.github.v3+json',
          },
          signal: AbortSignal.timeout(5000),
        });

        if (res.status === 200) {
          const data = (await res.json()) as any;
          const scopes = res.headers.get('x-oauth-scopes') || 'default';
          return {
            tokenType: 'GITHUB_TOKEN',
            tokenValue: trimmed,
            isLive: true,
            verifiedIdentity: `GitHub User: ${data.login || 'Unknown'} (${data.name || 'No Name'}) - ID: ${data.id}`,
            permissionsScope: scopes,
          };
        } else if (res.status === 401 || res.status === 403) {
          return {
            tokenType: 'GITHUB_TOKEN',
            tokenValue: trimmed,
            isLive: false,
            verifiedIdentity: 'Revoked or Expired GitHub Token (HTTP 401 Unauthorized)',
          };
        }
      } catch (e) {}
    }

    // 2. Slack Bot or User Token
    if (trimmed.startsWith('xoxb-') || trimmed.startsWith('xoxp-')) {
      try {
        const res = await fetch('https://slack.com/api/auth.test', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${trimmed}`,
            'Content-Type': 'application/json',
          },
          signal: AbortSignal.timeout(5000),
        });

        if (res.ok) {
          const data = (await res.json()) as any;
          if (data.ok) {
            return {
              tokenType: 'SLACK_TOKEN',
              tokenValue: trimmed,
              isLive: true,
              verifiedIdentity: `Slack Team: "${data.team || 'Unknown'}" | Bot/User: "${data.user || 'Unknown'}"`,
            };
          }
        }
      } catch (e) {}
    }

    // 3. Stripe Secret Key
    if (trimmed.startsWith('sk_live_') || trimmed.startsWith('rk_live_')) {
      try {
        const res = await fetch('https://api.stripe.com/v1/balance', {
          headers: {
            'Authorization': `Bearer ${trimmed}`,
          },
          signal: AbortSignal.timeout(5000),
        });

        if (res.status === 200) {
          return {
            tokenType: 'STRIPE_KEY',
            tokenValue: trimmed,
            isLive: true,
            verifiedIdentity: 'Active Stripe Production Secret Key (Full Financial Account Access)',
          };
        } else if (res.status === 401) {
          return {
            tokenType: 'STRIPE_KEY',
            tokenValue: trimmed,
            isLive: false,
            verifiedIdentity: 'Revoked Stripe Secret Key',
          };
        }
      } catch (e) {}
    }

    // Default: Generic unverified secret
    return {
      tokenType: 'GENERIC',
      tokenValue: trimmed,
      isLive: false,
      verifiedIdentity: 'Unverified static pattern match',
    };
  }
}
