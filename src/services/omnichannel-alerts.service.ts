export interface AlertPayload {
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe?: string;
  cvssScore?: number;
  targetUrl: string;
  evidenceSummary?: string;
  recommendation?: string;
  scanId?: number;
  timestamp?: string;
}

export interface WebhookConfig {
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
  telegramBotToken?: string;
  telegramChatId?: string;
  teamsWebhookUrl?: string;
  enabled: boolean;
  minSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

/**
 * Omnichannel Security Alerts Dispatcher
 * Bridges Sential AI detections with Slack, Discord, Telegram, and Microsoft Teams.
 */
export class OmnichannelAlertService {
  private static config: WebhookConfig = {
    enabled: true,
    minSeverity: 'HIGH',
    slackWebhookUrl: process.env.SLACK_WEBHOOK_URL || '',
    discordWebhookUrl: process.env.DISCORD_WEBHOOK_URL || '',
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
    telegramChatId: process.env.TELEGRAM_CHAT_ID || '',
    teamsWebhookUrl: process.env.TEAMS_WEBHOOK_URL || '',
  };

  public static configure(newConfig: Partial<WebhookConfig>): WebhookConfig {
    this.config = { ...this.config, ...newConfig };
    return this.config;
  }

  public static getConfig(): WebhookConfig {
    return this.config;
  }

  /**
   * Broadcast a critical security finding or drift across all configured channels
   */
  public static async broadcastAlert(alert: AlertPayload): Promise<{
    slack: boolean;
    discord: boolean;
    telegram: boolean;
    teams: boolean;
  }> {
    const results = { slack: false, discord: false, telegram: false, teams: false };
    if (!this.config.enabled) return results;

    const promises: Promise<any>[] = [];

    // 1. Slack Webhook Dispatch
    if (this.config.slackWebhookUrl) {
      promises.push(
        this.sendSlackAlert(this.config.slackWebhookUrl, alert)
          .then(ok => { results.slack = ok; })
          .catch(() => {})
      );
    }

    // 2. Discord Webhook Dispatch
    if (this.config.discordWebhookUrl) {
      promises.push(
        this.sendDiscordAlert(this.config.discordWebhookUrl, alert)
          .then(ok => { results.discord = ok; })
          .catch(() => {})
      );
    }

    // 3. Telegram Bot API Dispatch
    if (this.config.telegramBotToken && this.config.telegramChatId) {
      promises.push(
        this.sendTelegramAlert(this.config.telegramBotToken, this.config.telegramChatId, alert)
          .then(ok => { results.telegram = ok; })
          .catch(() => {})
      );
    }

    // 4. Microsoft Teams Webhook Dispatch
    if (this.config.teamsWebhookUrl) {
      promises.push(
        this.sendTeamsAlert(this.config.teamsWebhookUrl, alert)
          .then(ok => { results.teams = ok; })
          .catch(() => {})
      );
    }

    await Promise.allSettled(promises);
    return results;
  }

  private static async sendSlackAlert(url: string, alert: AlertPayload): Promise<boolean> {
    const color = alert.severity === 'CRITICAL' ? '#dc2626' : (alert.severity === 'HIGH' ? '#ea580c' : '#ca8a04');
    const body = {
      text: `🚨 *[Sential AI Security Alert]*: ${alert.severity} Vulnerability Detected!`,
      attachments: [
        {
          color,
          title: alert.title,
          title_link: alert.targetUrl,
          fields: [
            { title: 'Severity', value: alert.severity, short: true },
            { title: 'CVSS Score', value: `${alert.cvssScore || 8.5} / 10.0`, short: true },
            { title: 'CWE', value: alert.cwe || 'CWE-Unknown', short: true },
            { title: 'Target', value: alert.targetUrl, short: true },
            { title: 'Evidence', value: alert.evidenceSummary?.slice(0, 250) || 'Verified active security finding.', short: false },
          ],
          footer: 'Sential AI Autonomous Security Platform',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.ok;
  }

  private static async sendDiscordAlert(url: string, alert: AlertPayload): Promise<boolean> {
    const color = alert.severity === 'CRITICAL' ? 14423100 : (alert.severity === 'HIGH' ? 15357964 : 13273604);
    const body = {
      content: `🚨 **[Sential AI Alert]** Critical Security Defect Detected on \`${alert.targetUrl}\``,
      embeds: [
        {
          title: alert.title,
          url: alert.targetUrl,
          color,
          fields: [
            { name: 'Severity', value: alert.severity, inline: true },
            { name: 'CVSS v3.1', value: `${alert.cvssScore || 8.5}`, inline: true },
            { name: 'CWE Code', value: alert.cwe || 'N/A', inline: true },
            { name: 'Observation & Evidence', value: alert.evidenceSummary?.slice(0, 300) || 'Verified active finding.', inline: false },
            { name: 'Remediation', value: alert.recommendation?.slice(0, 300) || 'Review remediation guidance in dashboard.', inline: false },
          ],
          footer: { text: 'Sential AI DevSecOps Alert' },
          timestamp: new Date().toISOString(),
        },
      ],
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.ok;
  }

  private static async sendTelegramAlert(token: string, chatId: string, alert: AlertPayload): Promise<boolean> {
    const text = `🚨 *[Sential AI Security Alert]*\n\n` +
      `*Title:* ${alert.title}\n` +
      `*Severity:* ${alert.severity} (CVSS: ${alert.cvssScore || 8.5})\n` +
      `*CWE:* ${alert.cwe || 'N/A'}\n` +
      `*Target:* \`${alert.targetUrl}\`\n\n` +
      `*Evidence:* _${alert.evidenceSummary?.slice(0, 200) || 'Verified active finding'}_\n\n` +
      `🛡️ *Status:* Action required by SecOps team.`;

    const endpoint = `https://api.telegram.org/bot${token}/sendMessage`;
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'Markdown',
      }),
    });
    return res.ok;
  }

  private static async sendTeamsAlert(url: string, alert: AlertPayload): Promise<boolean> {
    const body = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      'themeColor': alert.severity === 'CRITICAL' ? 'd63384' : '0d6efd',
      'summary': alert.title,
      'sections': [
        {
          'activityTitle': `🚨 Sential AI Alert: ${alert.title}`,
          'activitySubtitle': `Target: ${alert.targetUrl} | Severity: ${alert.severity}`,
          'facts': [
            { 'name': 'CVSS v3.1', 'value': `${alert.cvssScore || 8.5}` },
            { 'name': 'CWE', 'value': alert.cwe || 'N/A' },
            { 'name': 'Evidence', 'value': alert.evidenceSummary?.slice(0, 200) || 'Verified defect.' },
          ],
          'markdown': true,
        },
      ],
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.ok;
  }
}
