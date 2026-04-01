import { MonitorAlert } from '../types';

export async function sendSlackAlert(webhookUrl: string, alert: MonitorAlert): Promise<void> {
  const payload = {
    text: `GuardRail alert: ${alert.packageName}@${alert.version}`,
    blocks: [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `GuardRail: ${alert.packageName}@${alert.version}`,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Previous:* ${alert.previousVersion ?? 'unknown'}` },
          { type: 'mrkdwn', text: `*Publish method:* ${alert.publishMethod}` },
          { type: 'mrkdwn', text: `*Publisher:* ${alert.publishedBy ?? 'unknown'}` },
          { type: 'mrkdwn', text: `*Risk score:* ${String(alert.scriptRiskScore)}` },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Reasons:* ${alert.reasons.join('; ') || 'no suspicious deltas detected'}`,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*New dependencies:* ${alert.newDependencies.join(', ') || 'none'}\n*Added lifecycle scripts:* ${alert.addedLifecycleScripts.join(', ') || 'none'}\n*Ghost dependencies:* ${alert.ghostDependencies.join(', ') || 'none'}`,
        },
      },
    ],
  };

  const response = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Slack webhook returned HTTP ${response.status}`);
  }
}
