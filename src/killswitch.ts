import { config } from './config';
import { tracedFetch } from './tracedFetch';
import { markAgentStopped, resetAgentState } from './agentState';

export interface WebhookResult {
  webhookOk: boolean;
  webhookError?: string;
}

async function callWebhook(
  label: string,
  webhookUrl: string,
  extraParams: Record<string, string> = {},
): Promise<WebhookResult> {
  const url = new URL(webhookUrl);
  url.searchParams.set('agentClientId', config.agentClientId);
  url.searchParams.set('timestamp', new Date().toISOString());
  for (const [key, value] of Object.entries(extraParams)) {
    url.searchParams.set(key, value);
  }

  try {
    const res = await tracedFetch(label, url.toString(), { method: 'GET' });
    if (!res.ok) {
      const detail = `webhook responded ${res.status}`;
      console.error(`${label} call failed:`, detail);
      return { webhookOk: false, webhookError: detail };
    }
    return { webhookOk: true };
  } catch (err) {
    const detail = (err as Error).message;
    console.error(`${label} call failed:`, detail);
    return { webhookOk: false, webhookError: detail };
  }
}

/**
 * Marks this agent as stopped (in-memory — the server process itself keeps
 * running so /debug stays reachable and you don't need to restart between
 * tests) and best-effort notifies the external killswitch webhook. A failed
 * webhook call is logged but never prevents the agent from being marked
 * stopped, and never crashes the process.
 */
export async function triggerKillswitch(
  reason: string,
  details: Record<string, unknown> = {},
): Promise<WebhookResult> {
  markAgentStopped(reason, details);

  const extraParams: Record<string, string> = { reason };
  if (Object.keys(details).length > 0) {
    extraParams.details = JSON.stringify(details);
  }
  return callWebhook('killswitch:webhook', config.killswitchWebhookUrl, extraParams);
}

/**
 * Clears the stopped state and best-effort notifies the external
 * "activation" webhook (the counterpart to the killswitch's deactivation
 * call) so whatever external system tracks this agent's status is kept in
 * sync. A failed webhook call is logged but never prevents the reset.
 */
export async function triggerActivation(): Promise<WebhookResult> {
  resetAgentState();
  return callWebhook('killswitch:reset-webhook', config.killswitchWebhookResetUrl);
}
