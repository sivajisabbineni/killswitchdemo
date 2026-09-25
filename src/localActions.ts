import { recordCall } from './debugLog';
import { listCampaigns, getCampaign, updateCampaign, createCampaign } from './marketingStore';
import type { AllowedAction } from './policy';

/**
 * Runs a `kind: 'local'` action (currently just marketing.* — see policy.ts)
 * against the in-process marketingStore instead of calling out to the
 * resource API. Still records a synthetic call via recordCall in the same
 * shape tracedFetch produces (method, url, Authorization header, JSON
 * bodies), so it renders in the existing T4/T9 "Agent Action" step card —
 * including the Token tab's bearer-claims decode, which reads the
 * Authorization header the same way regardless of who called recordCall.
 */
export async function runLocalAction(
  label: string,
  action: AllowedAction,
  actionName: string,
  params: Record<string, unknown>,
  accessToken: string,
): Promise<unknown> {
  const merged: Record<string, unknown> = { ...action.defaultParams, ...params };
  let path = action.path;
  for (const [key, value] of Object.entries(merged)) {
    path = path.replace(`:${key}`, encodeURIComponent(String(value)));
  }
  const url = `local://marketing${path}`;
  const requestHeaders = { Authorization: `Bearer ${accessToken}` };

  let result: unknown;
  try {
    if (actionName === 'marketing.list') {
      result = listCampaigns();
    } else if (actionName === 'marketing.get') {
      result = getCampaign(String(merged.id));
    } else if (actionName === 'marketing.update') {
      result = updateCampaign(String(merged.id), { status: merged.status as string | undefined, budget: merged.budget as string | number | undefined });
    } else if (actionName === 'marketing.create') {
      result = createCampaign({
        name: String(merged.name ?? ''),
        status: merged.status as string | undefined,
        budget: merged.budget as string | number | undefined,
        channel: merged.channel as string | undefined,
      });
    } else {
      throw new Error(`Unknown local action "${actionName}"`);
    }
  } catch (err) {
    recordCall({
      label,
      method: action.method,
      url,
      requestHeaders,
      requestBody: JSON.stringify(merged),
      status: 400,
      responseBody: JSON.stringify({ error: (err as Error).message }),
    });
    throw err;
  }

  recordCall({
    label,
    method: action.method,
    url,
    requestHeaders,
    requestBody: JSON.stringify(merged),
    status: 200,
    responseBody: JSON.stringify(result),
  });
  return result;
}
