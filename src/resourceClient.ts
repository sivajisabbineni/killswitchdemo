import { config } from './config';
import { tracedFetch } from './tracedFetch';

export interface ResourceAction {
  method: string;
  path: string;
}

export async function callResourceApi(
  accessToken: string,
  action: ResourceAction,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  let path = action.path;
  for (const [key, value] of Object.entries(params)) {
    path = path.replace(`:${key}`, encodeURIComponent(String(value)));
  }

  const res = await tracedFetch('resource:api-call', `${config.resourceApiBaseUrl}${path}`, {
    method: action.method,
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`resource API call failed: ${res.status} ${text}`);
  }
  if (!text) {
    return { status: res.status };
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
