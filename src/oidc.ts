import { decodeJwt } from 'jose';
import { config } from './config';
import { tracedFetch } from './tracedFetch';
import { recordToken } from './debugLog';

function safeDecode(token: string): Record<string, unknown> | undefined {
  try {
    return decodeJwt(token);
  } catch {
    return undefined;
  }
}

/**
 * Step 1 of XAA: a normal OIDC Authorization Code login for the human user,
 * against the Resource App (the app the user is actually signing into). The
 * resulting access_token becomes the `subject_token` for the ID-JAG
 * token-exchange request in xaa.ts, which authenticates separately as the
 * Agent (Requesting App) via private_key_jwt.
 */
export function buildAuthorizeUrl(state: string): string {
  const url = new URL(`${config.oktaOrgUrl}/oauth2/${config.loginAuthServerId}/v1/authorize`);
  url.searchParams.set('client_id', config.resourceAppClientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('redirect_uri', config.agentRedirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('resource', config.loginResource);
  return url.toString();
}

export async function exchangeCodeForToken(code: string): Promise<{ accessToken: string }> {
  const tokenUrl = `${config.oktaOrgUrl}/oauth2/${config.loginAuthServerId}/v1/token`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.agentRedirectUri,
    resource: config.loginResource,
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization:
      'Basic ' + Buffer.from(`${config.resourceAppClientId}:${config.resourceAppClientSecret}`).toString('base64'),
  };

  const res = await tracedFetch('login:token-exchange', tokenUrl, { method: 'POST', headers, body });
  if (!res.ok) {
    throw new Error(`login token exchange failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string };
  recordToken('user access_token (login)', json.access_token, safeDecode(json.access_token));
  return { accessToken: json.access_token };
}
