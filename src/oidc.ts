import { decodeJwt } from 'jose';
import { config } from './config';
import { tracedFetch } from './tracedFetch';
import { recordToken } from './debugLog';
import { buildClientAssertion } from './clientAssertion';

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

export async function exchangeCodeForToken(code: string): Promise<{ accessToken: string; idToken?: string }> {
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
  const json = (await res.json()) as { access_token: string; id_token?: string };
  recordToken('user access_token (login)', json.access_token, safeDecode(json.access_token));
  if (json.id_token) {
    recordToken('ID token (login)', json.id_token, safeDecode(json.id_token));
  }
  return { accessToken: json.access_token, idToken: json.id_token };
}

/**
 * Alternate login flow: the human user signs into the Agent app itself
 * (AGENT_CLIENT_ID) instead of the Resource App. The Agent has no client
 * secret, so it authenticates this code exchange the same way it does
 * everywhere else — private_key_jwt — rather than client_secret_basic. No
 * `resource` param here: this login isn't scoped to the resource app at all,
 * since the whole point is testing whether the Agent's own tokens (ID token
 * or access_token) can be used as the subject_token for the ID-JAG exchange.
 */
export function buildAgentAuthorizeUrl(state: string): string {
  const url = new URL(`${config.oktaOrgUrl}/oauth2/${config.loginAuthServerId}/v1/authorize`);
  url.searchParams.set('client_id', config.agentClientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('redirect_uri', config.agentRedirectUri);
  url.searchParams.set('state', state);
  return url.toString();
}

export async function exchangeAgentCodeForToken(code: string): Promise<{ accessToken: string; idToken?: string }> {
  const tokenUrl = `${config.oktaOrgUrl}/oauth2/${config.loginAuthServerId}/v1/token`;
  const clientAssertion = await buildClientAssertion(tokenUrl, 'jwt');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.agentRedirectUri,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
  });

  const res = await tracedFetch('agentlogin:token-exchange', tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`agent app login token exchange failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string; id_token?: string };
  recordToken('user access_token (agent login)', json.access_token, safeDecode(json.access_token));
  if (json.id_token) {
    recordToken('ID token (agent login)', json.id_token, safeDecode(json.id_token));
  }
  return { accessToken: json.access_token, idToken: json.id_token };
}
