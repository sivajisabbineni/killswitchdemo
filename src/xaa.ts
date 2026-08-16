import { decodeJwt } from 'jose';
import { config } from './config';
import { buildClientAssertion } from './clientAssertion';
import { tracedFetch } from './tracedFetch';
import { recordToken, recordCall } from './debugLog';

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

// Keyed by the user's access_token so different logged-in users don't share tokens.
const cache = new Map<string, CachedToken>();

function safeDecode(token: string): Record<string, unknown> | undefined {
  try {
    return decodeJwt(token);
  } catch {
    return undefined;
  }
}

/**
 * Step 2 of XAA (RFC 8693 token exchange): trade the user's access_token for
 * an ID-JAG, authenticating the agent with a signed client_assertion
 * (private_key_jwt) per the Identity Assertion Authorization Grant draft.
 */
async function requestIdJag(userAccessToken: string): Promise<string> {
  const tokenEndpoint = `${config.oktaOrgUrl}/oauth2/v1/token`;
  let clientAssertion: string;
  try {
    clientAssertion = await buildClientAssertion(tokenEndpoint, 'oauth-id-jag+jwt');
  } catch (err) {
    recordCall({ label: 'xaa:id-jag-request', method: 'POST', url: tokenEndpoint, error: `client_assertion signing failed: ${(err as Error).message}` });
    throw err;
  }
  const audience = `${config.oktaOrgUrl}/oauth2/${config.resourceAuthServerId}`;

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    subject_token: userAccessToken,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    audience,
    scope: config.xaaScope,
  });

  const res = await tracedFetch('xaa:id-jag-request', tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`ID-JAG request failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string };
  recordToken('ID-JAG', json.access_token, safeDecode(json.access_token));
  return json.access_token;
}

/**
 * Step 3 of XAA: exchange the ID-JAG for a real access token at the resource
 * app's own authorization server, via the jwt-bearer grant (RFC 7523). The
 * Agent authenticates as itself here too (private_key_jwt, typ "jwt") — the
 * resource app's own client credentials are never used for this call.
 */
async function exchangeIdJagForAccessToken(idJag: string): Promise<{ accessToken: string; expiresIn: number }> {
  let clientAssertion: string;
  try {
    clientAssertion = await buildClientAssertion(config.resourceAppTokenEndpoint, 'jwt');
  } catch (err) {
    recordCall({ label: 'xaa:resource-token-exchange', method: 'POST', url: config.resourceAppTokenEndpoint, error: `client_assertion signing failed: ${(err as Error).message}` });
    throw err;
  }
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: idJag,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  });

  const res = await tracedFetch('xaa:resource-token-exchange', config.resourceAppTokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`resource token exchange failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string; expires_in?: number };
  recordToken('resource access_token', json.access_token, safeDecode(json.access_token));
  return { accessToken: json.access_token, expiresIn: json.expires_in ?? 3600 };
}

async function runXaaExchange(userAccessToken: string): Promise<{ accessToken: string; expiresIn: number }> {
  const idJag = await requestIdJag(userAccessToken);
  return exchangeIdJagForAccessToken(idJag);
}

export async function getResourceAccessToken(userAccessToken: string): Promise<string> {
  const cached = cache.get(userAccessToken);
  if (cached && cached.expiresAt > Date.now() + 5000) {
    return cached.accessToken;
  }

  const { accessToken, expiresIn } = await runXaaExchange(userAccessToken);
  cache.set(userAccessToken, { accessToken, expiresAt: Date.now() + expiresIn * 1000 });
  return accessToken;
}

/**
 * Forces a fresh run of the ID-JAG + resource-token exchange, bypassing the
 * cache, so testing the Agent's XAA login always re-exercises both hops
 * (and re-populates the /debug call log + token list) instead of silently
 * returning a cached result.
 */
export async function testXaaLogin(userAccessToken: string): Promise<string> {
  const { accessToken, expiresIn } = await runXaaExchange(userAccessToken);
  cache.set(userAccessToken, { accessToken, expiresAt: Date.now() + expiresIn * 1000 });
  return accessToken;
}
