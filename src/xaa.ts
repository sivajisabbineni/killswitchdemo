import { decodeJwt } from 'jose';
import { config } from './config';
import { buildClientAssertion, type AgentIdentity } from './clientAssertion';
import { tracedFetch } from './tracedFetch';
import { recordToken, recordCall, clearCallsByLabel, clearTokensByLabel } from './debugLog';

function safeDecode(token: string): Record<string, unknown> | undefined {
  try {
    return decodeJwt(token);
  } catch {
    return undefined;
  }
}

export type SubjectTokenType = 'access_token' | 'id_token';

const SUBJECT_TOKEN_TYPE_URN: Record<SubjectTokenType, string> = {
  access_token: 'urn:ietf:params:oauth:token-type:access_token',
  id_token: 'urn:ietf:params:oauth:token-type:id_token',
};

interface XaaHopOptions {
  idJagLabel: string;
  resourceTokenLabel: string;
  idJagTokenName: string;
  resourceTokenName: string;
  resourceAuthServerId: string;
  resourceAppTokenEndpoint: string;
  scope: string;
  identity?: AgentIdentity;
  // RFC 8707 resource indicator naming the *next* hop's resource URL — only
  // set on the hop that hands its resulting access_token off to another
  // agent (e.g. Agent 1's own ID-JAG request naming Agent 2 as the resource),
  // per https://developer.okta.com/docs/guides/ai-agent-token-exchange/agent-to-agent/main/#exchange-subject-token-for-resource-token.
  nextHopResourceUrl?: string;
}

/**
 * Step 2 of XAA (RFC 8693 token exchange): trade the subject token (access
 * token, ID token, or — for a chained hop — a previous resource access
 * token) for an ID-JAG, authenticating the agent with a signed
 * client_assertion (private_key_jwt) per the Identity Assertion Authorization
 * Grant draft.
 */
async function requestIdJag(
  subjectToken: string,
  subjectTokenType: SubjectTokenType,
  opts: XaaHopOptions,
): Promise<string> {
  const tokenEndpoint = `${config.oktaOrgUrl}/oauth2/v1/token`;
  let clientAssertion: string;
  try {
    clientAssertion = await buildClientAssertion(tokenEndpoint, 'oauth-id-jag+jwt', opts.identity);
  } catch (err) {
    recordCall({ label: opts.idJagLabel, method: 'POST', url: tokenEndpoint, error: `client_assertion signing failed: ${(err as Error).message}` });
    throw err;
  }
  const audience = `${config.oktaOrgUrl}/oauth2/${opts.resourceAuthServerId}`;

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    subject_token_type: SUBJECT_TOKEN_TYPE_URN[subjectTokenType],
    subject_token: subjectToken,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    audience,
    scope: opts.scope,
  });
  if (opts.nextHopResourceUrl) {
    body.set('resource', opts.nextHopResourceUrl);
  }

  const res = await tracedFetch(opts.idJagLabel, tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`ID-JAG request failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string };
  recordToken(opts.idJagTokenName, json.access_token, safeDecode(json.access_token));
  return json.access_token;
}

/**
 * Step 3 of XAA: exchange the ID-JAG for a real access token at the resource
 * app's own authorization server, via the jwt-bearer grant (RFC 7523). The
 * Agent authenticates as itself here too (private_key_jwt, typ "jwt") — the
 * resource app's own client credentials are never used for this call.
 */
async function exchangeIdJagForAccessToken(
  idJag: string,
  opts: XaaHopOptions,
): Promise<{ accessToken: string; expiresIn: number }> {
  let clientAssertion: string;
  try {
    clientAssertion = await buildClientAssertion(opts.resourceAppTokenEndpoint, 'jwt', opts.identity);
  } catch (err) {
    recordCall({ label: opts.resourceTokenLabel, method: 'POST', url: opts.resourceAppTokenEndpoint, error: `client_assertion signing failed: ${(err as Error).message}` });
    throw err;
  }
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: idJag,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: clientAssertion,
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  });

  const res = await tracedFetch(opts.resourceTokenLabel, opts.resourceAppTokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) {
    throw new Error(`resource token exchange failed: ${res.status} ${await res.text()}`);
  }
  const json = (await res.json()) as { access_token: string; expires_in?: number };
  recordToken(opts.resourceTokenName, json.access_token, safeDecode(json.access_token));
  return { accessToken: json.access_token, expiresIn: json.expires_in ?? 3600 };
}

const FIRST_HOP: XaaHopOptions = {
  idJagLabel: 'xaa:id-jag-request',
  resourceTokenLabel: 'xaa:resource-token-exchange',
  idJagTokenName: 'ID-JAG',
  resourceTokenName: 'resource access_token',
  resourceAuthServerId: config.resourceAuthServerId,
  resourceAppTokenEndpoint: config.resourceAppTokenEndpoint,
  scope: config.xaaScope,
};

async function runXaaExchange(
  subjectToken: string,
  subjectTokenType: SubjectTokenType,
  opts: XaaHopOptions = FIRST_HOP,
): Promise<{ accessToken: string; expiresIn: number }> {
  // Every fresh attempt starts clean: otherwise a failure partway through
  // (e.g. T2 rejecting an ID token) would leave T3's card still showing the
  // token/result from a previous, unrelated successful attempt.
  clearCallsByLabel([opts.idJagLabel, opts.resourceTokenLabel]);
  clearTokensByLabel([opts.idJagTokenName, opts.resourceTokenName]);
  const idJag = await requestIdJag(subjectToken, subjectTokenType, opts);
  return exchangeIdJagForAccessToken(idJag, opts);
}

/**
 * Always runs a fresh ID-JAG + resource-token exchange against Okta — no
 * caching. Every call is a live check of whether the Agent's XAA trust is
 * still valid, so a killswitch that revoked it upstream shows up as a real
 * rejection here instead of the app quietly reusing a still-valid token.
 */
export async function testXaaLogin(
  subjectToken: string,
  subjectTokenType: SubjectTokenType = 'access_token',
): Promise<string> {
  const { accessToken } = await runXaaExchange(subjectToken, subjectTokenType);
  return accessToken;
}

export function isChainedXaaConfigured(): boolean {
  return Boolean(
    config.secondAgentClientId &&
      config.secondAgentKeyId &&
      config.secondAgentPrivateKeyPem &&
      config.secondResourceAuthServerId &&
      config.secondResourceAppTokenEndpoint &&
      config.secondAgentResourceUrl &&
      config.thirdResourceAuthServerId &&
      config.thirdResourceAppTokenEndpoint,
  );
}

/**
 * Chained XAA hop A: Agent 1 invokes Agent 2. Agent 1 signs with its own
 * identity (default) and requests an ID-JAG whose `audience` is Agent 2's own
 * custom authorization server — NOT the original single-hop resource app's
 * auth server. `resource` names Agent 2's registered resource URL, matching
 * https://developer.okta.com/docs/guides/ai-agent-token-exchange/agent-to-agent/main/#exchange-subject-token-for-resource-token
 * (`agent2().audience` / `agent2().resource` in the reference O4AA-All-Agentic-Flows
 * implementation's server/config.js `financeAgent` block). Redeeming the
 * resulting ID-JAG at Agent 2's own token endpoint produces "a token for
 * Agent 1 to invoke Agent 2".
 */
function buildChainedHopA(): XaaHopOptions {
  if (!isChainedXaaConfigured()) {
    throw new Error(
      'Chained XAA is not configured — set SECOND_AGENT_CLIENT_ID, SECOND_AGENT_KEY_ID, SECOND_AGENT_PRIVATE_KEY_PEM, SECOND_RESOURCE_AUTH_SERVER_ID, SECOND_RESOURCE_APP_TOKEN_ENDPOINT and SECOND_AGENT_RESOURCE_URL.',
    );
  }
  return {
    idJagLabel: 'xaa2:id-jag-request',
    resourceTokenLabel: 'xaa2:resource-token-exchange',
    idJagTokenName: 'ID-JAG (Agent 1 → Agent 2)',
    resourceTokenName: 'Agent 1 → Agent 2 access_token',
    resourceAuthServerId: config.secondResourceAuthServerId!,
    resourceAppTokenEndpoint: config.secondResourceAppTokenEndpoint!,
    scope: config.secondXaaScope,
    nextHopResourceUrl: config.secondAgentResourceUrl,
  };
}

/**
 * Chained XAA hop B: Agent 2 invokes the downstream resource, using hop A's
 * resulting access_token as its own subject_token. Agent 2 signs with its own
 * identity/private key and targets a third, distinct auth server — Agent 2's
 * actual downstream resource (THIRD_RESOURCE_AUTH_SERVER_ID /
 * THIRD_RESOURCE_APP_TOKEN_ENDPOINT), separate from both Agent 1's resource
 * and Agent 2's own auth server used in hop A. Matches the reference
 * implementation's separate "Finance MCP" resource server behind the Finance
 * Agent, per
 * https://developer.okta.com/docs/guides/ai-agent-token-exchange/agent-to-agent/main/#agent-2-exchanges-token-for-id-jag.
 */
function buildChainedHopB(): XaaHopOptions {
  if (!config.thirdResourceAuthServerId || !config.thirdResourceAppTokenEndpoint) {
    throw new Error('Chained XAA hop B is not configured — set THIRD_RESOURCE_AUTH_SERVER_ID and THIRD_RESOURCE_APP_TOKEN_ENDPOINT.');
  }
  return {
    idJagLabel: 'xaa3:id-jag-request',
    resourceTokenLabel: 'xaa3:resource-token-exchange',
    idJagTokenName: 'ID-JAG (Agent 2)',
    resourceTokenName: 'resource access_token (Agent 2)',
    resourceAuthServerId: config.thirdResourceAuthServerId,
    resourceAppTokenEndpoint: config.thirdResourceAppTokenEndpoint,
    scope: config.thirdXaaScope,
    identity: {
      clientId: config.secondAgentClientId!,
      keyId: config.secondAgentKeyId!,
      privateKeyPem: config.secondAgentPrivateKeyPem!,
    },
  };
}

/**
 * Chained XAA: User -> Agent 1 -> Agent 2 -> Resource. See buildChainedHopA/B
 * for what each hop's ID-JAG request targets and who signs it.
 */
export async function testChainedXaaLogin(
  subjectToken: string,
  subjectTokenType: SubjectTokenType = 'access_token',
): Promise<{ firstHopAccessToken: string; secondHopAccessToken: string }> {
  const hopA = buildChainedHopA();
  const hopB = buildChainedHopB();
  const { accessToken: firstHopAccessToken } = await runXaaExchange(subjectToken, subjectTokenType, hopA);
  const { accessToken: secondHopAccessToken } = await runXaaExchange(firstHopAccessToken, 'access_token', hopB);
  return { firstHopAccessToken, secondHopAccessToken };
}
