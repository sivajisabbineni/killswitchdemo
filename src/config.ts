import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';

/**
 * A plain KEY=VALUE line can't span multiple raw lines, so a PEM pasted in
 * its natural multi-line form (BEGIN/base64 body/END on separate lines)
 * would otherwise get truncated to just its first line. This joins any
 * "KEY=-----BEGIN ...-----" line through its matching "-----END ...-----"
 * line into one value (with literal \n) before handing off to dotenv.
 */
function loadPropertiesFile(filePath: string): void {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch {
    return; // no local properties file — e.g. Render sets env vars directly
  }

  const lines = raw.split(/\r?\n/);
  const normalized: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(-----BEGIN [^-]+-----)$/.exec(line.trim());
    if (match) {
      const [, key, beginMarker] = match;
      const parts = [beginMarker];
      i++;
      while (i < lines.length && !lines[i].includes('-----END')) {
        parts.push(lines[i]);
        i++;
      }
      if (i < lines.length) {
        parts.push(lines[i]);
      }
      normalized.push(`${key}=${parts.join('\\n')}`);
      continue;
    }
    normalized.push(line);
  }

  const parsed = dotenv.parse(normalized.join('\n'));
  for (const [key, value] of Object.entries(parsed)) {
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

loadPropertiesFile(process.env.CONFIG_PATH || path.join(process.cwd(), 'config', 'agent.properties'));

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required config property: ${name}`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT) || 3000,

  oktaOrgUrl: required('OKTA_ORG_URL'),
  loginAuthServerId: process.env.OKTA_LOGIN_AUTH_SERVER_ID || 'default',

  agentClientId: required('AGENT_CLIENT_ID'),
  agentKeyId: required('AGENT_KEY_ID'),
  agentRedirectUri: required('AGENT_REDIRECT_URI'),
  agentPrivateKeyPem: required('AGENT_PRIVATE_KEY_PEM').replace(/\\n/g, '\n'),
  // RFC 8707 resource indicator for the login step — becomes the `aud` claim
  // of the user's access_token, which the ID-JAG request later relies on.
  loginResource: required('LOGIN_RESOURCE'),

  resourceAuthServerId: required('RESOURCE_AUTH_SERVER_ID'),
  resourceAppTokenEndpoint: required('RESOURCE_APP_TOKEN_ENDPOINT'),
  resourceAppClientId: required('RESOURCE_APP_CLIENT_ID'),
  resourceAppClientSecret: required('RESOURCE_APP_CLIENT_SECRET'),
  resourceApiBaseUrl: required('RESOURCE_API_BASE_URL'),

  // --- M2M login (alternate login flow: no human user, client_credentials) ---
  resourceM2mClientId: required('RESOURCE_M2M_APP_CLIENT_ID'),
  resourceM2mClientSecret: required('RESOURCE_M2M_CLIENT_SECRET'),

  xaaScope: process.env.XAA_SCOPE || 'openid',

  // --- Second Agent (chained XAA hop): User -> Agent 1 -> Agent 2 -> Resource ---
  // Optional — only needed for the "Test Chained XAA" flow in /debug. Agent 2
  // authenticates itself with its own private_key_jwt (a separate Okta app,
  // separate keypair from the first Agent) and takes Agent 1's resource
  // access_token as the subject_token for a further ID-JAG exchange.
  secondAgentClientId: process.env.SECOND_AGENT_CLIENT_ID,
  secondAgentKeyId: process.env.SECOND_AGENT_KEY_ID,
  secondAgentPrivateKeyPem: process.env.SECOND_AGENT_PRIVATE_KEY_PEM?.replace(/\\n/g, '\n'),
  secondResourceAuthServerId: process.env.SECOND_RESOURCE_AUTH_SERVER_ID,
  secondResourceAppTokenEndpoint: process.env.SECOND_RESOURCE_APP_TOKEN_ENDPOINT,
  secondXaaScope: process.env.SECOND_XAA_SCOPE || 'openid',
  // RFC 8707 resource indicator naming Agent 2 as the intended recipient of
  // the ID-JAG requested in the first hop — must match the Audience/resource
  // URL configured on Agent 2's Machine access tab in Okta, or the delegation
  // policy check rejects the subject_token with "no delegation policy
  // authorizes this token" even once a caller link exists.
  secondAgentResourceUrl: process.env.SECOND_AGENT_RESOURCE_URL,

  // --- Third hop target: the actual downstream resource Agent 2 calls after
  // receiving Agent 1's hand-off token (hop B) — a distinct auth server from
  // both Agent 1's and Agent 2's own, matching the reference implementation's
  // separate "Finance MCP" resource server behind the Finance Agent.
  thirdResourceAuthServerId: process.env.THIRD_RESOURCE_AUTH_SERVER_ID,
  thirdResourceAppTokenEndpoint: process.env.THIRD_RESOURCE_APP_TOKEN_ENDPOINT,
  thirdXaaScope: process.env.THIRD_XAA_SCOPE || 'openid',

  sessionSecret: required('SESSION_SECRET'),
  killswitchWebhookUrl: required('KILLSWITCH_WEBHOOK_URL'),
  killswitchWebhookResetUrl: required('KILLSWITCH_WEBHOOK_RESET_URL'),
  adminTriggerSecret: required('ADMIN_TRIGGER_SECRET'),
};
