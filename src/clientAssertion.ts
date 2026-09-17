import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'node:crypto';
import { config } from './config';

export interface AgentIdentity {
  clientId: string;
  keyId: string;
  privateKeyPem: string;
}

const FIRST_AGENT_IDENTITY: AgentIdentity = {
  clientId: config.agentClientId,
  keyId: config.agentKeyId,
  privateKeyPem: config.agentPrivateKeyPem,
};

/**
 * Builds a private_key_jwt client_assertion for an Agent's Okta client. The
 * Agent authenticates as itself with this same key at both hops of the XAA
 * exchange — the ID-JAG request (typ "oauth-id-jag+jwt") and redeeming the
 * ID-JAG at the resource app's own token endpoint (typ "jwt") — only the
 * audience and typ differ per call.
 *
 * Defaults to the first Agent's identity; pass a different `identity` (e.g.
 * the second Agent in a chained XAA flow) to sign as that Agent instead.
 */
export async function buildClientAssertion(
  audience: string,
  typ: string,
  identity: AgentIdentity = FIRST_AGENT_IDENTITY,
): Promise<string> {
  const key = await importPKCS8(identity.privateKeyPem, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ, kid: identity.keyId })
    .setIssuer(identity.clientId)
    .setSubject(identity.clientId)
    .setAudience(audience)
    .setJti(crypto.randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}
