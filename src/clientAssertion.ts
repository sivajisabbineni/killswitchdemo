import { SignJWT, importPKCS8 } from 'jose';
import crypto from 'node:crypto';
import { config } from './config';

/**
 * Builds a private_key_jwt client_assertion for the Agent's Okta client,
 * signed with AGENT_PRIVATE_KEY_PEM. The Agent authenticates as itself with
 * this same key at both hops of the XAA exchange — the ID-JAG request (typ
 * "oauth-id-jag+jwt") and redeeming the ID-JAG at the resource app's own
 * token endpoint (typ "jwt") — only the audience and typ differ per call.
 */
export async function buildClientAssertion(audience: string, typ: string): Promise<string> {
  const key = await importPKCS8(config.agentPrivateKeyPem, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ, kid: config.agentKeyId })
    .setIssuer(config.agentClientId)
    .setSubject(config.agentClientId)
    .setAudience(audience)
    .setJti(crypto.randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}
