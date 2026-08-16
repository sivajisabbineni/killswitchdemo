import crypto from 'node:crypto';
import { config } from './config';

/**
 * Derives the public key/JWK that corresponds to AGENT_PRIVATE_KEY_PEM, so it
 * can be compared against whatever is actually registered in Okta's JWKS for
 * AGENT_KEY_ID. A signature-invalid error on the client_assertion means these
 * two don't match — either the registered key was rotated, or AGENT_KEY_ID
 * points at a different key than the one this PEM belongs to.
 */
export function derivePublicJwk(): Record<string, unknown> {
  const privateKey = crypto.createPrivateKey({ key: config.agentPrivateKeyPem, format: 'pem' });
  const publicKey = crypto.createPublicKey(privateKey);
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  return { ...jwk, kid: config.agentKeyId, use: 'sig', alg: 'RS256' };
}
