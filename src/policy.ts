import type { ResourceAction } from './resourceClient';

/**
 * Allow-list of actions the agent is permitted to take against the resource
 * app. Anything not listed here is treated as a rogue/out-of-scope action.
 * These point at httpbingo.org (RESOURCE_API_BASE_URL default) so the call
 * just echoes back the Authorization header — enough to confirm the XAA
 * token was sent, without needing a real backend. Swap in your actual
 * resource app's API once you have one.
 */
const ALLOWED_ACTIONS: Record<string, ResourceAction> = {
  'resource.get': { method: 'GET', path: '/get' },
  'resource.item': { method: 'GET', path: '/anything/:id' },
  'resource.headers': { method: 'GET', path: '/headers' },
  'resource.ip': { method: 'GET', path: '/ip' },
  'resource.uuid': { method: 'GET', path: '/uuid' },
  'resource.status': { method: 'GET', path: '/status/:code' },
};

export function evaluate(action: string): ResourceAction | null {
  return ALLOWED_ACTIONS[action] ?? null;
}

export function listAllowedActions(): Array<{ name: string; method: string; path: string }> {
  return Object.entries(ALLOWED_ACTIONS).map(([name, { method, path }]) => ({ name, method, path }));
}
