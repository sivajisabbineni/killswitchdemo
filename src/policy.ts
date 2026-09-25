import type { ResourceAction } from './resourceClient';

export interface AllowedAction extends ResourceAction {
  description: string;
  // 'local' actions are served in-process (e.g. the marketing data store)
  // instead of calling out to the resource API — see localActions.ts.
  kind?: 'local';
  // Overrides the XAA scope requested for this action's ID-JAG/resource-token
  // exchange (see xaa.ts) instead of the flow-wide XAA_SCOPE/THIRD_XAA_SCOPE
  // default — e.g. requesting a narrower read scope for reads and a write
  // scope only for the action that actually mutates data. Must be a scope
  // registered on the resource app's Okta auth server, or the token exchange
  // is rejected.
  scope?: string;
}

/**
 * Allow-list of actions the agent is permitted to take against the resource
 * app. Anything not listed here is treated as a rogue/out-of-scope action.
 * These point at httpbingo.org (RESOURCE_API_BASE_URL default) so the call
 * just echoes back the Authorization header — enough to confirm the XAA
 * token was sent, without needing a real backend. Swap in your actual
 * resource app's API once you have one.
 *
 * defaultParams let a tool work with a single click (no typed params
 * required) while still being overridable via the chat input.
 */
const ALLOWED_ACTIONS: Record<string, AllowedAction> = {
  'resource.get': {
    method: 'GET',
    path: '/get',
    description: 'Echo back the full request — headers, origin IP, URL.',
  },
  'resource.headers': {
    method: 'GET',
    path: '/headers',
    description: 'Show just the request headers the agent sent.',
  },
  'resource.ip': {
    method: 'GET',
    path: '/ip',
    description: "Show the resource server's view of the agent's IP.",
  },
  'resource.uuid': {
    method: 'GET',
    path: '/uuid',
    description: 'Generate a random UUID — no input needed.',
  },
  'resource.user_agent': {
    method: 'GET',
    path: '/user-agent',
    description: 'Show the User-Agent header the agent sent.',
  },
  'resource.item': {
    method: 'GET',
    path: '/anything/:id',
    description: 'Fetch an item by ID — any ID works, it just echoes back.',
    defaultParams: { id: 'item-123' },
  },
  'resource.delay': {
    method: 'GET',
    path: '/delay/:seconds',
    description: 'Simulate a slow call — waits N seconds (max 10) before responding.',
    defaultParams: { seconds: '2' },
  },
  'resource.base64': {
    method: 'GET',
    path: '/base64/:value',
    description: 'Decode a base64 string server-side.',
    defaultParams: { value: 'aHR0cGJpbmdv' },
  },

  // --- Marketing data — served in-process by marketingStore.ts via
  // localActions.ts, not the resource API above. Read vs. write access is
  // enforced by Okta via the scope requested below (api:access:read vs.
  // api:access:write), not by any in-app role check.
  'marketing.list': {
    method: 'GET',
    path: '/marketing/campaigns',
    kind: 'local',
    scope: 'api:access:read',
    description: 'List all marketing campaigns.',
  },
  'marketing.get': {
    method: 'GET',
    path: '/marketing/campaigns/:id',
    kind: 'local',
    scope: 'api:access:read',
    description: 'Get one marketing campaign by ID.',
    defaultParams: { id: 'camp-1' },
  },
  'marketing.update': {
    method: 'PATCH',
    path: '/marketing/campaigns/:id',
    kind: 'local',
    scope: 'api:access:write',
    description: 'Update a campaign’s budget and/or status.',
    defaultParams: { id: 'camp-1', budget: '15000' },
  },
  'marketing.create': {
    method: 'POST',
    path: '/marketing/campaigns',
    kind: 'local',
    scope: 'api:access:write',
    description: 'Create a new marketing campaign.',
    defaultParams: { name: 'New Campaign', budget: '1000' },
  },
};

export function evaluate(action: string): AllowedAction | null {
  return ALLOWED_ACTIONS[action] ?? null;
}

export interface AllowedActionInfo extends AllowedAction {
  name: string;
}

export function listAllowedActions(): AllowedActionInfo[] {
  return Object.entries(ALLOWED_ACTIONS).map(([name, action]) => ({ name, ...action }));
}
