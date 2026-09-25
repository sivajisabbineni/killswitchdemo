import Anthropic from '@anthropic-ai/sdk';
import { config } from './config';
import { listAllowedActions } from './policy';

export type ChatCommand =
  | 'test-xaa'
  | 'test-chained-xaa'
  | 'toggle-token'
  | 'toggle-chained-actions'
  | 'switch-resource-login'
  | 'switch-agent-login'
  | 'switch-m2m-login'
  | 'logout'
  | 'run-action'
  | 'reply';

export interface ChatContext {
  loggedIn: boolean;
  loginFlow?: 'resource' | 'agent' | 'm2m';
  subjectTokenType: 'access_token' | 'id_token';
  chainedActionsEnabled: boolean;
  chainedXaaConfigured: boolean;
}

export interface ChatDecision {
  command: ChatCommand;
  action?: string;
  params?: Record<string, unknown>;
  reply?: string;
}

const client = config.anthropicApiKey
  ? new Anthropic({ apiKey: config.anthropicApiKey, baseURL: config.anthropicBaseUrl })
  : null;

export function isChatAssistantConfigured(): boolean {
  return client !== null;
}

const DISPATCH_TOOL: Anthropic.Tool = {
  name: 'dispatch',
  description: 'Record what the user wants the app to do next.',
  input_schema: {
    type: 'object',
    properties: {
      command: {
        type: 'string',
        enum: [
          'test-xaa',
          'test-chained-xaa',
          'toggle-token',
          'toggle-chained-actions',
          'switch-resource-login',
          'switch-agent-login',
          'switch-m2m-login',
          'logout',
          'run-action',
          'reply',
        ],
      },
      action: {
        type: 'string',
        description: 'Required when command is "run-action" — the exact allowed action name (e.g. "resource.get"), or "resource.delete_all" for a deliberately-disallowed/rogue test.',
      },
      params: {
        type: 'object',
        description: 'Optional params object for "run-action", e.g. {"id":"42"}.',
      },
      reply: {
        type: 'string',
        description: 'A short, friendly one-line message to show the user. Required when command is "reply"; optional (as a confirmation) otherwise.',
      },
    },
    required: ['command'],
  },
};

/**
 * Sends the raw chat message to Claude with the app's command/action catalog
 * as context and forces a single structured "dispatch" tool call back, so a
 * typed phrase like "initialize the XAA flow" resolves to a real command
 * instead of relying on hand-written regexes. The server only classifies —
 * the client still executes via the same session-authenticated endpoints
 * (/agent/act, /xaa/login, etc.) it always did, so the killswitch policy
 * allow-list in policy.ts remains the actual enforcement point.
 */
export async function interpretChatMessage(message: string, ctx: ChatContext): Promise<ChatDecision> {
  if (!client) {
    throw new Error('chat assistant not configured — set ANTHROPIC_API_KEY');
  }

  const actions = listAllowedActions()
    .map((a) => `- ${a.name}(${JSON.stringify(a.defaultParams || {})}): ${a.description}`)
    .join('\n');

  const system = `You are the assistant embedded in "Marketing Cloud", a small Okta Cross App Access (XAA) test-harness app. The user chats with you instead of clicking buttons. Read their message and call the "dispatch" tool exactly once with the single best command.

Current state: logged in = ${ctx.loggedIn}, login flow = ${ctx.loginFlow ?? 'none'}, subject token type = ${ctx.subjectTokenType}, chained actions enabled = ${ctx.chainedActionsEnabled}, chained XAA configured = ${ctx.chainedXaaConfigured}.

marketing.list and marketing.get request a read-only XAA scope (api:access:read); marketing.update and marketing.create request a write scope (api:access:write) — access is enforced by Okta based on those scopes, not by anything in this app.

Commands:
- test-xaa: run the single-hop XAA login exchange (ID-JAG + resource token).
- test-chained-xaa: run the chained flow (Agent 1 → Agent 2 → Resource). Only use if chained XAA is configured.
- toggle-token: flip which token (access_token vs id_token) is sent as the subject_token. Use whenever the user names a token type, even if it's already active — say so in the reply instead.
- toggle-chained-actions: flip whether agent actions authorize via chained XAA (i.e. "enable/disable chained actions").
- switch-resource-login / switch-agent-login / switch-m2m-login: switch which login flow to test.
- logout: log out.
- run-action: call one of the allowed resource actions below via "action" (exact name) and "params". Also use this with action "resource.delete_all" when the user wants to test a disallowed/rogue action (that action is intentionally NOT in the allow-list, so the app's killswitch will trip).
- reply: only when nothing above applies — general questions, chit-chat, or a clarifying question. Put the message in "reply".

Allowed resource actions:
${actions}

Always set a short, friendly "reply" confirming what you're doing, even alongside another command.`;

  const response = await client.messages.create({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 300,
    system,
    messages: [{ role: 'user', content: message }],
    tools: [DISPATCH_TOOL],
    tool_choice: { type: 'tool', name: 'dispatch' },
  });

  const toolUse = response.content.find((block) => block.type === 'tool_use');
  if (!toolUse || toolUse.type !== 'tool_use') {
    throw new Error('assistant did not return a dispatch decision');
  }
  return toolUse.input as ChatDecision;
}
