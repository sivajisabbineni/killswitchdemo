import { decodeJwt } from 'jose';
import { getCalls, getTokens, type CallLogEntry, type TokenEntry } from './debugLog';
import { listAllowedActions } from './policy';
import type { StoppedState } from './agentState';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

interface DebugPageOptions {
  adminKey: string;
  loggedIn: boolean;
  loginFlow?: 'resource' | 'agent' | 'm2m';
  error?: string;
  stopped: StoppedState | null;
  chainedXaaConfigured: boolean;
  chatAssistantConfigured: boolean;
  userIdentity?: string;
}

type StepStatus = 'pending' | 'success' | 'error';

interface StepDef {
  n: number;
  labels: string[];
  title: string;
  subtitle: string;
  hint: string;
  // Keyed by which of `labels` actually fired, since the login step can
  // produce a different token pair (access + ID token) per flow.
  tokenLabelsByCallLabel?: Record<string, string[]>;
}

const STEPS: StepDef[] = [
  {
    n: 1,
    labels: ['login:token-exchange', 'agentlogin:token-exchange', 'm2mlogin:token-exchange'],
    title: 'ID & Access Tokens',
    subtitle: 'User → Okta (OIDC authorization code)',
    hint: 'Standard OIDC login — the human user authenticates, via either the Resource App (client_secret_basic) or the Agent app (private_key_jwt), and gets back a user access_token and ID token. The M2M login skips the human user entirely (client_credentials) and gets back only an access_token.',
    tokenLabelsByCallLabel: {
      'login:token-exchange': ['user access_token (login)', 'ID token (login)'],
      'agentlogin:token-exchange': ['user access_token (agent login)', 'ID token (agent login)'],
      'm2mlogin:token-exchange': ['access_token (M2M login)'],
    },
  },
  {
    n: 2,
    labels: ['xaa:id-jag-request'],
    title: 'Get ID-JAG',
    subtitle: 'Agent → Okta (org token endpoint)',
    hint: 'RFC 8693 token-exchange — the Agent trades the user access_token for an ID-JAG, authenticating itself with a private_key_jwt client_assertion.',
    tokenLabelsByCallLabel: { 'xaa:id-jag-request': ['ID-JAG'] },
  },
  {
    n: 3,
    labels: ['xaa:resource-token-exchange'],
    title: 'Resource Access Token',
    subtitle: 'Agent → Resource App token endpoint',
    hint: 'RFC 7523 jwt-bearer exchange — the Agent redeems the ID-JAG at the resource app\'s own token endpoint for a resource-scoped access_token.',
    tokenLabelsByCallLabel: { 'xaa:resource-token-exchange': ['resource access_token'] },
  },
  {
    n: 4,
    labels: ['resource:api-call'],
    title: 'Agent Action',
    subtitle: 'Agent → Resource API',
    hint: 'The Agent calls the resource API using the resource access_token from step 3 (only if the requested action is on the policy allow-list) — single-hop XAA, no chaining to a second Agent.',
  },
  {
    n: 5,
    labels: ['xaa2:id-jag-request'],
    title: 'Get ID-JAG (Agent 1 → Agent 2)',
    subtitle: 'Agent 1 → Okta (org token endpoint)',
    hint: "Chained XAA, hop A — Agent 1 requests an ID-JAG whose audience is Agent 2's own custom authorization server (not the single-hop resource app), naming Agent 2 as the `resource` this ID-JAG is destined for. Still signed with Agent 1's own private_key_jwt.",
    tokenLabelsByCallLabel: { 'xaa2:id-jag-request': ['ID-JAG (Agent 1 → Agent 2)'] },
  },
  {
    n: 6,
    labels: ['xaa2:resource-token-exchange'],
    title: 'Agent 1 → Agent 2 Access Token',
    subtitle: 'Agent 1 → Agent 2 token endpoint',
    hint: "RFC 7523 jwt-bearer exchange — Agent 1 redeems its ID-JAG at Agent 2's own token endpoint, getting an access_token that authorizes Agent 1 to invoke Agent 2.",
    tokenLabelsByCallLabel: { 'xaa2:resource-token-exchange': ['Agent 1 → Agent 2 access_token'] },
  },
  {
    n: 7,
    labels: ['xaa3:id-jag-request'],
    title: 'Get ID-JAG (Agent 2)',
    subtitle: 'Agent 2 → Okta (org token endpoint)',
    hint: "Chained XAA, hop B — Agent 2 takes the access_token from step 6 as its own subject_token and requests a further ID-JAG targeting the downstream resource's auth server, authenticating with its own private_key_jwt client_assertion.",
    tokenLabelsByCallLabel: { 'xaa3:id-jag-request': ['ID-JAG (Agent 2)'] },
  },
  {
    n: 8,
    labels: ['xaa3:resource-token-exchange'],
    title: 'Resource Access Token (Agent 2)',
    subtitle: 'Agent 2 → Resource App token endpoint',
    hint: "RFC 7523 jwt-bearer exchange — Agent 2 redeems its ID-JAG at the resource app's own token endpoint for the final resource-scoped access_token, completing User → Agent 1 → Agent 2 → Resource.",
    tokenLabelsByCallLabel: { 'xaa3:resource-token-exchange': ['resource access_token (Agent 2)'] },
  },
  {
    n: 9,
    labels: ['resource:api-call-chained'],
    title: 'Agent Action (Chained)',
    subtitle: 'Agent 2 → Resource API',
    hint: 'The Agent calls the resource API using the resource access_token from step 8 (only if the requested action is on the policy allow-list) — the final hop of User → Agent 1 → Agent 2 → Resource.',
  },
];

const STEP_BY_LABEL = new Map(STEPS.flatMap((s) => s.labels.map((label) => [label, s] as const)));

// Steps that are genuinely a token exchange with Okta (login + ID-JAG +
// resource-token redemption, both single-hop and chained). T4/T9 are
// deliberately excluded — those are the Agent Action / campaign-data calls,
// not Okta calls, so they must not count toward this timer.
const OKTA_EXCHANGE_STEPS = [1, 2, 3, 5, 6, 7, 8];

/**
 * Sums the network duration of the latest call for each Okta-exchange step
 * that has actually run. Only tracedFetch-recorded calls carry durationMs —
 * local marketing.* actions (T4/T9 when kind: 'local') never set it, so they
 * can never contribute even if a step number were added here by mistake.
 */
function computeOktaExchangeMs(): number | null {
  let total = 0;
  let any = false;
  for (const step of STEPS) {
    if (!OKTA_EXCHANGE_STEPS.includes(step.n)) continue;
    const call = getLatestCallForStep(step);
    if (call?.durationMs !== undefined) {
      total += call.durationMs;
      any = true;
    }
  }
  return any ? total : null;
}

function formatOktaTimer(ms: number | null): string {
  if (ms === null) return '⏱ Okta exchange: —';
  return `⏱ Okta exchange: ${(ms / 1000).toFixed(2)}s`;
}

/**
 * Call + token labels belonging to T1 (login) — kept out of any "clear the
 * timeline for a fresh run" wipe, since the login step reflects the current
 * session and should stay visible even when the run being cleared for
 * doesn't touch login itself (e.g. re-running "Test XAA login").
 */
export const LOGIN_STEP_LABELS: string[] = [
  ...STEPS[0].labels,
  ...Object.values(STEPS[0].tokenLabelsByCallLabel ?? {}).flat(),
];

function getLatestCallForStep(step: StepDef): CallLogEntry | undefined {
  return getCalls().find((c) => step.labels.includes(c.label));
}

const EXTRA_LABEL_TITLES: Record<string, string> = {
  'killswitch:webhook': 'Killswitch webhook (deactivation)',
  'killswitch:reset-webhook': 'Activation webhook (reset)',
};

const PARAM_GLOSSARY: Record<string, string> = {
  grant_type: 'The OAuth grant type being used for this request.',
  code: 'The authorization code returned by Okta after the user logs in.',
  client_id: 'The OAuth client identifier for the app making this request.',
  redirect_uri: 'Must match the redirect URI registered for this app in Okta.',
  resource: "RFC 8707 resource indicator — the resource server this token is intended for.",
  requested_token_type: 'The type of token being requested from the token endpoint.',
  subject_token_type: 'The type of the token being presented as the subject of a token-exchange request.',
  subject_token: "The token being exchanged — here, the user's access_token.",
  client_assertion_type: 'Indicates the client authenticates via a signed JWT (private_key_jwt) rather than a client secret.',
  client_assertion: "A JWT signed with the Agent's private key, proving its identity to the token endpoint.",
  audience: 'The intended recipient of the requested token.',
  scope: 'The requested scope(s) for the issued token.',
  assertion: 'The ID-JAG being redeemed for a resource-scoped access_token (RFC 7523 jwt-bearer grant).',
};

function statusOf(call: CallLogEntry | undefined): StepStatus {
  if (!call) return 'pending';
  if (call.error) return 'error';
  if (call.status !== undefined && call.status >= 400) return 'error';
  return 'success';
}

function collapsible(label: string, contentHtml: string, openByDefault = false): string {
  return `<details class="mini"${openByDefault ? ' open' : ''}><summary>${escapeHtml(label)}</summary>${contentHtml}</details>`;
}

function buildHeadersHtml(headers?: Record<string, string>): string {
  if (!headers || Object.keys(headers).length === 0) return '';
  const lines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  return collapsible('HEADERS', `<pre class="code-block">${escapeHtml(lines)}</pre>`);
}

function formatBody(body?: string): string {
  if (!body) return '<p class="muted" style="margin:8px 0;">(empty body)</p>';
  try {
    return `<pre class="code-dark">${escapeHtml(JSON.stringify(JSON.parse(body), null, 2))}</pre>`;
  } catch {
    // form-urlencoded bodies: one decoded key=value per line (URLSearchParams
    // decodes %XX escapes automatically), matching the reference UI's BODY block.
    if (body.includes('=')) {
      try {
        const params = new URLSearchParams(body);
        const formatted = Array.from(params.entries())
          .map(([k, v]) => `${k}=${v}`)
          .join('\n');
        return `<pre class="code-dark">${escapeHtml(formatted)}</pre>`;
      } catch {
        return `<pre class="code-dark">${escapeHtml(body)}</pre>`;
      }
    }
    return `<pre class="code-dark">${escapeHtml(body)}</pre>`;
  }
}

function buildParamRefHtml(body?: string): string {
  if (!body || !body.includes('=')) return '';
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(body);
  } catch {
    return '';
  }
  const known = Array.from(params.keys()).filter((k) => PARAM_GLOSSARY[k]);
  if (known.length === 0) return '';
  const items = known.map((k) => `<li><code>${escapeHtml(k)}</code> — ${escapeHtml(PARAM_GLOSSARY[k])}</li>`).join('');
  return collapsible(`PARAMETER REFERENCE (${known.length})`, `<ul class="param-ref">${items}</ul>`);
}

function buildCurl(c: CallLogEntry): string {
  let cmd = `curl -X ${c.method} '${c.url}'`;
  if (c.requestHeaders) {
    for (const [k, v] of Object.entries(c.requestHeaders)) {
      if (k.toLowerCase() === 'content-length') continue;
      cmd += ` \\\n  -H '${k}: ${v}'`;
    }
  }
  if (c.requestBody) {
    cmd += ` \\\n  -d '${c.requestBody.replace(/'/g, "'\\''")}'`;
  }
  return cmd;
}

function safeDecodeBearer(headers?: Record<string, string>): Record<string, unknown> | undefined {
  const auth = headers?.Authorization || headers?.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return undefined;
  try {
    return decodeJwt(auth.slice('Bearer '.length));
  } catch {
    return undefined;
  }
}

function buildStepCard(step: StepDef): string {
  const call = getLatestCallForStep(step);
  const status = statusOf(call);
  const statusIcon = status === 'success' ? '✓' : status === 'error' ? '✕' : '○';

  if (!call) {
    return `<div class="step-card">
      <button type="button" class="step-card-header status-${status}" data-step-toggle="${step.n}" data-expanded="false">
        <span class="status-icon">${statusIcon}</span>
        <div>
          <div class="step-card-title">T${step.n} — ${escapeHtml(step.title)}</div>
          <div class="step-card-subtitle">${escapeHtml(step.subtitle)}</div>
        </div>
        <span class="step-card-chevron">▾</span>
      </button>
      <div class="step-card-body" data-step-body="${step.n}">
        <p class="muted" style="margin:0;">Not called yet. ${escapeHtml(step.hint)}</p>
      </div>
    </div>`;
  }

  const requestTab = `
    <div class="req-line"><span class="method-pill">${escapeHtml(call.method)}</span><span class="req-url">${escapeHtml(call.url)}</span></div>
    ${buildHeadersHtml(call.requestHeaders)}
    <div class="field-label">BODY</div>
    ${formatBody(call.requestBody)}
    ${buildParamRefHtml(call.requestBody)}`;

  const statusBadge =
    call.status !== undefined
      ? `<span class="badge ${call.status < 400 ? 'badge-ok' : 'badge-fail'}">${call.status}</span>`
      : `<span class="badge badge-fail">network error</span>`;
  const responseTab = `
    <div class="req-line"><span class="method-pill ${call.status !== undefined && call.status < 400 ? 'pill-ok' : 'pill-fail'}">${call.status ?? 'ERR'}</span>${statusBadge}</div>
    ${buildHeadersHtml(call.responseHeaders)}
    ${call.responseBody ? `<div class="field-label">BODY</div>${formatBody(call.responseBody)}` : ''}
    ${call.error ? `<div class="banner banner-error" style="margin-top:8px;">${escapeHtml(call.error)}</div>` : ''}`;

  // Tokens are looked up by label with no direct link to a specific call, so
  // only trust a match when this call actually succeeded — otherwise a failed
  // retry would still show the token from an earlier successful attempt.
  const tokenLabels = status === 'success' ? step.tokenLabelsByCallLabel?.[call.label] ?? [] : [];
  const tokenEntries = tokenLabels
    .map((label) => getTokens().find((t) => t.label === label))
    .filter((t): t is TokenEntry => t !== undefined);
  const bearerClaims = tokenEntries.length === 0 && status === 'success' ? safeDecodeBearer(call.requestHeaders) : undefined;
  let tokenTab: string;
  if (tokenEntries.length > 0) {
    tokenTab = tokenEntries
      .map(
        (t) => `
      <div class="field-label">${escapeHtml(t.label.toUpperCase())}</div>
      <pre class="code-dark">${escapeHtml(t.token)}</pre>
      ${t.claims ? `<pre class="code-dark" style="margin-top:6px;">${escapeHtml(JSON.stringify(t.claims, null, 2))}</pre>` : ''}`,
      )
      .join('');
  } else if (bearerClaims) {
    tokenTab = `
      <p class="muted" style="margin-top:0;">This step doesn't issue a new token — it uses the resource access_token from the preceding step.</p>
      <div class="field-label">DECODED CLAIMS (from Authorization header)</div>
      <pre class="code-dark">${escapeHtml(JSON.stringify(bearerClaims, null, 2))}</pre>`;
  } else if (status === 'error') {
    tokenTab = `<p class="muted" style="margin:0;">This call failed — no token was issued. See the Response tab.</p>`;
  } else {
    tokenTab = `<p class="muted" style="margin:0;">No token associated with this call.</p>`;
  }

  const codeTab = `<pre class="code-dark">${escapeHtml(buildCurl(call))}</pre>`;

  return `<div class="step-card">
    <button type="button" class="step-card-header status-${status}" data-step-toggle="${step.n}" data-expanded="false">
      <span class="status-icon">${statusIcon}</span>
      <div>
        <div class="step-card-title">T${step.n} — ${escapeHtml(step.title)}</div>
        <div class="step-card-subtitle">${escapeHtml(step.subtitle)}</div>
      </div>
      <div class="step-card-timestamp">${escapeHtml(call.timestamp)}</div>
      <span class="step-card-chevron">▾</span>
    </button>
    <div class="step-card-body" data-step-body="${step.n}">
      <div class="tabs">
        <button class="tab-btn active" data-tab="request">Request</button>
        <button class="tab-btn" data-tab="response">Response</button>
        <button class="tab-btn" data-tab="token">Token</button>
        <button class="tab-btn" data-tab="code">Code</button>
      </div>
      <div class="tab-panels">
        <div class="tab-panel active" data-panel="request">${requestTab}</div>
        <div class="tab-panel" data-panel="response">${responseTab}</div>
        <div class="tab-panel" data-panel="token">${tokenTab}</div>
        <div class="tab-panel" data-panel="code">${codeTab}</div>
      </div>
    </div>
  </div>`;
}

function labelTitle(label: string): string {
  return STEP_BY_LABEL.get(label)?.title ?? EXTRA_LABEL_TITLES[label] ?? label;
}

// Marketing (local) calls all share the generic "Agent Action" step title —
// too vague for the chat feed, so name the bubble after the actual campaign
// operation instead. Distinguished by HTTP method (localActions.ts uses GET
// for list/get, POST for create, PATCH for update), not by label, since
// list/get/create/update all share the same T4/T9 step.
function bubbleTitle(c: CallLogEntry): string {
  if (c.url.startsWith('local://marketing')) {
    if (c.method === 'PATCH') return 'Campaign Update';
    if (c.method === 'POST') return 'Campaign Create';
    return 'Campaign Read';
  }
  return labelTitle(c.label);
}

function tryPrettyJson(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function truncateToken(token: string, max = 44): string {
  return token.length > max ? `${token.slice(0, max)}…` : token;
}

/**
 * Chat bubbles show the real substance of a call, not a paraphrase: the
 * issued token(s) for login/XAA/ID-JAG steps (which all have
 * tokenLabelsByCallLabel), or the raw JSON output for tool calls (T4/T9 —
 * resource/marketing actions, which don't). On failure, show whatever
 * detail is available instead, since there's no token/output to show.
 */
function buildBubbleContent(c: CallLogEntry, step: StepDef | undefined, ok: boolean): string {
  if (!ok) {
    const detail = c.error ?? (c.responseBody ? tryPrettyJson(c.responseBody) : undefined);
    return detail ? `<pre class="code-dark" style="margin-top:6px; white-space:pre-wrap;">${escapeHtml(detail)}</pre>` : '';
  }
  const tokenLabels = step?.tokenLabelsByCallLabel?.[c.label];
  if (tokenLabels && tokenLabels.length > 0) {
    const tokenEntries = tokenLabels
      .map((label) => getTokens().find((t) => t.label === label))
      .filter((t): t is TokenEntry => t !== undefined);
    if (tokenEntries.length > 0) {
      return tokenEntries
        .map(
          (t) => `
      <div class="field-label" style="margin-top:8px;">${escapeHtml(t.label.toUpperCase())}</div>
      <pre class="code-dark" style="margin:4px 0 0;">${escapeHtml(truncateToken(t.token))}</pre>`,
        )
        .join('');
    }
  }
  if (!c.responseBody) return '';
  return `<pre class="code-dark" style="margin-top:6px;">${escapeHtml(tryPrettyJson(c.responseBody))}</pre>`;
}

function buildFeedHtml(): string {
  const greeting = `<div class="bubble bubble-assistant">Hi! I'm the Marketing Cloud test harness. Use the actions below to run allowed calls, test the XAA login, or trigger the killswitch — every hop shows up in the timeline on the right.</div>`;
  // T1 (login) is deliberately kept in the underlying call log across every
  // action (via clearHistoryExceptLabels(LOGIN_STEP_LABELS) in server.ts) so
  // its accordion card stays populated — but that means it would otherwise
  // resurface as a stale bubble in every request's chat feed. Filter it out
  // here only; the accordion (buildStepCard/getLatestCallForStep) still
  // reads the unfiltered call log and reflects T1's true state regardless.
  const calls = getCalls()
    .filter((c) => !LOGIN_STEP_LABELS.includes(c.label))
    .slice()
    .reverse();
  const bubbles = calls
    .map((c) => {
      const ok = !c.error && (c.status === undefined || c.status < 400);
      const badge = c.error ? 'network error' : c.status !== undefined ? String(c.status) : '';
      const step = STEP_BY_LABEL.get(c.label);
      const jumpAttr = step ? ` data-jump-step="${step.n}"` : '';
      const content = buildBubbleContent(c, step, ok);
      return `<div class="bubble bubble-assistant ${ok ? 'bubble-ok' : 'bubble-fail'}"${jumpAttr}>
        <strong>${escapeHtml(bubbleTitle(c))}</strong> <span class="badge ${ok ? 'badge-ok' : 'badge-fail'}">${escapeHtml(badge)}</span>
        ${content}
        ${step ? `<span class="muted"> — click to view T${step.n}</span>` : ''}
        <div class="muted timestamp">${escapeHtml(c.timestamp)}</div>
      </div>`;
    })
    .join('');
  return greeting + bubbles;
}

export interface DebugFragments {
  stepStatuses: Record<number, StepStatus>;
  stepCards: Record<number, string>;
  feedHtml: string;
  stopped: StoppedState | null;
  oktaExchangeMs: number | null;
}

export function renderDebugFragments(stopped: StoppedState | null): DebugFragments {
  const stepStatuses: Record<number, StepStatus> = {};
  const stepCards: Record<number, string> = {};
  for (const step of STEPS) {
    stepStatuses[step.n] = statusOf(getLatestCallForStep(step));
    stepCards[step.n] = buildStepCard(step);
  }
  return { stepStatuses, stepCards, feedHtml: buildFeedHtml(), stopped, oktaExchangeMs: computeOktaExchangeMs() };
}

export function renderDebugPage(opts: DebugPageOptions): string {
  const { stepStatuses, stepCards, feedHtml, oktaExchangeMs } = renderDebugFragments(opts.stopped);

  const errorHtml = opts.error
    ? `<div class="banner banner-error" style="margin:12px;"><strong>Error:</strong> ${escapeHtml(opts.error)}</div>`
    : '';

  const stoppedHtml = `<div id="stoppedBanner" class="banner banner-error" style="margin:12px; ${opts.stopped ? '' : 'display:none;'}">
        <strong>⚠ Agent stopped</strong> at <span id="stoppedAt">${opts.stopped ? escapeHtml(opts.stopped.stoppedAt) : ''}</span> — reason: <code id="stoppedReason">${opts.stopped ? escapeHtml(opts.stopped.reason) : ''}</code>
        <div style="margin-top:8px;"><button id="resetBtn" class="btn btn-secondary">Reset Agent</button></div>
      </div>`;

  const actionPills = listAllowedActions()
    .map(
      (a) =>
        `<button type="button" class="pill" data-action="${escapeHtml(a.name)}" data-default-params="${escapeHtml(JSON.stringify(a.defaultParams || {}))}" title="${escapeHtml(a.description)}">${escapeHtml(a.name)}</button>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Marketing Cloud debug</title>
  <style>
    :root {
      --bg: #eef4fa;
      --card-bg: #ffffff;
      --border: #cfe0f0;
      --text: #1a1f24;
      --muted: #6b7280;
      --accent: #004b93;
      --accent-dark: #00396f;
      --success-bg: #eafaf0;
      --success-border: #34c85a;
      --success-text: #0a7d28;
      --warn-bg: #fff8e6;
      --warn-border: #e5a300;
      --warn-text: #8a5a00;
      --error-bg: #fde7e9;
      --error-border: #e0455a;
      --error-text: #b00020;
      --dark: #001f45;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      min-height: 100vh;
      background: linear-gradient(135deg, #001f45 0%, #004b93 55%, #0064b1 100%);
      color: var(--text);
      line-height: 1.5;
    }
    .app-shell {
      position: relative;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 24px;
      max-width: 1000px;
      margin: 20px auto;
      padding: 0 16px 20px;
    }
    .user-identity {
      position: absolute;
      top: 20px;
      right: 16px;
      font-size: 12.5px;
      font-weight: 600;
      color: #fff;
      background: rgba(255,255,255,0.12);
      padding: 5px 12px;
      border-radius: 999px;
    }
    .chat-panel {
      width: 100%;
      max-width: 720px;
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      overflow: hidden;
      min-height: 780px;
      box-shadow: 0 8px 24px rgba(0,31,69,0.08);
    }
    .chat-header { padding: 20px 22px 14px; border-bottom: 1px solid var(--border); }
    .chat-header h1 { font-size: 19px; margin: 0 0 2px; }
    .chat-header .subtitle { color: var(--muted); font-size: 13px; margin: 0; }
    .flow-tag {
      display: inline-block; margin-top: 8px; margin-right: 6px; font-size: 11.5px; font-weight: 600;
      padding: 3px 10px; border-radius: 999px; background: #eaf2fb; color: #004b93;
    }
    .timer-tag {
      display: inline-block; margin-top: 8px; font-size: 11.5px; font-weight: 600;
      padding: 3px 10px; border-radius: 999px; background: #eafaf0; color: #0a7d28;
      font-family: ui-monospace, monospace;
    }
    .chat-toolbar { padding: 14px 22px; border-bottom: 1px solid var(--border); display: flex; flex-direction: column; gap: 10px; }
    .toolbar-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .toolbar-label {
      font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
      color: var(--muted); margin: 2px 0 0;
    }
    .chat-feed { flex: 1; overflow-y: auto; padding: 20px 22px; display: flex; flex-direction: column; gap: 12px; min-height: 380px; max-height: none; }
    .bubble {
      background: #eef1f5;
      border-radius: 14px;
      padding: 12px 16px;
      font-size: 14px;
      max-width: 100%;
      transition: transform 0.12s ease, box-shadow 0.12s ease;
    }
    .bubble-assistant { align-self: flex-start; }
    .bubble-ok { background: var(--success-bg); }
    .bubble-fail { background: var(--error-bg); }
    .bubble-pending { background: #eceff1; color: var(--muted); }
    .bubble[data-jump-step] { cursor: pointer; }
    .bubble[data-jump-step]:hover { filter: brightness(0.97); transform: translateX(2px); box-shadow: 0 2px 8px rgba(0,31,69,0.08); }
    .chat-suggestions { padding: 12px 22px; border-top: 1px solid var(--border); display: flex; gap: 8px; flex-wrap: wrap; }
    .pill {
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 7px 14px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      cursor: pointer;
      transition: transform 0.12s ease, box-shadow 0.12s ease, background-color 0.12s ease, border-color 0.12s ease;
      box-shadow: 0 1px 2px rgba(0,31,69,0.05);
    }
    .pill:hover { background: #eaf2fb; border-color: var(--accent); transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,31,69,0.12); }
    .pill:active { transform: translateY(0); box-shadow: 0 1px 2px rgba(0,31,69,0.08); }
    .pill.pill-active { background: var(--accent); border-color: var(--accent-dark); color: #fff; }
    .pill.pill-active:hover { background: var(--accent-dark); }
    .pill-danger { border-color: var(--error-border); color: var(--error-text); }
    .pill-danger:hover { background: var(--error-bg); border-color: var(--error-border); }
    .chat-input-row { display: flex; gap: 10px; padding: 16px 22px 20px; border-top: 1px solid var(--border); }
    .chat-input-row input[type="text"] {
      flex: 1; font-size: 15px; padding: 12px 16px; border-radius: 10px;
      transition: border-color 0.12s ease, box-shadow 0.12s ease;
    }
    .chat-input-row input[type="text"]:focus {
      outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,75,147,0.12);
    }
    .chat-input-row .btn-primary { padding: 12px 22px; font-size: 15px; border-radius: 10px; }
    .timeline-panel { width: 100%; max-width: 720px; }
    .accordion { display: flex; flex-direction: column; gap: 10px; }
    .step-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    .step-card-header {
      background: var(--dark); color: #fff; padding: 16px 18px; display: flex; align-items: center; gap: 12px;
      cursor: pointer; font-family: inherit; border: none; width: 100%; text-align: left;
      transition: filter 0.12s ease;
    }
    .step-card-header:hover { filter: brightness(1.15); }
    .step-card-header .status-icon {
      width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
      font-weight: 700; flex-shrink: 0; background: rgba(255,255,255,0.12);
    }
    .step-card-header.status-success .status-icon { background: var(--success-border); }
    .step-card-header.status-error .status-icon { background: var(--error-border); }
    .step-card-title { font-weight: 700; font-size: 15px; }
    .step-card-subtitle { color: #9ca3af; font-size: 12.5px; }
    .step-card-timestamp { margin-left: auto; color: #9ca3af; font-size: 11.5px; }
    .step-card-chevron { margin-left: auto; color: #9ca3af; font-size: 12px; transition: transform 0.15s ease; flex-shrink: 0; }
    .step-card-header[data-expanded="true"] .step-card-chevron { transform: rotate(180deg); }
    .step-card-header[data-expanded="true"] .step-card-timestamp { margin-left: 0; }
    .step-card-body { padding: 16px 18px; display: none; }
    .step-card-body.expanded { display: block; }
    .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); padding: 0 18px; }
    .tab-btn {
      font-family: inherit; font-size: 13px; font-weight: 600; color: var(--muted);
      background: none; border: none; border-bottom: 2px solid transparent; padding: 10px 6px; cursor: pointer;
    }
    .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
    .tab-panels { padding: 16px 18px; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .req-line {
      background: var(--dark); color: #fff; padding: 10px 14px; border-radius: 8px;
      display: flex; gap: 10px; align-items: center; font-family: ui-monospace, monospace; font-size: 12.5px;
      overflow-x: auto; margin-bottom: 4px;
    }
    .req-url { word-break: break-all; }
    .method-pill {
      background: #e32934; color: #fff; padding: 3px 10px; border-radius: 6px; font-weight: 700;
      font-size: 11px; flex-shrink: 0;
    }
    .method-pill.pill-ok { background: var(--success-border); }
    .method-pill.pill-fail { background: var(--error-border); }
    .field-label { font-size: 11px; color: var(--muted); margin: 12px 0 4px; text-transform: uppercase; letter-spacing: 0.03em; font-weight: 600; }
    .code-block, .code-dark {
      white-space: pre-wrap; word-break: break-all; padding: 10px; border-radius: 6px; font-size: 12px; margin: 0;
      font-family: ui-monospace, monospace;
    }
    .code-block { background: #f6f8fa; border: 1px solid var(--border); }
    .code-dark { background: var(--dark); color: #fbbf24; }
    .mini { margin: 8px 0; font-size: 12px; }
    .mini summary { cursor: pointer; color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; }
    .mini summary::-webkit-details-marker { display: none; }
    .mini summary::before { content: "▸ "; }
    .mini[open] summary::before { content: "▾ "; }
    .param-ref { margin: 6px 0 0; padding-left: 18px; font-size: 12.5px; }
    .param-ref li { margin-bottom: 4px; }
    .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 999px; }
    .badge-ok { background: var(--success-bg); color: var(--success-text); }
    .badge-fail { background: var(--error-bg); color: var(--error-text); }
    .banner { padding: 12px 14px; border-radius: 8px; border: 1px solid transparent; }
    .banner-error { background: var(--error-bg); border-color: var(--error-border); color: var(--error-text); }
    .muted { color: var(--muted); }
    .timestamp { font-size: 11px; }
    button, .btn {
      font-family: inherit; font-size: 13px; font-weight: 600; padding: 7px 14px; border-radius: 6px;
      border: 1px solid var(--border); background: #fff; cursor: pointer;
      transition: transform 0.12s ease, box-shadow 0.12s ease, background-color 0.12s ease;
    }
    button:hover, .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 10px rgba(0,31,69,0.1); }
    button:active, .btn:active { transform: translateY(0); box-shadow: none; }
    .btn-primary { background: #e32934; border-color: #c81e28; color: #fff; }
    .btn-primary:hover { background: #c81e28; }
    .btn-secondary { background: #fff; }
    input[type="text"] { font-family: inherit; font-size: 13px; padding: 7px 10px; border-radius: 6px; border: 1px solid var(--border); }
    a.plain { text-decoration: none; }
  </style>
</head>
<body>
  ${errorHtml}
  ${stoppedHtml}
  <div class="app-shell">
    ${opts.userIdentity ? `<span class="user-identity">👤 ${escapeHtml(opts.userIdentity)}</span>` : ''}
    <aside class="chat-panel">
      <div class="chat-header">
        <h1>Marketing Cloud</h1>
        <p class="subtitle">Okta Cross App Access (XAA) test harness</p>
        ${
          opts.loginFlow
            ? `<span class="flow-tag">Testing: ${
                opts.loginFlow === 'agent'
                  ? 'Agent app login (/agentapplogin)'
                  : opts.loginFlow === 'm2m'
                    ? 'M2M login (/m2mlogin)'
                    : 'Resource app login (/login)'
              }</span>`
            : ''
        }
        <span class="timer-tag" id="oktaTimerTag" title="Total network time across the login + XAA/ID-JAG token exchanges with Okta (T1, T2/T3, and T5–T8 when chained) — excludes T4/T9 (the campaign/resource action call itself), which never talks to Okta.">${formatOktaTimer(oktaExchangeMs)}</span>
      </div>
      <div class="chat-toolbar">
        ${
          opts.loggedIn
            ? '<p class="toolbar-label">💬 Try these, or just type them</p>' +
              '<div class="toolbar-row">' +
              '<button type="button" class="pill" id="tokenTypePill" data-cmd="toggle-token" title="Type \'use ID token\' or \'use access_token\' to switch"></button>' +
              '<button type="button" class="pill" data-cmd="test-xaa">▶ Start XAA flow</button>' +
              (opts.chainedXaaConfigured
                ? '<button type="button" class="pill" id="chainedXaaPill" data-cmd="test-chained-xaa" title="User → Agent 1 → Agent 2 → Resource">▶ Start Chained XAA flow</button>'
                : '') +
              '</div>' +
              (opts.chainedXaaConfigured
                ? '<div class="toolbar-row">' +
                  '<button type="button" class="pill" id="chainedActionsPill" data-cmd="toggle-chained-actions" title="Type \'enable chained actions\' or \'disable chained actions\'"></button>' +
                  '</div>'
                : '') +
              '<p class="toolbar-label">👤 Session</p>' +
              '<div class="toolbar-row">' +
              (opts.loginFlow !== 'resource'
                ? '<button type="button" class="pill" data-cmd="switch-resource-login">Switch to Resource app login</button>'
                : '') +
              (opts.loginFlow !== 'agent'
                ? '<button type="button" class="pill" data-cmd="switch-agent-login">Switch to Agent app login</button>'
                : '') +
              (opts.loginFlow !== 'm2m'
                ? '<button type="button" class="pill" data-cmd="switch-m2m-login">Switch to M2M login</button>'
                : '') +
              '<button type="button" class="pill" data-cmd="logout">🚪 Logout</button>' +
              '</div>'
            : '<p class="toolbar-label">👤 Log in to start</p>' +
              '<div class="toolbar-row">' +
              '<button type="button" class="pill" data-cmd="switch-resource-login">Log in via Resource app</button>' +
              '<button type="button" class="pill" data-cmd="switch-agent-login">Log in via Agent app</button>' +
              '<button type="button" class="pill" data-cmd="switch-m2m-login">Log in via M2M login</button>' +
              '</div>'
        }
      </div>
      <div class="chat-feed" id="chatFeed">${feedHtml}</div>
      <div class="chat-suggestions">
        ${actionPills}
        <button type="button" class="pill pill-danger" id="rogueBtn">⚠ Trigger Rogue Action</button>
      </div>
      <form class="chat-input-row" id="chatForm">
        <input type="text" id="chatInput" placeholder='${opts.chatAssistantConfigured ? 'Ask for anything — "initialize the XAA flow", "use my ID token", "fetch item 42"…' : 'Try "start XAA flow", "use ID token", or resource.get'}' />
        <button type="submit" class="btn-primary">➤ Send</button>
      </form>
    </aside>
    <main class="timeline-panel">
      <div class="accordion" id="accordion"></div>
    </main>
  </div>

  <script>
    var ADMIN_KEY = ${JSON.stringify(opts.adminKey)};
    var ALLOWED_ACTION_NAMES = ${JSON.stringify(listAllowedActions().map((a) => a.name))};
    var STEP_META = ${JSON.stringify(STEPS.map((s) => ({ n: s.n, title: s.title })))};
    var stepStatuses = ${JSON.stringify(stepStatuses)};
    var stepCards = ${JSON.stringify(stepCards)};
    var expandedStep = null;
    var subjectTokenType = 'access_token';
    var chainedActionsEnabled = false;
    var CHAT_ASSISTANT_CONFIGURED = ${JSON.stringify(opts.chatAssistantConfigured)};

    function renderModePills() {
      var tokenPill = document.getElementById('tokenTypePill');
      if (tokenPill) tokenPill.textContent = '🔑 Using ' + (subjectTokenType === 'id_token' ? 'ID token' : 'access_token');
      var chainedPill = document.getElementById('chainedActionsPill');
      if (chainedPill) {
        chainedPill.textContent = (chainedActionsEnabled ? '☑' : '☐') + ' Actions via Chained XAA';
        chainedPill.classList.toggle('pill-active', chainedActionsEnabled);
      }
    }

    function wireTabs(container) {
      var btns = container.querySelectorAll('.tab-btn');
      for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener('click', function (e) {
          e.stopPropagation();
          var tab = e.currentTarget.getAttribute('data-tab');
          var card = e.currentTarget.closest('.step-card');
          card.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.toggle('active', b === e.currentTarget); });
          card.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.toggle('active', p.getAttribute('data-panel') === tab); });
        });
      }
    }

    function applyExpandedState(container) {
      container.querySelectorAll('[data-step-toggle]').forEach(function (header) {
        var n = parseInt(header.getAttribute('data-step-toggle'), 10);
        var isOpen = n === expandedStep;
        header.setAttribute('data-expanded', isOpen ? 'true' : 'false');
        var body = container.querySelector('[data-step-body="' + n + '"]');
        if (body) body.classList.toggle('expanded', isOpen);
      });
    }

    function renderAccordion() {
      var el = document.getElementById('accordion');
      el.innerHTML = STEP_META.map(function (s) { return stepCards[s.n] || ''; }).join('');
      wireTabs(el);
      applyExpandedState(el);
    }

    function selectStep(n) {
      expandedStep = expandedStep === n ? null : n;
      applyExpandedState(document.getElementById('accordion'));
      if (expandedStep === n) {
        var header = document.querySelector('[data-step-toggle="' + n + '"]');
        if (header) header.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }

    document.getElementById('accordion').addEventListener('click', function (e) {
      var header = e.target.closest('[data-step-toggle]');
      if (header) selectStep(parseInt(header.getAttribute('data-step-toggle'), 10));
    });

    document.getElementById('chatFeed').addEventListener('click', function (e) {
      var bubble = e.target.closest('[data-jump-step]');
      if (bubble) {
        var n = parseInt(bubble.getAttribute('data-jump-step'), 10);
        expandedStep = n;
        applyExpandedState(document.getElementById('accordion'));
        var header = document.querySelector('[data-step-toggle="' + n + '"]');
        if (header) header.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    });

    function addPendingBubble(text) {
      var feed = document.getElementById('chatFeed');
      var div = document.createElement('div');
      div.className = 'bubble bubble-assistant bubble-pending';
      div.textContent = text;
      feed.appendChild(div);
      feed.scrollTop = feed.scrollHeight;
    }

    function renderOktaTimer(ms) {
      var tag = document.getElementById('oktaTimerTag');
      if (!tag) return;
      tag.textContent = ms === null || ms === undefined ? '⏱ Okta exchange: —' : '⏱ Okta exchange: ' + (ms / 1000).toFixed(2) + 's';
    }

    async function refreshFragments() {
      try {
        const res = await fetch('/debug/fragments?key=' + encodeURIComponent(ADMIN_KEY));
        if (!res.ok) return;
        const data = await res.json();
        stepStatuses = data.stepStatuses;
        stepCards = data.stepCards;
        renderAccordion();
        renderOktaTimer(data.oktaExchangeMs);
        document.getElementById('chatFeed').innerHTML = data.feedHtml;
        document.getElementById('chatFeed').scrollTop = document.getElementById('chatFeed').scrollHeight;
        document.getElementById('stoppedBanner').style.display = data.stopped ? '' : 'none';
        if (data.stopped) {
          document.getElementById('stoppedAt').textContent = data.stopped.stoppedAt;
          document.getElementById('stoppedReason').textContent = data.stopped.reason;
        }
      } catch (e) {}
    }

    async function runTestXaaLogin() {
      addPendingBubble('Running ID-JAG exchange using ' + subjectTokenType + '...');
      try {
        await fetch('/xaa/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subjectTokenType }),
        });
      } catch (e) {}
      await refreshFragments();
    }

    async function runTestChainedXaaLogin() {
      addPendingBubble('Running chained XAA (Agent 1 → Agent 2) using ' + subjectTokenType + '...');
      var ok = false;
      try {
        var res = await fetch('/xaa/chained-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subjectTokenType }),
        });
        ok = res.ok;
      } catch (e) {}
      if (ok) {
        // T5–T8 succeeded — finish the chain by calling T9 (Agent Action,
        // Chained) with Agent 2's resulting resource access_token, same as
        // clicking an action pill in chained mode. If the exchange above
        // failed, skip this: T9 should stay "not called yet", not show a
        // stale or unrelated result.
        await postAgentAction('resource.get', undefined, 'chained');
      } else {
        await refreshFragments();
      }
    }

    async function postAgentAction(action, params, forceXaaMode) {
      var xaaMode = forceXaaMode || (chainedActionsEnabled ? 'chained' : undefined);
      addPendingBubble('Sending "' + action + '"' + (xaaMode ? ' via Chained XAA' : '') + '...');
      try {
        await fetch('/agent/act', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, params, xaaMode }),
        });
      } catch (e) {}
      await refreshFragments();
    }

    document.querySelectorAll('.chat-suggestions .pill[data-action]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var action = btn.getAttribute('data-action');
        var defaultParams = {};
        try {
          defaultParams = JSON.parse(btn.getAttribute('data-default-params') || '{}');
        } catch (e) {}
        var hasParams = Object.keys(defaultParams).length > 0;
        if (hasParams) {
          // Guided input: prefill the editable defaults instead of firing
          // blind, so it's obvious what's being sent and it's easy to tweak.
          var input = document.getElementById('chatInput');
          input.value = action + ' ' + JSON.stringify(defaultParams);
          input.focus();
          input.select();
        } else {
          postAgentAction(action, undefined);
        }
      });
    });

    document.getElementById('rogueBtn').addEventListener('click', function () {
      postAgentAction('resource.delete_all', undefined);
    });

    // Toolbar quick-reply pills post the same commands a typed phrase would
    // resolve to, so clicking and typing are two paths into one place.
    function runCommand(cmd) {
      if (cmd === 'test-xaa') return runTestXaaLogin();
      if (cmd === 'test-chained-xaa') return runTestChainedXaaLogin();
      if (cmd === 'switch-resource-login') { window.location.href = '/login'; return; }
      if (cmd === 'switch-agent-login') { window.location.href = '/agentapplogin'; return; }
      if (cmd === 'switch-m2m-login') { window.location.href = '/m2mlogin'; return; }
      if (cmd === 'logout') { window.location.href = '/logout'; return; }
      if (cmd === 'toggle-token') {
        subjectTokenType = subjectTokenType === 'id_token' ? 'access_token' : 'id_token';
        renderModePills();
        addPendingBubble('Using ' + subjectTokenType + ' as the subject_token from now on.');
        setTimeout(refreshFragments, 10);
        return;
      }
      if (cmd === 'toggle-chained-actions') {
        chainedActionsEnabled = !chainedActionsEnabled;
        renderModePills();
        addPendingBubble((chainedActionsEnabled ? 'Enabled' : 'Disabled') + ' Chained XAA for agent actions.');
        setTimeout(refreshFragments, 10);
        return;
      }
    }

    document.querySelectorAll('.chat-toolbar .pill[data-cmd]').forEach(function (btn) {
      btn.addEventListener('click', function () { runCommand(btn.getAttribute('data-cmd')); });
    });
    renderModePills();

    // Fallback path when no LLM is configured (no ANTHROPIC_API_KEY): a small
    // set of hand-written patterns so the chat still recognizes a few obvious
    // phrasings rather than only literal action names.
    function matchCommandFallback(text) {
      var t = text.toLowerCase().trim();
      var startVerb = /(start|run|test|initiat|initiali[sz]e|kick ?off|begin|trigger)/;
      if (startVerb.test(t) && /chained/.test(t) && /xaa/.test(t)) return 'test-chained-xaa';
      if (startVerb.test(t) && /xaa/.test(t)) return 'test-xaa';
      if (/id.?token/.test(t) && /(use|switch)/.test(t)) return 'toggle-token';
      if (/access.?token/.test(t) && /(use|switch)/.test(t)) return 'toggle-token';
      if (/chained.*action/.test(t) && /(enable|on|turn on)/.test(t)) return chainedActionsEnabled ? null : 'toggle-chained-actions';
      if (/chained.*action/.test(t) && /(disable|off|turn off)/.test(t)) return chainedActionsEnabled ? 'toggle-chained-actions' : null;
      if (/resource app/.test(t) && /(switch|log ?in|login)/.test(t)) return 'switch-resource-login';
      if (/agent app/.test(t) && /(switch|log ?in|login)/.test(t)) return 'switch-agent-login';
      if (/m2m/.test(t) && /(switch|log ?in|login)/.test(t)) return 'switch-m2m-login';
      if (/^log ?out$/.test(t)) return 'logout';
      return null;
    }

    // Lets phrases like "show me campaigns" or "update campaign camp-2 budget
    // to 20000, set it active" resolve to marketing.list/get/update with
    // parsed params, without requiring the literal action name + JSON the
    // plain fallback otherwise expects. Only used when no LLM is configured.
    function extractCampaignId(t) {
      var m = t.match(/\\bcamp[a-z]*[\\s-]*(\\d+)\\b/);
      if (m) return 'camp-' + m[1];
      var m2 = t.match(/\\bid\\s*[:=]?\\s*(camp-\\d+)\\b/);
      return m2 ? m2[1] : null;
    }

    function matchMarketingAction(raw) {
      var t = raw.toLowerCase();
      if (!/campa[gi]/.test(t)) return null;
      var id = extractCampaignId(t);
      if (/(create|add|new)/.test(t)) {
        var params = {};
        var nameMatch = raw.match(/["“]([^"”]+)["”]/) || raw.match(/named\\s+([a-z0-9 ]+?)(?:,|\\.|$)/i);
        params.name = nameMatch ? nameMatch[1].trim() : 'New Campaign';
        var budgetMatch = t.match(/budget[^0-9]*([0-9][0-9,]*)/);
        if (budgetMatch) params.budget = budgetMatch[1].replace(/,/g, '');
        var statusMatch = t.match(/\\b(draft|active|paused)\\b/);
        if (statusMatch) params.status = statusMatch[1];
        return { action: 'marketing.create', params: params };
      }
      if (/(update|change|set|edit)/.test(t)) {
        var params = { id: id || 'camp-1' };
        var budgetMatch = t.match(/budget[^0-9]*([0-9][0-9,]*)/);
        if (budgetMatch) params.budget = budgetMatch[1].replace(/,/g, '');
        var statusMatch = t.match(/\\b(draft|active|paused)\\b/);
        if (statusMatch) params.status = statusMatch[1];
        return { action: 'marketing.update', params: params };
      }
      if (id) return { action: 'marketing.get', params: { id: id } };
      if (/(show|list|view|get|see|display|what)/.test(t)) return { action: 'marketing.list', params: {} };
      return null;
    }

    function handleFallback(raw) {
      var cmd = matchCommandFallback(raw);
      if (cmd) { runCommand(cmd); return; }
      var marketingMatch = matchMarketingAction(raw);
      if (marketingMatch) { postAgentAction(marketingMatch.action, marketingMatch.params); return; }
      var braceIdx = raw.indexOf('{');
      var action = (braceIdx === -1 ? raw : raw.slice(0, braceIdx)).trim();
      var paramsRaw = braceIdx === -1 ? '' : raw.slice(braceIdx).trim();
      if (ALLOWED_ACTION_NAMES.indexOf(action) === -1) {
        // Same client-side gate as the pills: free-text input can never reach
        // the killswitch, even with an unrecognized action typed in.
        addPendingBubble('⚠ "' + action + '" is not an allowed action, so this input won\\'t send it. Use "Trigger Rogue Action" to test that on purpose.');
        setTimeout(refreshFragments, 10);
        return;
      }
      var params;
      if (paramsRaw) {
        try {
          params = JSON.parse(paramsRaw);
        } catch (err) {
          addPendingBubble('❌ Params must be valid JSON: ' + err);
          setTimeout(refreshFragments, 10);
          return;
        }
      }
      postAgentAction(action, params);
    }

    // Sends the raw message to the server, which asks Claude to classify it
    // against the same command set the toolbar pills use, so free-form
    // phrasing like "fetch item 42" or "trigger a rogue action" resolves
    // without hand-written pattern matching. Falls back to matchCommandFallback
    // when no ANTHROPIC_API_KEY is configured server-side.
    async function handleChatMessage(raw) {
      if (!CHAT_ASSISTANT_CONFIGURED) {
        handleFallback(raw);
        return;
      }
      addPendingBubble('Thinking...');
      var decision;
      try {
        var res = await fetch('/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: raw, subjectTokenType: subjectTokenType, chainedActionsEnabled: chainedActionsEnabled }),
        });
        if (!res.ok) throw new Error('chat request failed');
        decision = await res.json();
      } catch (e) {
        await refreshFragments();
        handleFallback(raw);
        return;
      }
      await refreshFragments();
      if (decision.reply) addPendingBubble(decision.reply);
      if (decision.command === 'run-action') {
        postAgentAction(decision.action, decision.params);
      } else if (decision.command && decision.command !== 'reply') {
        runCommand(decision.command);
      } else {
        setTimeout(refreshFragments, 10);
      }
    }

    document.getElementById('chatForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var raw = document.getElementById('chatInput').value.trim();
      if (!raw) return;
      document.getElementById('chatInput').value = '';
      handleChatMessage(raw);
    });

    var resetBtn = document.getElementById('resetBtn');
    if (resetBtn) {
      resetBtn.addEventListener('click', async function () {
        addPendingBubble('Resetting agent...');
        try {
          await fetch('/admin/reset', { method: 'POST', headers: { 'x-admin-secret': ADMIN_KEY } });
          document.getElementById('stoppedBanner').style.display = 'none';
        } catch (e) {}
        await refreshFragments();
      });
    }

    renderAccordion();
    document.getElementById('chatFeed').scrollTop = document.getElementById('chatFeed').scrollHeight;
  </script>
</body>
</html>`;
}
