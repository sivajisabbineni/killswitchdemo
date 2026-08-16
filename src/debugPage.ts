import { decodeJwt } from 'jose';
import { getCalls, getTokens, getLatestCallByLabel, type CallLogEntry } from './debugLog';
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
  error?: string;
  stopped: StoppedState | null;
}

type StepStatus = 'pending' | 'success' | 'error';

interface StepDef {
  n: number;
  label: string;
  title: string;
  subtitle: string;
  hint: string;
  tokenLabel?: string;
}

const STEPS: StepDef[] = [
  {
    n: 1,
    label: 'login:token-exchange',
    title: 'Access Token',
    subtitle: 'User → Okta (OIDC authorization code)',
    hint: 'Standard OIDC login — the human user authenticates and the Resource App exchanges the authorization code for a user access_token.',
    tokenLabel: 'user access_token (login)',
  },
  {
    n: 2,
    label: 'xaa:id-jag-request',
    title: 'Get ID-JAG',
    subtitle: 'Agent → Okta (org token endpoint)',
    hint: 'RFC 8693 token-exchange — the Agent trades the user access_token for an ID-JAG, authenticating itself with a private_key_jwt client_assertion.',
    tokenLabel: 'ID-JAG',
  },
  {
    n: 3,
    label: 'xaa:resource-token-exchange',
    title: 'Resource Access Token',
    subtitle: 'Agent → Resource App token endpoint',
    hint: 'RFC 7523 jwt-bearer exchange — the Agent redeems the ID-JAG at the resource app\'s own token endpoint for a resource-scoped access_token.',
    tokenLabel: 'resource access_token',
  },
  {
    n: 4,
    label: 'resource:api-call',
    title: 'Agent Action',
    subtitle: 'Agent → Resource API',
    hint: 'The Agent calls the resource API using the resource access_token from step 3 (only if the requested action is on the policy allow-list).',
  },
];

const STEP_BY_LABEL = new Map(STEPS.map((s) => [s.label, s]));

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
    // form-urlencoded bodies: one param per line, matching the reference UI's BODY block.
    if (body.includes('=') && body.includes('&')) {
      const formatted = body
        .split('&')
        .map((pair, i) => (i === 0 ? pair : '&' + pair))
        .join('\n');
      return `<pre class="code-dark">${escapeHtml(formatted)}</pre>`;
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
  const call = getLatestCallByLabel(step.label);
  const status = statusOf(call);
  const statusIcon = status === 'success' ? '✓' : status === 'error' ? '✕' : '○';

  if (!call) {
    return `<div class="step-card">
      <div class="step-card-header status-${status}">
        <span class="status-icon">${statusIcon}</span>
        <div>
          <div class="step-card-title">T${step.n} — ${escapeHtml(step.title)}</div>
          <div class="step-card-subtitle">${escapeHtml(step.subtitle)}</div>
        </div>
      </div>
      <div class="step-card-body">
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

  const tokenEntry = step.tokenLabel ? getTokens().find((t) => t.label === step.tokenLabel) : undefined;
  const bearerClaims = !tokenEntry ? safeDecodeBearer(call.requestHeaders) : undefined;
  let tokenTab: string;
  if (tokenEntry) {
    tokenTab = `
      <div class="field-label">RAW TOKEN</div>
      <pre class="code-dark">${escapeHtml(tokenEntry.token)}</pre>
      ${tokenEntry.claims ? `<div class="field-label">DECODED CLAIMS</div><pre class="code-dark">${escapeHtml(JSON.stringify(tokenEntry.claims, null, 2))}</pre>` : ''}`;
  } else if (bearerClaims) {
    tokenTab = `
      <p class="muted" style="margin-top:0;">This step doesn't issue a new token — it uses the resource access_token from T3.</p>
      <div class="field-label">DECODED CLAIMS (from Authorization header)</div>
      <pre class="code-dark">${escapeHtml(JSON.stringify(bearerClaims, null, 2))}</pre>`;
  } else {
    tokenTab = `<p class="muted" style="margin:0;">No token associated with this call.</p>`;
  }

  const codeTab = `<pre class="code-dark">${escapeHtml(buildCurl(call))}</pre>`;

  return `<div class="step-card">
    <div class="step-card-header status-${status}">
      <span class="status-icon">${statusIcon}</span>
      <div>
        <div class="step-card-title">T${step.n} — ${escapeHtml(step.title)}</div>
        <div class="step-card-subtitle">${escapeHtml(step.subtitle)}</div>
      </div>
      <div class="step-card-timestamp">${escapeHtml(call.timestamp)}</div>
    </div>
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
  </div>`;
}

function labelTitle(label: string): string {
  return STEP_BY_LABEL.get(label)?.title ?? EXTRA_LABEL_TITLES[label] ?? label;
}

function buildFeedHtml(): string {
  const greeting = `<div class="bubble bubble-assistant">Hi! I'm the killswitch-agent test harness. Use the actions below to run allowed calls, test the XAA login, or trigger the killswitch — every hop shows up in the timeline on the right.</div>`;
  const calls = getCalls().slice().reverse();
  const bubbles = calls
    .map((c) => {
      const ok = !c.error && (c.status === undefined || c.status < 400);
      const badge = c.error ? 'network error' : c.status !== undefined ? String(c.status) : '';
      const step = STEP_BY_LABEL.get(c.label);
      const jumpAttr = step ? ` data-jump-step="${step.n}"` : '';
      return `<div class="bubble bubble-assistant ${ok ? 'bubble-ok' : 'bubble-fail'}"${jumpAttr}>
        <strong>${escapeHtml(labelTitle(c.label))}</strong> <span class="badge ${ok ? 'badge-ok' : 'badge-fail'}">${escapeHtml(badge)}</span>
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
}

export function renderDebugFragments(stopped: StoppedState | null): DebugFragments {
  const stepStatuses: Record<number, StepStatus> = {};
  const stepCards: Record<number, string> = {};
  for (const step of STEPS) {
    stepStatuses[step.n] = statusOf(getLatestCallByLabel(step.label));
    stepCards[step.n] = buildStepCard(step);
  }
  return { stepStatuses, stepCards, feedHtml: buildFeedHtml(), stopped };
}

export function renderDebugPage(opts: DebugPageOptions): string {
  const { stepStatuses, stepCards, feedHtml } = renderDebugFragments(opts.stopped);

  const errorHtml = opts.error
    ? `<div class="banner banner-error" style="margin:12px;"><strong>Error:</strong> ${escapeHtml(opts.error)}</div>`
    : '';

  const stoppedHtml = `<div id="stoppedBanner" class="banner banner-error" style="margin:12px; ${opts.stopped ? '' : 'display:none;'}">
        <strong>⚠ Agent stopped</strong> at <span id="stoppedAt">${opts.stopped ? escapeHtml(opts.stopped.stoppedAt) : ''}</span> — reason: <code id="stoppedReason">${opts.stopped ? escapeHtml(opts.stopped.reason) : ''}</code>
        <div style="margin-top:8px;"><button id="resetBtn" class="btn btn-secondary">Reset Agent</button></div>
      </div>`;

  const actionPills = listAllowedActions()
    .map((a) => `<button type="button" class="pill" data-action="${escapeHtml(a.name)}">${escapeHtml(a.name)}</button>`)
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>killswitch-agent debug</title>
  <style>
    :root {
      --bg: #f4f5f7;
      --card-bg: #ffffff;
      --border: #e1e4e8;
      --text: #1a1f24;
      --muted: #6b7280;
      --accent: #2563eb;
      --accent-dark: #1d4ed8;
      --success-bg: #eafaf0;
      --success-border: #34c85a;
      --success-text: #0a7d28;
      --warn-bg: #fff8e6;
      --warn-border: #e5a300;
      --warn-text: #8a5a00;
      --error-bg: #fde7e9;
      --error-border: #e0455a;
      --error-text: #b00020;
      --dark: #0f1420;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 0;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .app-shell {
      display: flex;
      gap: 20px;
      max-width: 1440px;
      margin: 20px auto;
      padding: 0 16px 20px;
      align-items: flex-start;
    }
    .chat-panel {
      width: 360px;
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }
    .chat-header { padding: 16px 18px 12px; border-bottom: 1px solid var(--border); }
    .chat-header h1 { font-size: 17px; margin: 0 0 2px; }
    .chat-header .subtitle { color: var(--muted); font-size: 12.5px; margin: 0; }
    .chat-toolbar { padding: 12px 18px; border-bottom: 1px solid var(--border); display: flex; gap: 8px; flex-wrap: wrap; }
    .chat-feed { flex: 1; overflow-y: auto; padding: 14px 18px; display: flex; flex-direction: column; gap: 10px; max-height: 480px; }
    .bubble {
      background: #eef1f5;
      border-radius: 12px;
      padding: 10px 13px;
      font-size: 13px;
      max-width: 100%;
    }
    .bubble-assistant { align-self: flex-start; }
    .bubble-ok { background: var(--success-bg); }
    .bubble-fail { background: var(--error-bg); }
    .bubble-pending { background: #eceff1; color: var(--muted); }
    .bubble[data-jump-step] { cursor: pointer; }
    .bubble[data-jump-step]:hover { filter: brightness(0.97); }
    .chat-suggestions { padding: 10px 18px; border-top: 1px solid var(--border); display: flex; gap: 6px; flex-wrap: wrap; }
    .pill {
      font-family: inherit;
      font-size: 12.5px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #fff;
      cursor: pointer;
    }
    .pill:hover { background: #f6f8fa; }
    .pill-danger { border-color: var(--error-border); color: var(--error-text); }
    .pill-danger:hover { background: var(--error-bg); }
    .chat-input-row { display: flex; gap: 8px; padding: 12px 18px 16px; border-top: 1px solid var(--border); }
    .chat-input-row input[type="text"] { flex: 1; }
    .timeline-panel { flex: 1; min-width: 0; }
    .stepper { display: flex; align-items: center; margin-bottom: 16px; }
    .step-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 8px 16px 8px 10px;
      cursor: pointer;
      font-family: inherit;
      text-align: left;
    }
    .step-pill.selected { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(37,99,235,0.15); }
    .step-pill + .step-pill { margin-left: 10px; }
    .step-connector { flex: 1; height: 2px; background: var(--border); margin: 0 -2px; min-width: 12px; }
    .step-dot { width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: #fff; flex-shrink: 0; }
    .status-pending .step-dot { background: #9ca3af; }
    .status-success .step-dot { background: var(--success-border); }
    .status-error .step-dot { background: var(--error-border); }
    .step-label { font-size: 12px; font-weight: 600; line-height: 1.2; }
    .step-label small { color: var(--muted); font-weight: 500; display: block; font-size: 11px; }
    .step-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    .step-card-header { background: var(--dark); color: #fff; padding: 16px 18px; display: flex; align-items: center; gap: 12px; }
    .step-card-header .status-icon {
      width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
      font-weight: 700; flex-shrink: 0; background: rgba(255,255,255,0.12);
    }
    .step-card-header.status-success .status-icon { background: var(--success-border); }
    .step-card-header.status-error .status-icon { background: var(--error-border); }
    .step-card-title { font-weight: 700; font-size: 15px; }
    .step-card-subtitle { color: #9ca3af; font-size: 12.5px; }
    .step-card-timestamp { margin-left: auto; color: #9ca3af; font-size: 11.5px; }
    .step-card-body { padding: 16px 18px; }
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
      background: #4f46e5; color: #fff; padding: 3px 10px; border-radius: 6px; font-weight: 700;
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
    }
    .btn-primary { background: var(--accent); border-color: var(--accent-dark); color: #fff; }
    .btn-primary:hover { background: var(--accent-dark); }
    .btn-secondary { background: #fff; }
    input[type="text"] { font-family: inherit; font-size: 13px; padding: 7px 10px; border-radius: 6px; border: 1px solid var(--border); }
    a.plain { text-decoration: none; }
  </style>
</head>
<body>
  ${errorHtml}
  ${stoppedHtml}
  <div class="app-shell">
    <aside class="chat-panel">
      <div class="chat-header">
        <h1>killswitch-agent</h1>
        <p class="subtitle">Okta Cross App Access (XAA) test harness</p>
      </div>
      <div class="chat-toolbar">
        ${
          opts.loggedIn
            ? '<button type="button" class="pill" id="xaaLoginBtn">Test XAA login</button>'
            : '<a class="plain" href="/login"><button type="button" class="pill">Log in with Okta</button></a>'
        }
      </div>
      <div class="chat-feed" id="chatFeed">${feedHtml}</div>
      <div class="chat-suggestions">
        ${actionPills}
        <button type="button" class="pill pill-danger" id="rogueBtn">⚠ Trigger Rogue Action</button>
      </div>
      <form class="chat-input-row" id="chatForm">
        <input type="text" id="chatInput" placeholder='resource.get or resource.status {"code":"500"}' />
        <button type="submit" class="btn-primary">Send</button>
      </form>
    </aside>
    <main class="timeline-panel">
      <div class="stepper" id="stepper"></div>
      <div id="stepDetail"></div>
    </main>
  </div>

  <script>
    var ADMIN_KEY = ${JSON.stringify(opts.adminKey)};
    var ALLOWED_ACTION_NAMES = ${JSON.stringify(listAllowedActions().map((a) => a.name))};
    var STEP_META = ${JSON.stringify(STEPS.map((s) => ({ n: s.n, title: s.title })))};
    var stepStatuses = ${JSON.stringify(stepStatuses)};
    var stepCards = ${JSON.stringify(stepCards)};
    var currentStep = 1;

    function renderStepper() {
      var html = STEP_META.map(function (s, i) {
        var st = stepStatuses[s.n] || 'pending';
        var pill = '<button type="button" class="step-pill status-' + st + (s.n === currentStep ? ' selected' : '') + '" data-step="' + s.n + '">' +
          '<span class="step-dot">T' + s.n + '</span><span class="step-label">' + s.title + '</span></button>';
        return i > 0 ? '<span class="step-connector"></span>' + pill : pill;
      }).join('');
      document.getElementById('stepper').innerHTML = html;
    }

    function wireTabs(container) {
      var btns = container.querySelectorAll('.tab-btn');
      for (var i = 0; i < btns.length; i++) {
        btns[i].addEventListener('click', function (e) {
          var tab = e.currentTarget.getAttribute('data-tab');
          var card = e.currentTarget.closest('.step-card');
          card.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.toggle('active', b === e.currentTarget); });
          card.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.toggle('active', p.getAttribute('data-panel') === tab); });
        });
      }
    }

    function renderStepDetail() {
      var el = document.getElementById('stepDetail');
      el.innerHTML = stepCards[currentStep] || '';
      wireTabs(el);
    }

    function selectStep(n) {
      currentStep = n;
      renderStepper();
      renderStepDetail();
    }

    document.getElementById('stepper').addEventListener('click', function (e) {
      var pill = e.target.closest('.step-pill');
      if (pill) selectStep(parseInt(pill.getAttribute('data-step'), 10));
    });

    document.getElementById('chatFeed').addEventListener('click', function (e) {
      var bubble = e.target.closest('[data-jump-step]');
      if (bubble) selectStep(parseInt(bubble.getAttribute('data-jump-step'), 10));
    });

    function addPendingBubble(text) {
      var feed = document.getElementById('chatFeed');
      var div = document.createElement('div');
      div.className = 'bubble bubble-assistant bubble-pending';
      div.textContent = text;
      feed.appendChild(div);
      feed.scrollTop = feed.scrollHeight;
    }

    async function refreshFragments() {
      try {
        const res = await fetch('/debug/fragments?key=' + encodeURIComponent(ADMIN_KEY));
        if (!res.ok) return;
        const data = await res.json();
        stepStatuses = data.stepStatuses;
        stepCards = data.stepCards;
        renderStepper();
        renderStepDetail();
        document.getElementById('chatFeed').innerHTML = data.feedHtml;
        document.getElementById('chatFeed').scrollTop = document.getElementById('chatFeed').scrollHeight;
        document.getElementById('stoppedBanner').style.display = data.stopped ? '' : 'none';
        if (data.stopped) {
          document.getElementById('stoppedAt').textContent = data.stopped.stoppedAt;
          document.getElementById('stoppedReason').textContent = data.stopped.reason;
        }
      } catch (e) {}
    }

    var xaaLoginBtn = document.getElementById('xaaLoginBtn');
    if (xaaLoginBtn) {
      xaaLoginBtn.addEventListener('click', async function () {
        addPendingBubble('Running ID-JAG exchange...');
        try {
          await fetch('/xaa/login', { method: 'POST' });
        } catch (e) {}
        await refreshFragments();
      });
    }

    async function postAgentAction(action, params) {
      addPendingBubble('Sending "' + action + '"...');
      try {
        await fetch('/agent/act', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, params }),
        });
      } catch (e) {}
      await refreshFragments();
    }

    document.querySelectorAll('.chat-suggestions .pill[data-action]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        postAgentAction(btn.getAttribute('data-action'), undefined);
      });
    });

    document.getElementById('rogueBtn').addEventListener('click', function () {
      postAgentAction('resource.delete_all', undefined);
    });

    document.getElementById('chatForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var raw = document.getElementById('chatInput').value.trim();
      if (!raw) return;
      var braceIdx = raw.indexOf('{');
      var action = (braceIdx === -1 ? raw : raw.slice(0, braceIdx)).trim();
      var paramsRaw = braceIdx === -1 ? '' : raw.slice(braceIdx).trim();
      if (ALLOWED_ACTION_NAMES.indexOf(action) === -1) {
        // Same client-side gate as the pills: free-text input can never reach
        // the killswitch, even with an unrecognized action typed in.
        addPendingBubble('⚠ "' + action + '" is not an allowed action, so this input won\\'t send it. Use "Trigger Rogue Action" to test that on purpose.');
        setTimeout(refreshFragments, 10);
        document.getElementById('chatInput').value = '';
        return;
      }
      var params;
      if (paramsRaw) {
        try {
          params = JSON.parse(paramsRaw);
        } catch (err) {
          addPendingBubble('❌ Params must be valid JSON: ' + err);
          setTimeout(refreshFragments, 10);
          document.getElementById('chatInput').value = '';
          return;
        }
      }
      document.getElementById('chatInput').value = '';
      postAgentAction(action, params);
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

    renderStepper();
    renderStepDetail();
    document.getElementById('chatFeed').scrollTop = document.getElementById('chatFeed').scrollHeight;
  </script>
</body>
</html>`;
}
