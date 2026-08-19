export interface LandingPageOptions {
  loggedIn: boolean;
  loginFlow?: 'resource' | 'agent';
  adminKey: string;
}

export function renderLandingPage(opts: LandingPageOptions): string {
  const debugUrl = `/debug?key=${encodeURIComponent(opts.adminKey)}`;
  const flowLabel =
    opts.loginFlow === 'agent' ? 'Agent app (/agentapplogin)' : opts.loginFlow === 'resource' ? 'Resource app (/login)' : null;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>killswitch-agent</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f4f5f7; color: #1a1f24; margin: 0; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      background: #fff; border: 1px solid #e1e4e8; border-radius: 12px;
      padding: 32px 36px; max-width: 420px; width: 100%; text-align: center;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    h1 { font-size: 20px; margin: 0 0 6px; }
    p { color: #6b7280; font-size: 13.5px; margin: 0 0 20px; }
    .status { background: #eef2ff; color: #4338ca; border-radius: 8px; padding: 10px 12px; font-size: 13px; margin-bottom: 18px; }
    .options { display: flex; flex-direction: column; gap: 10px; }
    button {
      font-family: inherit; font-size: 14px; font-weight: 600; padding: 10px 16px;
      border-radius: 8px; border: 1px solid #e1e4e8; background: #fff; cursor: pointer; width: 100%;
    }
    .btn-primary { background: #2563eb; border-color: #1d4ed8; color: #fff; }
    a.plain { text-decoration: none; }
    .footer-links { margin-top: 18px; display: flex; justify-content: center; gap: 14px; font-size: 12.5px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>killswitch-agent</h1>
    <p>Choose how the human user logs in before testing the Okta Cross App Access (XAA) flow.</p>
    ${opts.loggedIn ? `<div class="status">Currently logged in via <strong>${flowLabel}</strong></div>` : ''}
    <div class="options">
      <a class="plain" href="/login"><button class="btn-primary">Log in via Resource app</button></a>
      <a class="plain" href="/agentapplogin"><button>Log in via Agent app</button></a>
    </div>
    <div class="footer-links">
      ${opts.loggedIn ? `<a href="${debugUrl}">Go to debug page</a>` : ''}
      ${opts.loggedIn ? `<a href="/logout">Logout</a>` : ''}
    </div>
  </div>
</body>
</html>`;
}
