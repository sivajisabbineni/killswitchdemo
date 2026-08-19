import crypto from 'node:crypto';
import express from 'express';
import session from 'express-session';
import { config } from './config';
import { buildAuthorizeUrl, exchangeCodeForToken, buildAgentAuthorizeUrl, exchangeAgentCodeForToken } from './oidc';
import { testXaaLogin } from './xaa';
import { callResourceApi } from './resourceClient';
import { evaluate } from './policy';
import { triggerKillswitch, triggerActivation } from './killswitch';
import { renderDebugPage, renderDebugFragments } from './debugPage';
import { renderLandingPage } from './landingPage';
import { derivePublicJwk } from './publicKeyInfo';
import { getAgentStoppedState } from './agentState';
import { clearHistory, clearCallsByLabel } from './debugLog';

const app = express();
// Render (and most PaaS hosts) terminate TLS at a proxy and forward plain HTTP
// internally. Without this, Express sees every request as insecure, so
// express-session refuses to set the session cookie when cookie.secure is
// true — breaking the oauthState round-trip between /login and /callback.
app.set('trust proxy', 1);
app.use(express.json());
app.use(
  session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' },
  }),
);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(
    renderLandingPage({
      loggedIn: Boolean(req.session.userAccessToken),
      loginFlow: req.session.loginFlow,
      adminKey: config.adminTriggerSecret,
    }),
  );
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/login', (req, res) => {
  clearHistory();
  const state = crypto.randomUUID();
  req.session.oauthState = state;
  req.session.loginFlow = 'resource';
  res.redirect(buildAuthorizeUrl(state));
});

app.get('/agentapplogin', (req, res) => {
  clearHistory();
  const state = crypto.randomUUID();
  req.session.oauthState = state;
  req.session.loginFlow = 'agent';
  res.redirect(buildAgentAuthorizeUrl(state));
});

app.get('/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  const debugUrl = `/debug?key=${encodeURIComponent(config.adminTriggerSecret)}`;

  if (typeof error === 'string') {
    const detail = typeof errorDescription === 'string' ? `${error}: ${errorDescription}` : error;
    return res.redirect(`${debugUrl}&error=${encodeURIComponent(`Okta rejected the login request: ${detail}`)}`);
  }

  if (typeof code !== 'string' || state !== req.session.oauthState) {
    return res.redirect(`${debugUrl}&error=${encodeURIComponent('Invalid or expired login callback (state mismatch or missing code)')}`);
  }

  try {
    const { accessToken, idToken } =
      req.session.loginFlow === 'agent' ? await exchangeAgentCodeForToken(code) : await exchangeCodeForToken(code);
    req.session.userAccessToken = accessToken;
    req.session.userIdToken = idToken;
    res.redirect(debugUrl);
  } catch (err) {
    res.redirect(`${debugUrl}&error=${encodeURIComponent((err as Error).message)}`);
  }
});

app.get('/debug', (req, res) => {
  if (req.query.key !== config.adminTriggerSecret) {
    return res.status(401).send('Unauthorized. Append ?key=<ADMIN_TRIGGER_SECRET> to the URL.');
  }
  res.set('Content-Type', 'text/html');
  res.send(
    renderDebugPage({
      adminKey: config.adminTriggerSecret,
      loggedIn: Boolean(req.session.userAccessToken),
      loginFlow: req.session.loginFlow,
      error: typeof req.query.error === 'string' ? req.query.error : undefined,
      stopped: getAgentStoppedState(),
    }),
  );
});

app.get('/debug/fragments', (req, res) => {
  if (req.query.key !== config.adminTriggerSecret) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  res.json(renderDebugFragments(getAgentStoppedState()));
});

app.get('/xaa/public-key', (req, res) => {
  if (req.query.key !== config.adminTriggerSecret) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  try {
    res.json(derivePublicJwk());
  } catch (err) {
    res.status(500).json({ error: 'key_derivation_failed', detail: (err as Error).message });
  }
});

app.post('/xaa/login', async (req, res) => {
  // Deliberately no local "stopped" short-circuit here: this always attempts
  // the real ID-JAG + resource-token exchange against Okta, so if the
  // killswitch webhook actually revoked the Agent's trust upstream, that
  // real rejection is what shows up in the timeline — not a locally faked one.
  const userAccessToken = req.session.userAccessToken;
  if (!userAccessToken) {
    return res.status(401).json({ error: 'not_logged_in' });
  }

  const subjectTokenType = req.body?.subjectTokenType === 'id_token' ? 'id_token' : 'access_token';
  const subjectToken = subjectTokenType === 'id_token' ? req.session.userIdToken : userAccessToken;
  if (!subjectToken) {
    return res.status(400).json({ error: 'no_id_token', message: 'No ID token was captured for this login — log in again.' });
  }

  try {
    const accessToken = await testXaaLogin(subjectToken, subjectTokenType);
    res.json({ status: 'ok', resourceAccessToken: accessToken });
  } catch (err) {
    res.status(502).json({ error: 'xaa_exchange_failed', detail: (err as Error).message });
  }
});

app.post('/agent/act', async (req, res) => {
  const userAccessToken = req.session.userAccessToken;
  if (!userAccessToken) {
    return res.status(401).json({ error: 'not_logged_in' });
  }

  const { action, params } = req.body ?? {};
  const matched = evaluate(action);

  if (!matched) {
    const killswitch = await triggerKillswitch('policy_violation', { action, params });
    return res
      .status(403)
      .json({ error: 'rogue_action_detected', action, message: 'This agent has been stopped.', killswitch });
  }

  try {
    // No local "stopped" short-circuit, and no cached token reuse: every
    // action re-runs the full XAA exchange fresh, so a killswitch that
    // actually revoked the Agent at Okta shows up as a real rejection here
    // instead of the app silently trusting a still-valid cached token.
    //
    // Under the Agent app login flow there's no delegation policy covering
    // the Agent's own access_token, so tool calls must use the ID token
    // instead. The access_token option in "Test XAA login" stays available
    // there purely for negative testing.
    const subjectTokenType = req.session.loginFlow === 'agent' ? 'id_token' : 'access_token';
    const subjectToken = subjectTokenType === 'id_token' ? req.session.userIdToken : userAccessToken;
    if (!subjectToken) {
      return res
        .status(400)
        .json({ error: 'no_id_token', message: 'No ID token was captured for this login — log in again.' });
    }
    // Clear T4's stale result too — if the exchange below fails, T4 should
    // show "not called yet" for this attempt, not a leftover success from an
    // earlier, unrelated action.
    clearCallsByLabel(['resource:api-call']);
    const accessToken = await testXaaLogin(subjectToken, subjectTokenType);
    const result = await callResourceApi(accessToken, matched, params);
    res.json({ result });
  } catch (err) {
    res.status(502).json({ error: 'resource_call_failed', detail: (err as Error).message });
  }
});

app.post('/admin/kill', async (req, res) => {
  if (req.header('x-admin-secret') !== config.adminTriggerSecret) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { reason } = req.body ?? {};
  const killswitch = await triggerKillswitch(reason ?? 'manual_admin_trigger', {});
  res.json({ status: 'agent_stopped', message: 'This agent has been stopped.', killswitch });
});

app.post('/admin/reset', async (req, res) => {
  if (req.header('x-admin-secret') !== config.adminTriggerSecret) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const activation = await triggerActivation();
  res.json({ status: 'agent_reset', activation });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  res.status(500).send(`Internal error: ${err.message}`);
});

app.listen(config.port, () => {
  console.log(`killswitch-agent listening on port ${config.port}`);
});
