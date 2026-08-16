import crypto from 'node:crypto';
import express from 'express';
import session from 'express-session';
import { config } from './config';
import { buildAuthorizeUrl, exchangeCodeForToken } from './oidc';
import { getResourceAccessToken, testXaaLogin } from './xaa';
import { callResourceApi } from './resourceClient';
import { evaluate } from './policy';
import { triggerKillswitch, triggerActivation } from './killswitch';
import { renderDebugPage, renderDebugFragments } from './debugPage';
import { derivePublicJwk } from './publicKeyInfo';
import { getAgentStoppedState } from './agentState';

const app = express();
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

app.get('/login', (req, res) => {
  const state = crypto.randomUUID();
  req.session.oauthState = state;
  res.redirect(buildAuthorizeUrl(state));
});

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const debugUrl = `/debug?key=${encodeURIComponent(config.adminTriggerSecret)}`;

  if (typeof code !== 'string' || state !== req.session.oauthState) {
    return res.redirect(`${debugUrl}&error=${encodeURIComponent('Invalid or expired login callback (state mismatch or missing code)')}`);
  }

  try {
    const { accessToken } = await exchangeCodeForToken(code);
    req.session.userAccessToken = accessToken;
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
  const stopped = getAgentStoppedState();
  if (stopped) {
    return res.status(403).json({ error: 'agent_stopped', message: 'This agent has been stopped.', ...stopped });
  }

  const userAccessToken = req.session.userAccessToken;
  if (!userAccessToken) {
    return res.status(401).json({ error: 'not_logged_in' });
  }

  try {
    const accessToken = await testXaaLogin(userAccessToken);
    res.json({ status: 'ok', resourceAccessToken: accessToken });
  } catch (err) {
    res.status(502).json({ error: 'xaa_exchange_failed', detail: (err as Error).message });
  }
});

app.post('/agent/act', async (req, res) => {
  const stopped = getAgentStoppedState();
  if (stopped) {
    return res.status(403).json({ error: 'agent_stopped', message: 'This agent has been stopped.', ...stopped });
  }

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
    const accessToken = await getResourceAccessToken(userAccessToken);
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
