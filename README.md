# killswitch-agent

A test agent that authenticates via Okta Cross App Access (XAA) and calls an
external killswitch webhook when it attempts an action outside its allowed
policy ("goes rogue").

## Protocol

Implements the [Identity Assertion Authorization Grant](https://datatracker.ietf.org/doc/html/draft-parecki-oauth-identity-assertion-authz-grant)
flow that Okta XAA is built on:

1. `GET /login` → `GET /callback`: standard OIDC Authorization Code login for
   the human user against the **Resource App** (`RESOURCE_APP_CLIENT_ID` /
   `RESOURCE_APP_CLIENT_SECRET`, client_secret_basic) — this is the app the
   user is actually signing into. Yields a user `access_token`.
2. `src/xaa.ts` — `requestIdJag`: RFC 8693 token exchange at
   `{OKTA_ORG_URL}/oauth2/v1/token`, trading the user's access_token for an
   ID-JAG. Here the **Agent** (Requesting App) authenticates itself with a
   signed `client_assertion` (private_key_jwt) built from `AGENT_CLIENT_ID` +
   `AGENT_PRIVATE_KEY_PEM` — the agent never logs the user in directly, it
   only asserts its own identity for this exchange.
3. `src/xaa.ts` — `exchangeIdJagForAccessToken`: RFC 7523 jwt-bearer exchange
   at `RESOURCE_APP_TOKEN_ENDPOINT`, redeeming the ID-JAG for a real access
   token scoped to the resource app. Authenticates again as the **Resource
   App** (`RESOURCE_APP_CLIENT_ID`/`SECRET`) — same client as step 1, since
   it's the resource app's own authorization server issuing this token.
4. `src/resourceClient.ts` calls the resource app's API with that token.

## Setup

1. Copy `config/agent.properties.example` to `config/agent.properties` and
   fill in your Okta org URL, the Requesting App's client ID + private key
   (PKCS8 PEM, matching the public key/JWKS registered against that app in
   Okta), the resource app's token endpoint/client ID, and your existing
   killswitch webhook URL.
2. `npm install`
3. `npm run dev` (runs on `http://localhost:3000` by default)

## Debug page

`GET /debug?key=<ADMIN_TRIGGER_SECRET>` shows every outbound call this agent
has made (Okta login token exchange, ID-JAG request, resource token exchange,
resource API calls) with full request/response bodies, every token captured
(raw + decoded JWT claims), and a small form to fire `POST /agent/act`
without needing curl or cookie-copying.

`GET /callback` redirects here automatically after login (success or
failure), with `?error=...` set if the login token exchange failed — check
this page first if login isn't behaving as expected; it shows Okta's exact
error response instead of a blank page.

## Testing the rogue trigger

1. Visit `/login` in a browser to complete the Okta login — it redirects to
   `/debug` when done, cookie and all, so you don't need to copy anything.
2. From the debug page's "Run an agent action" form, submit `resource.get`
   (allowed) and confirm it succeeds.
3. Submit anything not in `src/policy.ts`'s allow-list (e.g.
   `resource.delete_all`) — the agent reports itself rogue, calls
   `KILLSWITCH_WEBHOOK_URL`, and exits. The form will show a network error on
   the *next* request since the process is gone by then — that's expected.
4. To test the webhook path directly without a policy violation:
   ```
   curl -X POST http://localhost:3000/admin/kill \
     -H 'Content-Type: application/json' \
     -H "x-admin-secret: $ADMIN_TRIGGER_SECRET" \
     -d '{"reason":"manual test"}'
   ```

Edit `ALLOWED_ACTIONS` in `src/policy.ts` to match your actual resource app's
API and the scope you want the agent restricted to.

## Deploying to Render

1. Push this repo and create a service from `render.yaml` (Render Blueprint).
2. In the Render dashboard, set every env var marked `sync: false` in
   `render.yaml` — these hold real Okta credentials/keys and the webhook URL,
   and are never committed to the repo.
3. Set `AGENT_REDIRECT_URI` to `https://<your-service>.onrender.com/callback`
   and register that same redirect URI on the Requesting App in Okta.
