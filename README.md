# webengage-mcp-oauth-prototype

A standalone Spring Boot app that implements just enough of MCP OAuth 2.1 - authorization
code + PKCE, resource binding, pre-registered *and* CIMD client resolution, a minimal `/mcp`
server with two fake tools - to validate protocol behavior against **real Claude and ChatGPT
connectors** before porting the design into the WebEngage Struts monolith
(`MCP_OAUTH_IMPLEMENTATION.md`).

This is a throwaway test harness, not a reference implementation to copy wholesale: it runs
the authorization server and the MCP resource server in one process for convenience (the real
WebEngage deployment splits them into two repos), stores everything in memory, and uses a fake
login/consent screen instead of real WebEngage auth. The OAuth *mechanics* - PKCE, exact
redirect validation, atomic code consumption, CIMD fetch/validate, standards-shaped token
responses, scope enforcement - are built the same way they'd need to work for real.

## What's simplified vs. the real WebEngage build

- AS and RS are one process, one deployable unit.
- Fake login (a text field, not real WebEngage auth) and two hardcoded fake publishers.
- In-memory storage only - restarting the app clears every client, code, and token.
- Refresh tokens are non-rotating (no rotation/reuse-detection) - see
  `RefreshToken.java` for why, and the "reconsider no-refresh-tokens" note this prototype
  exists partly to test.
- Client-secret comparison is a plain `.equals()`, not hashed - fine for a throwaway app,
  not something to carry into the real repo (which already has this flagged as deferred work).
- The CIMD SSRF guard has a known DNS-rebinding gap (documented in
  `ClientMetadataFetcher.java`) - acceptable for validating protocol behavior, not for a
  production authorization server.

## Run it locally

```bash
mvn spring-boot:run
```

The app listens on `:8080` by default (override with `--server.port=` or `$PORT`). On
startup it registers two pre-registered test clients from `application.yml`:

| client_id | for | redirect_uri |
|---|---|---|
| `claude-test-client` | manual-credential test against Claude | `https://claude.ai/api/mcp/auth_callback` (confirmed from Anthropic's docs) |
| `chatgpt-test-client` | manual-credential test against ChatGPT | placeholder - **fill in from ChatGPT's own Advanced Settings screen before testing this path** |

Sanity-check the endpoints:

```bash
curl -s http://localhost:8080/.well-known/oauth-authorization-server | python3 -m json.tool
curl -s http://localhost:8080/.well-known/oauth-protected-resource/mcp | python3 -m json.tool
curl -i -X POST http://localhost:8080/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
# expect: 401 with WWW-Authenticate: Bearer resource_metadata="..."
```

A full manual PKCE round-trip (authorize -> consent -> token -> authenticated tool call),
plus the negative cases (replayed code, wrong verifier, unknown client, bad redirect_uri,
implicit flow, non-HTTPS CIMD client_id, insufficient_scope), is exactly what was used to
validate this build before deployment. Ask for the test script if you want to re-run it
against a fresh instance - it's a single Python file with no dependencies beyond the
standard library.

## Deploy so Claude/ChatGPT's cloud infrastructure can reach it

Claude and ChatGPT connect from their own infrastructure, not your machine - `localhost`
won't work. Deploying with Docker to a small host (e.g. Render) was the option chosen for
this round:

1. Push this directory to a new GitHub repo (`git init` has already been run locally; create
   the remote yourself - I'm not going to create GitHub repos or push on your behalf).
2. On Render: **New > Web Service**, connect the repo, runtime **Docker** (auto-detected from
   the `Dockerfile`), instance type can start on the free tier.
3. Set environment variables before the first deploy:
   - `OAUTH_ISSUER` = `https://<your-service>.onrender.com`
   - `MCP_RESOURCE` = `https://<your-service>.onrender.com/mcp`
   - `CLAUDE_CLIENT_SECRET` / `CHATGPT_CLIENT_SECRET` = pick real secret values (defaults in
     `application.yml` are placeholders, fine for a private test but don't leave them if
     anyone else could reach this URL)
4. Deploy, then re-run the curl checks above against the real HTTPS URL.

**Cold-start warning:** Render's free tier spins the service down after inactivity, and a
cold JVM start can take well past Claude's documented timeouts (10s for discovery/
registration/token calls, 30s for refresh - see `MCP_OAUTH_IMPLEMENTATION.md`). If a
connector setup attempt fails with something that looks like a timeout rather than a real
protocol error, hit the service's own URL once yourself to warm it up, then retry the
connector setup immediately after. If this becomes a recurring nuisance, move to a paid
instance rather than debugging phantom "bugs" that are actually cold starts.

## Testing against Claude

Claude.ai / Desktop -> **Settings > Connectors > Add custom connector**, enter your deployed
MCP URL (`https://<your-service>.onrender.com/mcp`).

- **To exercise the manual pre-registered-client path:** in Advanced Settings, paste
  `client_id=claude-test-client` and the `CLAUDE_CLIENT_SECRET` value you set at deploy time.
- **To exercise CIMD:** leave the Client ID/Secret fields blank. Per Claude's own client-
  selection priority, since our AS metadata advertises both `client_id_metadata_document_
  supported: true` and `"none"` in `token_endpoint_auth_methods_supported`, Claude should
  fetch and self-identify via its own hosted CIMD document rather than asking you for
  credentials - this is the real end-to-end test of `ClientMetadataFetcher`.

Either way you should land on this app's fake consent screen, approve, and see the connector
report "search_campaigns_with_stats" and "get_channel_integration_status" as available tools.

## Testing against ChatGPT

ChatGPT (web) -> **Settings > Apps > Advanced settings > Developer mode** (Plus/Pro/
Business/Enterprise/Education only), then add the same MCP URL. ChatGPT supports the
equivalent CIMD / DCR / predefined-client set, but I couldn't independently confirm its exact
redirect URI or per-org-vs-per-user credential semantics from public docs the way I could for
Claude - check what its Advanced Settings screen shows or asks for when you get here, and
update `chatgpt-test-client`'s `redirect-uri` in `application.yml` accordingly before testing
the manual-client path. The CIMD path doesn't depend on knowing that value ahead of time.

## What to watch for during real testing

- Does the flow complete at all, end to end, for each platform?
- Which client-registration path does each platform actually pick (manual vs. CIMD) when
  given the choice?
- Does Claude's proactive/reactive refresh behavior work the way its docs describe once a
  real client is driving it, and does anything break without a refresh token if you disable
  `webengage.oauth.refresh-token-enabled`?
- Any WWW-Authenticate / metadata shape the real client is pickier about than the spec text
  suggested.

Feed whatever breaks back into `MCP_OAUTH_IMPLEMENTATION.md` before starting the real
WebEngage-repo implementation - that's the whole point of testing here first.
