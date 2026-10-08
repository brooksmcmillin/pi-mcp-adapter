# Controlled coding enrollment smoke

Task: https://nexus.brooksmcmillin.com/task/7335

This is a local synthetic benchmark, not live installation or deployment proof.
The driver launches four separate Node/adapter processes sharing **only** an
encrypted cohort-proof entry in a temporary directory. Each process owns its own
session credential store and runtime. The broker fixture imports the trusted
infra checkout's actual `broker_oauth.coding_credentials`, browser renewal
handlers, `coding_authorization` store and gateway enforcement. It binds only
loopback; all data, TOTP material, credentials and policy are synthetic and
removed on exit. No production services or real secret stores are touched.

Initial human consent is simulated by the fixture's trusted store API; the unit
tests separately exercise the real MCP SDK PKCE code exchange and capture of
its v1 credential response. Renewal exercises the real browser-bound GET/POST
form with an ephemeral provisioned TOTP. The driver performs that **one**
simulated human renewal, then manually continues each independent process;
none initiates an individual OAuth prompt. Synthetic downstream results are
returned only after the real gateway admits the call.

## Commands

From this adapter worktree, with a trusted API-v1 infra checkout and its `uv`
dependencies available:

```bash
npm ci --ignore-scripts
PI_MCP_ADAPTER_TEST_AUTH_STORE=memory npm test -- \
  __tests__/mcp-coding-auth.test.ts __tests__/server-manager-http-auth.test.ts \
  __tests__/mcp-device-auth.test.ts __tests__/mcp-auth-storage.test.ts
npm run typecheck
CODING_BROKER_INFRA=/absolute/path/to/infra \
  node --import tsx __tests__/coding-enrollment-smoke.mjs
```

The driver emits only outcome counts, hashes for internal comparisons (not in
the report), revisions and elapsed time. Never run the fixture as a deployed
service: its `/__test/*` control routes are deliberately test-only. It uses the
existing externally keyed encrypted backend, not the unit-test memory backend.

## Observed result

2026-10-08 UTC: adapter base `9ccec7833517e1afdb14ce90bd34f512b4d9b8da`
(5.0.0 plus this task's changes), broker
`d1db89ea63bcca6df5e16861092ee2550480363f`, Pi dependency 1.0.0,
MCP client/core 2.0.0. The run passed in 1,257 ms:

- Four distinct access and refresh credentials across four independent processes.
- Three eligible processes paused with identical non-secret renewal guidance.
- Exactly one browser/TOTP renewal; all three continued without OAuth prompts.
- Idle-expired and absolute-expired old bearer credentials were independently replaced.
- The explicitly revoked fourth session remained denied.
- An extra grant was allowed before expiry, then denied after expiry/renewal/replacement;
  the ordinary coding baseline remained allowed.

The smoke is an explicit local command, not a CI claim. CI runs the coding unit
and transport-consumer regression files through its unrestricted Vitest test
selection. No launcher flags, live Pi version installation, automatic tool
replay, or broker implementation changes belong to this delivery.

## Lifecycle and consumer map

| Transition | Producer → consumer | State / authority | Verification |
| --- | --- | --- | --- |
| Startup | Human PKCE response → OAuth provider → private cohort store | URL/slot selects proof; human approval alone grants authority | SDK code exchange and URL/slot isolation regressions; cohort enrollment smoke |
| Pause | Broker coding status → provider/transport/auth helpers | Enrollment proof works without a live bearer; only curated renewal route is shown | Common-route pause tests; multi-process pause smoke |
| Continue | Human renewal → status → per-launch replacement | Both enrollment/refresh proofs rotate atomically; per-launch queue and installation fence | Concurrency, SDK-context/Request-input/omitted-definition public reads, stale-install and idle/absolute expiry tests |
| Reload | Host-owned weak registry → new provider/runtime | Completed session proofs retained; old runtime work cannot install late | Module-reload, retained identity/URL-slot rebinding and cohort-backend selection regressions; existing host-session tests |
| Logout/cancel | Revocation generation / runtime signal → pending rotation | No late install, no terminal-proof fallback to cohort enrollment | Logout, abort and deactivation regressions |
| Replay | Lost replacement response → later status | No idempotent retrieval promise; consumed proof is terminal | Consumed-response-loss/no-replay and terminal no-fallback regressions |

Real cross-origin redirect regressions cover coding proof requests and both URL
and `Request` forms of the initial code exchange, with zero target requests.

Immediate consumers: `McpOAuthProvider`, `getValidToken`/`startAuth`,
`removeAuth`, and server-manager's SDK-owned transport fetch. Public generated
`dist` modules are rebuilt with `npm run build:public`. CI typechecks and tests
all adapter changes; the broker smoke is locally exercised separately because
it requires a trusted sibling infra checkout.
