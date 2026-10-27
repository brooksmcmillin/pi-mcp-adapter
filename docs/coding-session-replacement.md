# Explicit coding conversation replacement

Task: https://nexus.brooksmcmillin.com/task/7709

`replaceMcpCodingSession` is exported from `pi-mcp-adapter/oauth`. It is a
**host-owned** lifecycle operation, not a model tool or automatic error recovery.
Consume the exact adapter commit recorded in task 7709's delivery/PR handoff;
package version 5.3.2 alone does not identify this API. No launcher integration
or production installation is included here.

## Host contract

Call only for an intentional **new conversation**, using the existing server
name, URL and adapter-owned session storage. The coding binding must already
exist (a coding provider has been constructed). No config key is added:
`settings.oauthPersistence: "session"` and `oauth.codingEnrollment: { version: 1,
cohort: "your-slot" }` remain required. Keep the same storage identity and cleanup
ownership; rotating the launcher label is unnecessary.

```ts
import { replaceMcpCodingSession } from "pi-mcp-adapter/oauth";

// Capture any old cleanup capability before replacement fences its token helpers.
await replaceMcpCodingSession(serverName, serverUrl, {
  authStorageOptions, // the host's existing sessionEntries/session identity
  runtime,           // current OAuth runtime; omit only when using the legacy runtime
  signal,
  retire: async () => {
    // Host-owned, bounded cleanup: disconnect old transports and revoke the old
    // remote session/enrollment using the previously captured cleanup capability.
    // Throw if retirement fails; do not silently claim remote revocation.
    await retireOldConversation();
  },
});
// Complete the conversation switch, then construct fresh providers/connections.
// The successor may share cohort proof, never an access/refresh token or grant.
```

Before awaiting `retire`, the adapter invalidates old OAuth authority (including
captured fetches across module reload), detaches pending sign-in, discards the
old local enrollment and clears this launch's OAuth credentials. It blocks
new providers during retirement. Successful retirement enables a new empty
credential generation. The next normal token read independently enrolls it
using valid cohort authorization; no tools are replayed. Remote revocation is
the host's responsibility: this generic adapter does not invent a cleanup API.

A pre-aborted signal or wrong binding changes nothing. Failure or cancellation
after retirement starts never restores old credentials, never enrolls a
successor and leaves token reads denied. The host may retry **explicitly** after
reconciling cleanup, or perform fresh human sign-in. Callbacks must observe the
host's cancellation signal and use bounded network timeouts; the adapter does
not replay or abandon an in-flight remote cleanup.

Missing cohort proof returns absent tokens and uses normal human sign-in.
Revoked proof returns terminal fresh-consent guidance. Explicit `startAuth`
(interactive sign-in) may then open a new human consent flow; reconnect and token
helpers cannot do so. Failed human consent does not make revoked credentials
usable. The broker remains authoritative for consent, status and revocation.

## Distinct lifecycle boundaries

| Event | Behavior |
| --- | --- |
| Deliberate new conversation | Host invokes replacement, retires the old session, then constructs new providers |
| Reconnect / `/mcp reload` / extension reload / resume | Preserve enrollment and central status gate; never implicitly invoke replacement |
| Logout | Retain existing terminal-denial semantics; not a new independent enrollment |
| External enrollment revocation | Reconnect stays denied; explicit human sign-in or deliberate new-conversation replacement is required |

Unrelated names, other launches' session stores, persistent cohort proof and
non-coding OAuth are not cleared. Old pending rotations, queued calls, token
helper reads and credential installation cannot cross the generation boundary.

## Verification and consumer map

| Transition | Producer → consumer | State/authority | Regression |
| --- | --- | --- | --- |
| Reset | Host → OAuth lifecycle → coding registry | One launch's authority generation retires before async cleanup | Old provider, captured fetch, direct client and module-reload fences |
| Wait | Pending rotation/sign-in/helper → credential storage | Old authority cannot install/read after reset | Late rotation success/failure/cancel; pending helper/provider reads |
| Replacement | Successful host cleanup → next provider/token helper | New independent enrollment under retained cohort proof | Missing/revoked proof, actual SDK human consent, independent credentials |
| Reconnect/reload | Retained binding → new provider/manager | Terminal enrollment remains denied; other launches unaffected | Existing reload/resume/logout tests plus external-revocation regression |
| Replay | Failed cleanup → explicit host retry | No background cleanup, enrollment or tool retry | Failed/cancelled reset remains denied until explicit retry |

Direct consumers are `McpOAuthProvider`, `getValidToken`/public token helpers,
`startAuth`, and server-manager's captured SDK transport fetch. The generic
OAuth authority registry is retained across module reload like the existing
coding registry. Public `dist` consumers are refreshed by `npm run build:public`;
CI typechecks, runs the unit selection and checks generated distribution drift.
The broker-backed fixture is an explicit local command, not a CI/deployment claim:

```sh
npx vitest run __tests__/mcp-coding-auth.test.ts \
  __tests__/coding-call-recovery.test.ts __tests__/coding-connection-renewal.test.ts
npm run typecheck
npm run build:public
CODING_BROKER_INFRA=/absolute/path/to/trusted/infra \
  node --import tsx __tests__/coding-reset-smoke.mjs
```

The loopback fixture imports the real packaged broker authorization/gateway
handlers from `services/mcp-broker`; its synthetic state proves old enrollment
denial, independent successor authentication, no copied extra grant, denial on
unsolicited reconnect after external revocation, and an unaffected second launch.
It uses a temporary encrypted cohort store and synthetic consent, not operator
credentials. Its report records exact broker/adapter revisions and elapsed time;
pre-commit runs name the base SHA and must be bound to the final delivery tree
in the PR verification record. See [enrollment smoke](coding-enrollment-smoke.md)
for the existing multi-process renewal fixture and its proof limitations.
