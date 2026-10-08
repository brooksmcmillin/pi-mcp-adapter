# Pending coding-call recovery

Opt-in `oauth.codingEnrollment` v1 providers can retain a pending tool invocation
across one shared human renewal. The adapter holds the original promise and
arguments in memory, outside repeated model turns. Proxy, namespace and direct
tool routes use the same recovery boundary; ordinary providers, resources,
initial connection failures and completed/idle turns are unchanged.

## Safe retry boundary

Only broker JSON-RPC `-32003` errors with the complete v1 pause contract qualify:
`status: authorization_paused`, `execution: not_executed`, `forwarded: false`,
`retryable: true`, the bound authorization reference, expiry/revision, and the
expected human-renewal/status guidance. HTTP 403 envelopes must match the exact
outgoing `tools/call` ID. No error-text matching or arbitrary tool-error results.
The SDK's validated v1 credential-status preflight can also pause: it runs before
tool dispatch. Unversioned credential errors retain manual guidance only.

After current status becomes active, the existing credential client recovers
this launch's credentials, then the original call is retried **once**. Lost
replacement responses, timeouts, disconnected/ambiguous execution, upstream
errors, ordinary denials, revocation and unknown versions do not trigger replay.
The guarantee is one upstream invocation when the first attempt was definitively
rejected, not exactly-once delivery under arbitrary network failure.

## Budgets and lifecycle

- One serialized tool invocation per coding launch; different sessions remain
  independent. A queued invocation waits at most five minutes before dispatch.
- After a definitive pause: at most five minutes and 40 status checks, whichever
  ends first. Check immediately, then jittered exponential polling: 1 second
  multiplied by 1.6, capped at 10 seconds, with ±20% jitter (maximum 12 seconds).
- Each status/replacement HTTP request has the existing 30-second limit, further
  bounded by the wait deadline. At most one replacement follows active status.
  Initial SDK preflight, original invocation and single retry retain their
  existing request deadlines; those are separate from the renewal budget.
- The queue and renewal budgets are separate: at most ten minutes of queue/wait
  time for a queued call, plus the normal bounded SDK requests.
- A UI notification exposes the waiting state and non-secret renewal URL.
  No notification subscription is required: each poll reads current authoritative
  status, so missed events cannot strand a pending call. A terminated MCP session
  still uses the existing narrow 404 recovery; its new SDK credential preflight
  rechecks current status before dispatch.
- Tool cancellation, runtime shutdown/reload, connection/configuration replacement,
  logout, fresh consent and revocation fence old pending operations. Explicit
  connection replacement cancels rather than transferring an old operation to an
  unrelated connection. A new/manual invocation checks status afresh.
- Budget exhaustion reports manual continue guidance. The original tool and
  arguments remain in the conversation; no background retry survives. Cancellation
  discards the in-memory pending operation. Process exit never persists a replay
  queue, credentials or tool arguments.

## Verification

The rejection fixture is copied byte-for-byte from
`brooksmcmillin/infra@1780b3e1901058725edc962c05aa949b017a065f:scripts/tests/fixtures/coding-authorization-v1.json`.
The enrollment fixture/API remains the prerequisite documented in
[coding enrollment smoke](coding-enrollment-smoke.md).

```bash
npm ci --ignore-scripts
npx vitest run __tests__/coding-call-recovery.test.ts \
  __tests__/mcp-coding-auth.test.ts __tests__/server-manager-http-auth.test.ts
npm run typecheck
CODING_BROKER_INFRA=/absolute/path/to/trusted/infra \
  node --import tsx __tests__/coding-call-recovery-smoke.mjs
```

The controlled smoke uses 20 independent session stores, OAuth runtimes and real
MCP SDK/manager clients in one Node process. A loopback-only fixture imports the
real broker authority, status, renewal and enforcement handlers from the trusted
infra checkout. Initial consent is simulated with synthetic authority; one
browser-bound renewal uses a synthetic TOTP. Downstream results are synthetic,
but counters increment only after the actual gateway admits each operation.
Nothing touches production credentials, deployed Pi sessions or live providers.

Observed locally with broker `1780b3e1901058725edc962c05aa949b017a065f`, adapter
base `9702e8e` plus these changes, Pi dependency 1.0.0 and MCP SDK 2.0.0:
20 clients, 18 pending calls, 17 automatically resumed, one cancelled in 1 ms,
one renewal, one real HTTP rejection (the others paused in SDK preflight), zero
idle/finished turn resurrection; every successful pending operation forwarded
exactly once. Total 1,716 ms. The existing four-process enrollment smoke also
passed: expired credentials recovered and the revoked session remained denied.
These are local controlled results, not installed-version or deployment claims.
