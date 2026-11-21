# Pending coding-call recovery

Opt-in `oauth.codingEnrollment` v1 providers can retain a pending tool invocation
across one shared human renewal. The adapter holds the original promise and
arguments in memory, outside repeated model turns. Proxy, namespace and direct
tool routes use the same recovery boundary; ordinary providers, resources and
completed/idle turns are unchanged.

## Interactive connection renewal

When a coding connection pauses during startup or reconnect, Pi shows a
cancellable renewal prompt and holds that connection attempt for up to five
minutes. Approve the linked renewal in your browser; Pi recovers credentials,
closes the prompt and retries connection setup once, including tool discovery.
Concurrent connection prompts are serialized so they do not overlap the editor.
New launches with only a cohort proof can also wait: rejected enrollment requests
are checked until human approval allows one successful enrollment. Enrolled
sessions check status before replacing expired credentials. A credential-endpoint
pause can resume connection setup, but does not authorize replaying a tool call.

Escape, shutdown/reload, timeout, revoked proofs or ambiguous credential responses
stop recovery; no background reconnect or rotation replay survives. Noninteractive
connections report manual guidance without polling. After cancellation or timeout,
renew and use `/mcp-adapter reconnect <server>` to try again.

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

## Credential request failures

Credential failures identify `operation=status|enroll|replace`, the failure class
(`network`, `timeout`, `invalid_response`, or `http`), attempt count and HTTP status
when available. Diagnostics never include upstream exception text, response bodies
or credential values. `tool_dispatch=unknown` means the auth layer cannot establish
whether the enclosing MCP call ran; it is not permission to replay a mutation.

A transient read-only status failure gets at most five attempts within the same
30-second deadline (network, malformed JSON, or HTTP 5xx). Between attempts,
backoff is 1, 2, 4 and 8 seconds, each with 0–20% added jitter: 15–18 seconds
of total waiting, plus request time, still bounded by the shared deadline.
Healthy status reads have no added wait. Deadline exhaustion, caller cancellation,
consent rejection, authorization pause and other HTTP errors do not retry.
Non-JSON HTTP errors (such as a gateway's HTML 502) remain `failure=http`, not
`invalid_response`. Enrollment and replacement requests never retry here. Subsequent
credential recovery still checks status before replacement; a consumed, lost
replacement cannot fall back to cohort enrollment.

A status failure does not establish expired credentials, a lost task lease or a
persistent broker outage. Read authoritative task ownership after an uncertain
renewal and distinguish that observation from the failed request. A successful
task read does not prove renewal succeeded. Resume mutations only after the
owning task workflow confirms ownership and safe renewal recovery.

## Budgets and lifecycle

- One serialized tool invocation per coding launch; different sessions remain
  independent. A queued invocation waits at most five minutes before dispatch.
- After a definitive pause: at most five minutes and 40 status checks, whichever
  ends first. Check immediately, then jittered exponential polling: 1 second
  multiplied by 1.6, capped at 10 seconds, with ±20% jitter (maximum 12 seconds).
- Each status check (including all transient attempts and backoff) or replacement
  has the existing 30-second limit, further
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

## Restart incident evidence

For task 8097 on 2026-11-19, the session recorded a status-route HTTP 502 at
00:44:45.758 UTC; both attempts together took 11 ms. The subsequent status check
and task read encountered the same broker failure/backoff, not independently
confirmed Nexus failures. The local `mcp-proxy.service` journal shows:

- 00:44:43 UTC: stopping the broker;
- 00:44:53 UTC: SIGTERM timeout, SIGKILL, then service started;
- 00:44:56 UTC: proxy listening again, with the default upstream authenticated.

This establishes a local broker restart overlapping the failure window, not
expired credentials. The reason for that restart and shutdown timeout was not
established. Correlation used the timestamps and host journal; there was no
request-specific correlation ID in the captured client error. Read the original
bounded journal with:

```bash
journalctl -u mcp-proxy.service --since '2026-11-19 00:44:30 UTC' \
  --until '2026-11-19 00:45:10 UTC' --no-pager -o short-iso
```

Regression coverage models a 13-second unavailable interval at both jitter
bounds, followed by fresh active status and a single tool dispatch. A separate
loopback smoke exercises real timers and HTTP, returning HTML 502 for 13 seconds
before active status. These are controlled tests, not a production restart test
or an end-to-end Nexus invocation. Longer outages can still
exhaust the deadline and need manual continuation. Recovery must reread task
ownership before any new mutation; it must not replay an uncertain prior write.
The existing session-backed closeout evidence keeps unfinished reconciliation
visible after restart; no credential or tool replay queue is added here.

## Verification

The rejection fixture is copied byte-for-byte from
`brooksmcmillin/infra@1780b3e1901058725edc962c05aa949b017a065f:scripts/tests/fixtures/coding-authorization-v1.json`.
The enrollment fixture/API remains the prerequisite documented in
[coding enrollment smoke](coding-enrollment-smoke.md).

```bash
npm ci --ignore-scripts
npx vitest run __tests__/coding-request-errors.test.ts \
  __tests__/coding-call-recovery.test.ts \
  __tests__/mcp-coding-auth.test.ts __tests__/server-manager-http-auth.test.ts \
  __tests__/coding-connection-renewal.test.ts __tests__/init-auto-auth.test.ts
npm run typecheck
node --import tsx __tests__/coding-status-restart-smoke.mjs
CODING_BROKER_INFRA=/absolute/path/to/trusted/infra \
  node --import tsx __tests__/coding-call-recovery-smoke.mjs
```

The restart smoke uses synthetic session-only credentials, five status requests,
no rotation, and one simulated tool dispatch after fresh active status. A local
real-timer run recovered in 16,186 ms. It does not require infra, private credentials,
or restarting any running service.

The broader 20-client smoke currently fails against infra
`8e29270137cf1d87da0dab4c7547e52acc2bc7a2` before exercising recovery: its fixture supplies
`SimpleNamespace(enabled=True)` to `create_grant`, which now requires a
broker-verified human-presence proof (`ApprovalPolicyError`). Do not weaken that
gate to run this fixture. The historical passing result below is not current proof.

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
