import { randomUUID } from "node:crypto"
import { readFileSync } from "node:fs"
import { ProtocolError, SdkHttpError, SdkErrorCode } from "@modelcontextprotocol/client"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { codingHttpRejection, rejectedCodingReference, CODING_WAIT_MAX_CHECKS, CODING_WAIT_BUDGET_MS } from "../coding-call-recovery.ts"
import { CodingAuthClient } from "../mcp-coding-auth.ts"
import { captureOAuthAuthority, getAuthStorageOptions, resetTestAuthSecretStore } from "../mcp-auth.ts"

vi.mock("node:timers/promises", () => ({ setTimeout: vi.fn(async (_ms, _value, { signal }) => { signal.throwIfAborted() }) }))
const url = "https://broker.example/broker/mcp"
const reference = "coding_test"
const route = `/broker/coding/renew?authorization_ref=${reference}`
const pauseData = { version: 1, status: "authorization_paused", authorization_ref: reference, expires_at: "2000-01-01T00:00:00.000Z",
  revision: 1, status_route: "authorization.status", renewal_requires_human: true, retryable: true, execution: "not_executed", forwarded: false }
const rejection = () => new ProtocolError(-32003, "authorization_paused", pauseData)
const proof = (n = 1) => ({ version: 1 as const, token_type: "Bearer" as const, scope: "profile:coding" as const,
  access_token: `synthetic-access-${n}`, refresh_token: `synthetic-refresh-${n}`, enrollment_token: `synthetic-enrollment-${n}`,
  authorization_ref: reference, expires_at: new Date(Date.now() + 3600_000).toISOString() })
const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } })
function setup() {
  const storage = getAuthStorageOptions(undefined, process.cwd(), "session")
  const config = { version: 1 as const, cohort: randomUUID() }
  const client = new CodingAuthClient("broker", url, config, storage)
  const check = captureOAuthAuthority("broker", true, storage)
  client.install(proof(), check)
  return { client, check, storage, config }
}
const status = (paused = false, expired = false) => json({ version: 1, status: paused ? "authorization_paused" : "active",
  authorization_ref: reference, credential_status: expired ? "expired" : "active", renewal_route: route })

beforeEach(() => { vi.stubEnv("PI_MCP_ADAPTER_TEST_AUTH_STORE", "memory"); resetTestAuthSecretStore() })
afterEach(() => { vi.unstubAllEnvs(); resetTestAuthSecretStore(); vi.restoreAllMocks() })

describe("broker v1 pre-execution contract", () => {
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/coding-authorization-v1.json", import.meta.url), "utf8"))
  it.each(fixture.cases.filter((row: any) => row.error_code))("recognizes only $name when retryable", (row) => {
    expect(rejectedCodingReference(new ProtocolError(row.error_code, row.status, { ...pauseData, ...row })))
      .toBe(row.name === "pause" ? reference : undefined)
  })
  it.each(Object.keys(pauseData))("rejects missing %s", (key) => {
    const data = { ...pauseData }; delete data[key as keyof typeof data]
    expect(rejectedCodingReference(new ProtocolError(-32003, "paused", data))).toBeUndefined()
  })
  it.each([{ version: 2 }, { execution: "unknown" }, { forwarded: true }, { retryable: false }, { status_route: "other" }, { revision: 0 }])("rejects unknown contract %j", (change) => {
    expect(rejectedCodingReference(new ProtocolError(-32003, "paused", { ...pauseData, ...change }))).toBeUndefined()
  })
  it("correlates HTTP rejection with the exact tools/call request", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "nexus.get_task" } })
    const payload = { jsonrpc: "2.0", id: 7, error: { code: -32003, message: "paused", data: pauseData } }
    expect(rejectedCodingReference(await codingHttpRejection(json(payload, 403), body))).toBe(reference)
    for (const changed of [{ ...payload, id: 8 }, { ...payload, result: {} }, { error: payload.error }]) {
      expect(await codingHttpRejection(json(changed, 403), body)).toBeUndefined()
    }
    expect(await codingHttpRejection(json(payload, 500), body)).toBeUndefined()
    expect(await codingHttpRejection(json(payload, 403), body.replace("tools/call", "resources/read"))).toBeUndefined()
  })
})

describe("pending coding invocation", () => {
  it("retains original arguments and executes upstream once after renewal and replacement", async () => {
    const { client, check } = setup()
    let checks = 0, upstream = 0
    const args = { task: 123 }
    const fetcher = vi.fn(async (input: any) => String(input).endsWith("/replace") ? json(proof(2)) : status(++checks < 3, true))
    const call = vi.fn(async () => { if (!checks) throw rejection(); upstream++; return args })
    const notify = vi.fn()
    expect(await client.runPending(call, fetcher, { check, notify })).toBe(args)
    expect(call).toHaveBeenCalledTimes(2)
    expect(upstream).toBe(1)
    expect(fetcher.mock.calls.map(row => new URL(String(row[0])).pathname)).toEqual([
      "/broker/coding/status", "/broker/coding/status", "/broker/coding/status", "/broker/coding/replace",
    ])
    expect(notify).toHaveBeenCalledTimes(1)
  })
  it("recovers a typed status preflight pause without first dispatching", async () => {
    const { client, check } = setup()
    let polls = 0, upstream = 0
    const fetcher = vi.fn(async () => status(++polls < 3))
    const call = vi.fn(async () => { await client.tokens(fetcher, check); upstream++; return "ok" })
    expect(await client.runPending(call, fetcher, { check })).toBe("ok")
    expect(upstream).toBe(1)
  })
  it.each([
    new Error("authorization_paused not_executed"), new Error("disconnected"), new DOMException("timeout", "TimeoutError"),
    new ProtocolError(-32003, "denied", { ...pauseData, status: "policy_denied" }),
    new ProtocolError(-32003, "paused", { ...pauseData, version: 2 }),
    new ProtocolError(-32003, "paused", { ...pauseData, authorization_ref: "other" }),
    new SdkHttpError(SdkErrorCode.ClientHttpNotImplemented, "upstream", { status: 503 }),
  ])("never retries ambiguous or ordinary failures (%s)", async (failure) => {
    const { client, check } = setup()
    const call = vi.fn(async () => { throw failure }), fetcher = vi.fn()
    await expect(client.runPending(call, fetcher, { check })).rejects.toBe(failure)
    expect(call).toHaveBeenCalledTimes(1); expect(fetcher).not.toHaveBeenCalled()
  })
  it("does not promote an unversioned credential error to automatic waiting", async () => {
    const { client, check } = setup(), fetcher = vi.fn(async () => json({ error: "authorization_paused" }, 403)), notify = vi.fn()
    const call = vi.fn(() => client.tokens(fetcher, check))
    await expect(client.runPending(call, fetcher, { check, notify })).rejects.toThrow(/human renewal/)
    expect(call).toHaveBeenCalledTimes(1); expect(fetcher).toHaveBeenCalledTimes(1); expect(notify).not.toHaveBeenCalled()
  })
  it("returns ordinary tool errors without retry", async () => {
    const { client, check } = setup(), result = { isError: true, content: [{ text: "authorization_paused" }] }
    const fetcher = vi.fn(), call = vi.fn(async () => result)
    expect(await client.runPending(call, fetcher, { check })).toBe(result)
    expect(call).toHaveBeenCalledTimes(1); expect(fetcher).not.toHaveBeenCalled()
  })
  it("does not replay an ambiguous retry failure", async () => {
    const { client, check } = setup(), lost = new Error("lost reply")
    const call = vi.fn().mockRejectedValueOnce(rejection()).mockRejectedValue(lost)
    await expect(client.runPending(call, async () => status(), { check })).rejects.toBe(lost)
    expect(call).toHaveBeenCalledTimes(2)
  })
  it("exhausts a bounded request budget and preserves manual fallback guidance", async () => {
    const { client, check } = setup(), fetcher = vi.fn(async () => status(true)), call = vi.fn(async () => { throw rejection() })
    await expect(client.runPending(call, fetcher, { check })).rejects.toThrow(/manually continue.*original tool and arguments/)
    expect(fetcher).toHaveBeenCalledTimes(CODING_WAIT_MAX_CHECKS); expect(call).toHaveBeenCalledTimes(1)
  })
  it("ends the wall-clock budget even when a status transport ignores cancellation", async () => {
    const { client, check } = setup(), deadline = new AbortController()
    const nativeTimeout = AbortSignal.timeout.bind(AbortSignal)
    vi.spyOn(AbortSignal, "timeout").mockImplementation(ms => ms === CODING_WAIT_BUDGET_MS ? deadline.signal : nativeTimeout(ms))
    let release!: (value: Response) => void
    const fetcher = vi.fn(() => new Promise<Response>(resolve => { release = resolve }))
    const call = vi.fn(async () => { throw rejection() })
    const pending = client.runPending(call, fetcher, { check })
    const result = expect(pending).rejects.toThrow(/wait ended.*manually continue/)
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1))
    deadline.abort(new DOMException("Timed out", "TimeoutError")); await result
    release(status()); await Promise.resolve()
    expect(call).toHaveBeenCalledTimes(1)
  })
  it("never repeats a replacement with an ambiguous lost response", async () => {
    const { client, check } = setup()
    const fetcher = vi.fn(async (input: any) => {
      if (String(input).endsWith("/replace")) throw new Error("lost replacement response")
      return status(false, true)
    })
    const call = vi.fn(async () => { throw rejection() })
    await expect(client.runPending(call, fetcher, { check })).rejects.toThrow(/do not replay a credential rotation/)
    expect(fetcher).toHaveBeenCalledTimes(2); expect(call).toHaveBeenCalledTimes(1)
  })
  it.each(["cancel", "logout", "consent", "config", "config-roundtrip", "revoke", "unknown", "disconnected"])("fences %s during a late status response", async (action) => {
    const { client, check, storage, config } = setup(), controller = new AbortController()
    let release!: (value: Response) => void
    const fetcher = vi.fn(() => new Promise<Response>(resolve => { release = resolve }))
    const call = vi.fn(async () => { throw rejection() })
    const pending = client.runPending(call, fetcher, { check, signal: controller.signal })
    const result = expect(pending).rejects.toBeInstanceOf(Error)
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1))
    if (action === "cancel") controller.abort()
    if (action === "logout") client.logout()
    if (action === "consent") client.install(proof(9), check)
    if (action === "config" || action === "config-roundtrip") new CodingAuthClient("broker", url, { version: 1, cohort: "other" }, storage)
    if (action === "config-roundtrip") new CodingAuthClient("broker", url, config, storage)
    release(action === "revoke" ? json({ error: "invalid_grant" }, 400)
      : action === "unknown" ? json({ version: 2 }) : action === "disconnected" ? json({}, 503) : status())
    await result
    expect(call).toHaveBeenCalledTimes(1)
  })
  it("serializes siblings, including cancellation of a queued caller", async () => {
    const { client, check } = setup()
    let release!: () => void
    const first = client.runPending(() => new Promise<void>(resolve => { release = resolve }), vi.fn(), { check })
    const cancel = new AbortController(), secondCall = vi.fn(), thirdCall = vi.fn(async () => "third")
    const second = client.runPending(secondCall, vi.fn(), { check, signal: cancel.signal })
    const rejected = expect(second).rejects.toBeInstanceOf(Error)
    cancel.abort(); await rejected
    const third = client.runPending(thirdCall, vi.fn(), { check })
    await Promise.resolve(); expect(thirdCall).not.toHaveBeenCalled()
    release(); await first; expect(await third).toBe("third"); expect(secondCall).not.toHaveBeenCalled()
  })
})
