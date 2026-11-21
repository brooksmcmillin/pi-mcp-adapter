import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { setTimeout as sleep } from "node:timers/promises"

vi.mock("node:timers/promises", () => ({ setTimeout: vi.fn(async (_ms, _value, { signal }) => { signal.throwIfAborted() }) }))
import { randomUUID } from "node:crypto"
import { CodingAuthClient, CodingRequestError } from "../mcp-coding-auth.ts"
import { getAuthStorageOptions } from "../mcp-auth.ts"

const url = "https://broker.example/broker/mcp"
const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), { status })
const status = { version: 1, status: "active", authorization_ref: "test", credential_status: "active", renewal_route: "/broker/coding/renew?authorization_ref=test" }
function client(cohort?: string) {
  const coding = new CodingAuthClient("broker", url, { version: 1, cohort: cohort ?? randomUUID() }, getAuthStorageOptions(undefined, process.cwd(), "session"))
  coding.install({ version: 1, token_type: "Bearer", scope: "profile:coding", authorization_ref: "test",
    access_token: "secret-access", refresh_token: "secret-refresh", enrollment_token: "secret-enrollment",
    expires_at: new Date(Date.now() + 3600_000).toISOString(), ...(cohort ? { cohort_credential: "secret-cohort" } : {}) }, () => {})
  return coding
}
beforeEach(() => {
  vi.mocked(sleep).mockReset().mockImplementation(async (_ms, _value, options) => { options?.signal?.throwIfAborted() })
  vi.spyOn(Math, "random").mockReturnValue(0)
})
afterEach(() => vi.restoreAllMocks())

describe("coding request diagnostics and bounded recovery", () => {
  it.each(["network", "invalid_response", "http"])("recovers transient status %s without rotating or replaying a tool", async failure => {
    const coding = client()
    const fetchFn = vi.fn(async () => json(status))
    fetchFn.mockImplementationOnce(async () => {
      if (failure === "network") throw new Error("secret-enrollment")
      if (failure === "invalid_response") return new Response("secret-enrollment")
      return json({ error: "secret-enrollment" }, 503)
    })
    expect((await coding.tokens(fetchFn, () => {}))?.accessToken).toBe("secret-access")
    expect(fetchFn).toHaveBeenCalledTimes(2)
    expect(sleep).toHaveBeenCalledExactlyOnceWith(1000, undefined, { signal: expect.any(AbortSignal) })
    for (const [input] of fetchFn.mock.calls as unknown as [string][]) expect(input).toBe("https://broker.example/broker/coding/status")
  })

  it.each(["network", "invalid_response", "http"])("reports persistent status %s with bounded sanitized details", async failure => {
    const fetchFn = vi.fn(async () => {
      if (failure === "network") throw new Error("secret-enrollment")
      if (failure === "invalid_response") return new Response("secret-enrollment")
      return json({ error: "secret-enrollment" }, 502)
    })
    const error = await client().tokens(fetchFn, () => {}).catch(e => e)
    expect(error).toBeInstanceOf(CodingRequestError)
    expect(error).toMatchObject({ operation: "status", failure, attempts: 5, toolDispatch: "unknown" })
    expect(String(error)).toContain("no credential rotation was attempted by this status request")
    expect(JSON.stringify(error) + String(error)).not.toContain("secret-")
    expect(fetchFn).toHaveBeenCalledTimes(5)
    expect(vi.mocked(sleep).mock.calls.map(([ms]) => ms)).toEqual([1000, 2000, 4000, 8000])
  })

  it.each([0, 0.9999])("survives a 13-second restart with bounded jitter %s and a single tool dispatch", async jitter => {
    vi.mocked(Math.random).mockReturnValue(jitter)
    let elapsed = 0
    vi.mocked(sleep).mockImplementation(async ms => { elapsed += Number(ms) })
    const fetchFn = vi.fn(async () => elapsed < 13_000 ? new Response("secret-proxy-body", { status: 502 }) : json(status))
    const tool = vi.fn(async () => "delivered")
    const coding = client()
    await expect(coding.runPending(async () => {
      await coding.tokens(fetchFn, () => {})
      return tool()
    }, fetchFn, { check: () => {} })).resolves.toBe("delivered")
    expect(fetchFn).toHaveBeenCalledTimes(5)
    expect(tool).toHaveBeenCalledTimes(1)
    expect(elapsed).toBeGreaterThanOrEqual(15_000)
    expect(elapsed).toBeLessThan(18_000)
  })

  it("classifies a non-JSON gateway failure as HTTP, not a malformed status response", async () => {
    const fetchFn = vi.fn(async () => new Response("secret-proxy-body", { status: 502 }))
    const error = await client().tokens(fetchFn, () => {}).catch(e => e)
    expect(error).toMatchObject({ operation: "status", failure: "http", httpStatus: 502, attempts: 5 })
    expect(String(error)).toContain("not proof of expired credentials or an upstream tool failure")
    expect(JSON.stringify(error) + String(error)).not.toContain("secret-")
  })

  it("does not dispatch the tool when status stays unavailable", async () => {
    const coding = client(), tool = vi.fn()
    const fetchFn = vi.fn(async () => new Response("unavailable", { status: 502 }))
    await expect(coding.runPending(async () => {
      await coding.tokens(fetchFn, () => {})
      return tool()
    }, fetchFn, { check: () => {} })).rejects.toMatchObject({ attempts: 5 })
    expect(tool).not.toHaveBeenCalled()
  })

  it.each([401, 403, 429])("does not retry status HTTP %i or infer revoked consent", async code => {
    const fetchFn = vi.fn(async () => json({ error: "unrecognized" }, code))
    await expect(client().tokens(fetchFn, () => {})).rejects.toMatchObject({ operation: "status", failure: "http", httpStatus: code, attempts: 1 })
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("preserves terminal consent rejection and does not retry it", async () => {
    const coding = client(), fetchFn = vi.fn(async () => json({ error: "invalid_grant" }, 403))
    await expect(coding.tokens(fetchFn, () => {})).rejects.toThrow(/fresh human consent/)
    await expect(coding.tokens(fetchFn, () => {})).rejects.toThrow(/fresh human consent/)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("does not retry a paused authorization", async () => {
    const fetchFn = vi.fn(async () => json({ error: "authorization_paused" }, 403))
    await expect(client().tokens(fetchFn, () => {})).rejects.toThrow(/paused/)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it.each(["network", "invalid_response", "http"])("never retries ambiguous replacement %s", async failure => {
    const coding = client(), routes: string[] = []
    const fetchFn = vi.fn(async (input: string | URL | Request) => {
      routes.push(String(input))
      if (String(input).endsWith("/status")) return json({ ...status, credential_status: "expired" })
      if (failure === "network") throw new Error("secret-refresh")
      if (failure === "invalid_response") return new Response("secret-refresh")
      return json({ error: "secret-refresh" }, 503)
    })
    const error = await coding.tokens(fetchFn, () => {}).catch(e => e)
    expect(error).toMatchObject({ operation: "replace", failure, attempts: 1, toolDispatch: "unknown" })
    expect(String(error)).toContain("do not replay a credential rotation")
    expect(JSON.stringify(error) + String(error)).not.toContain("secret-")
    expect(routes.map(r => r.split("/").pop())).toEqual(["status", "replace"])
  })

  it("never retries ambiguous enrollment", async () => {
    const cohort = randomUUID()
    client(cohort)
    const coding = new CodingAuthClient("broker", url, { version: 1, cohort }, getAuthStorageOptions(undefined, process.cwd(), "session"))
    const fetchFn = vi.fn(async () => new Response("secret-proxy-body", { status: 502 }))
    await expect(coding.tokens(fetchFn, () => {})).rejects.toMatchObject({ operation: "enroll", failure: "http", attempts: 1 })
    expect(fetchFn).toHaveBeenCalledExactlyOnceWith("https://broker.example/broker/coding/enroll", expect.anything())
    expect(sleep).not.toHaveBeenCalled()
  })

  it("reports timeout without extending the 30-second request budget", async () => {
    const coding = client()
    const timeout = new AbortController()
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(timeout.signal)
    const fetchFn = vi.fn(async () => {
      timeout.abort(new DOMException("secret-enrollment", "TimeoutError"))
      throw timeout.signal.reason
    })
    await expect(coding.tokens(fetchFn, () => {})).rejects.toMatchObject({ operation: "status", failure: "timeout", attempts: 1 })
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("shares one 30000ms deadline across status attempts", async () => {
    const coding = client(), deadline = new AbortController()
    const timeout = vi.spyOn(AbortSignal, "timeout").mockReturnValue(deadline.signal)
    const signals: (AbortSignal | null | undefined)[] = []
    const fetchFn = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      signals.push(init?.signal)
      if (signals.length === 1) throw new Error("transient network failure")
      deadline.abort(new DOMException("Timed out", "TimeoutError"))
      throw deadline.signal.reason
    })
    await expect(coding.tokens(fetchFn, () => {})).rejects.toMatchObject({ operation: "status", failure: "timeout", attempts: 2 })
    expect(timeout).toHaveBeenCalledExactlyOnceWith(30000)
    expect(fetchFn).toHaveBeenCalledTimes(2)
    expect(signals[0]).toBe(signals[1])
    expect(signals[1]?.aborted).toBe(true)
  })

  it("stops when the shared deadline expires during backoff", async () => {
    const deadline = new AbortController()
    vi.spyOn(AbortSignal, "timeout").mockReturnValue(deadline.signal)
    vi.mocked(sleep).mockImplementation(async () => {
      deadline.abort(new DOMException("secret-timeout", "TimeoutError"))
      throw deadline.signal.reason
    })
    const fetchFn = vi.fn(async () => new Response("unavailable", { status: 502 }))
    const error = await client().tokens(fetchFn, () => {}).catch(e => e)
    expect(error).toMatchObject({ operation: "status", failure: "timeout", attempts: 1 })
    expect(String(error)).not.toContain("secret-")
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("honors cancellation during backoff without a later status request", async () => {
    const controller = new AbortController()
    vi.mocked(sleep).mockImplementation(async (_ms, _value, options) => {
      controller.abort()
      options?.signal?.throwIfAborted()
    })
    const fetchFn = vi.fn(async () => new Response("unavailable", { status: 502 }))
    await expect(client().tokens(fetchFn, () => {}, controller.signal)).rejects.toThrow(/abort/i)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("rechecks local authority after backoff before sending another request", async () => {
    const coding = client()
    vi.mocked(sleep).mockImplementation(async () => { coding.logout() })
    const fetchFn = vi.fn(async () => new Response("unavailable", { status: 502 }))
    await expect(coding.tokens(fetchFn, () => {})).rejects.toThrow(/fresh human consent/)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })

  it("honors cancellation before a second status attempt", async () => {
    const controller = new AbortController()
    const fetchFn = vi.fn(async () => { controller.abort(); throw new Error("network") })
    await expect(client().tokens(fetchFn, () => {}, controller.signal)).rejects.toThrow(/abort/i)
    expect(fetchFn).toHaveBeenCalledTimes(1)
  })
})
