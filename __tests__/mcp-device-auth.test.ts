import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { readFileSync } from "node:fs"
import { authenticate, createOAuthRuntime, getValidToken, hasPendingAuth, removeAuth, shutdownOAuth, startAuth } from "../mcp-auth-flow.ts"
import { getAuthEntry, getAuthStorageOptions, type AuthStorageOptions } from "../mcp-auth.ts"
import { DEVICE_GRANT } from "../mcp-device-auth.ts"
import { McpOAuthProvider } from "../mcp-oauth-provider.ts"

// Exact snapshot from infra@a391ecb38f73f1997917beb080065587b95156c5:
// scripts/tests/fixtures/broker-device-flow.json (all values are synthetic).
const fixture = JSON.parse(readFileSync(new URL("./fixtures/broker-device-flow.json", import.meta.url), "utf8"))
const mocks = vi.hoisted(() => ({ delays: [] as number[], wait: undefined as undefined | (() => void | Promise<void>), callback: vi.fn() }))
vi.mock("node:timers/promises", () => ({
  setTimeout: async (ms: number, _value: unknown, options: { signal?: AbortSignal }) => {
    options.signal?.throwIfAborted()
    mocks.delays.push(ms)
    vi.setSystemTime(Date.now() + ms)
    await mocks.wait?.()
    options.signal?.throwIfAborted()
  },
}))
vi.mock("../mcp-callback-server.ts", () => ({
  ensureCallbackServer: mocks.callback,
  waitForCallback: vi.fn(), cancelPendingCallback: vi.fn(), stopCallbackServer: vi.fn(),
  stopCallbackServerIfIdle: vi.fn(), releaseCallbackServer: vi.fn(),
}))

const origin = "https://trebby.lan"
const issuer = `${origin}/broker`
const definition = { url: fixture.resource as string, oauth: { grantType: "device_code" as const } }
const json = (payload: unknown, status = 200, headers?: HeadersInit) => new Response(JSON.stringify(payload), {
  status, headers: { "content-type": "application/json", ...headers },
})

type RequestRecord = { path: string; params: URLSearchParams; headers: Headers }
function broker(options: {
  supported?: boolean
  pairing?: Record<string, unknown>
  tokens?: unknown[]
  tokenHook?: (params: URLSearchParams, signal: AbortSignal | null | undefined) => Promise<Response>
} = {}) {
  const requests: RequestRecord[] = []
  let registrations = 0
  const responses = [...(options.tokens ?? [fixture.success])]
  vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    const params = new URLSearchParams(String(init?.body ?? ""))
    requests.push({ path: url.pathname, params, headers: new Headers(init?.headers) })
    if (url.pathname === "/broker/mcp") return json({}, 401, { "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/broker/mcp"` })
    if (url.pathname.includes("oauth-protected-resource")) return json({ resource: fixture.resource, authorization_servers: [issuer] })
    if (url.pathname.includes("oauth-authorization-server")) return json({
      issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`, response_types_supported: ["code"],
      grant_types_supported: options.supported === false ? ["authorization_code", "refresh_token"] : [DEVICE_GRANT, "authorization_code", "refresh_token"],
      ...(options.supported === false ? {} : { device_authorization_endpoint: `${issuer}/device_authorization` }),
      token_endpoint_auth_methods_supported: ["none"], code_challenge_methods_supported: ["S256"],
    })
    if (url.pathname === "/broker/register") {
      const metadata = JSON.parse(String(init?.body))
      return json({ ...metadata, client_id: `launch-${++registrations}`, client_id_issued_at: 1 }, 201)
    }
    if (url.pathname === "/broker/device_authorization" || params.get("grant_type") === DEVICE_GRANT) expect(init?.redirect).toBe("error")
    if (url.pathname === "/broker/device_authorization") return json({
      ...fixture.device_authorization,
      device_code: `${fixture.device_authorization.device_code}-${params.get("client_id")}`,
      ...options.pairing,
    })
    if (url.pathname === "/broker/token") {
      if (options.tokenHook) return options.tokenHook(params, init?.signal)
      const payload = responses.shift() ?? fixture.errors.pending
      return json(payload, typeof payload === "object" && payload !== null && "error" in payload ? 400 : 200)
    }
    throw new Error(`Unexpected synthetic endpoint ${url.pathname}`)
  }))
  return requests
}

let runtime: ReturnType<typeof createOAuthRuntime>
let storage: AuthStorageOptions
beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date("2026-09-30T00:00:00Z"))
  mocks.delays.length = 0
  mocks.wait = undefined
  mocks.callback.mockClear()
  runtime = createOAuthRuntime()
  storage = getAuthStorageOptions(undefined, undefined, "session")
})
afterEach(async () => {
  await shutdownOAuth(runtime)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.useRealTimers()
})
const options = () => ({ runtime, authStorageOptions: storage, onDeviceAuthorization: vi.fn() })

describe("broker device grant contract", () => {
  it("registers device/refresh grants, binds client/resource, honors pending and cumulative slow_down", async () => {
    const requests = broker({ tokens: [fixture.errors.pending, fixture.errors.slow, fixture.errors.slow, fixture.success] })
    const opts = options()
    await expect(authenticate("broker", fixture.resource, definition, opts)).resolves.toBe("authenticated")
    expect(mocks.delays).toEqual([5000, 5000, 10000, 15000])
    expect(mocks.callback).not.toHaveBeenCalled()
    expect(opts.onDeviceAuthorization).toHaveBeenCalledWith({
      verificationUri: fixture.device_authorization.verification_uri, userCode: fixture.device_authorization.user_code,
    }, expect.any(AbortSignal), expect.any(Function))
    const polling = requests.filter(request => request.path === "/broker/token")
    for (const { params } of polling) {
      expect(params.get("grant_type")).toBe(fixture.grant_type)
      expect(params.get("resource")).toBe(fixture.resource)
      expect(params.get("client_id")).toBe("launch-1")
      expect(params.get("device_code")).toBe(`${fixture.device_authorization.device_code}-launch-1`)
    }
    expect(getAuthEntry("broker", storage)?.tokens).toMatchObject({ accessToken: fixture.success.access_token, refreshToken: fixture.success.refresh_token, issuer })
    expect(hasPendingAuth("broker", storage, runtime)).toBe(false)
    const provider = new McpOAuthProvider("other", fixture.resource, { grantType: "device_code" }, { onRedirect: vi.fn() }, storage)
    // SDK refresh selection needs an internal redirect URL, but no listener or
    // redirect URI participates in the device request/registration.
    expect(provider.clientMetadata.grant_types).toEqual([DEVICE_GRANT, "refresh_token"])
    expect(provider.clientMetadata.redirect_uris).toEqual([])
  })

  it.each([fixture.errors.denied, fixture.errors.expired, { error: "invalid_client" }, { error: "invalid_grant" }, { error: "invalid_target" }])("stops on $error without callback/fallback or credentials", async error => {
    broker({ tokens: [error] })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow(error.error)
    expect(mocks.callback).not.toHaveBeenCalled()
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
    expect(hasPendingAuth("broker", storage, runtime)).toBe(false)
  })

  it("falls back to authorization-code only when advertised support is absent", async () => {
    broker({ supported: false })
    const result = await startAuth("broker", fixture.resource, definition, options())
    expect(result.authorizationUrl).toContain("/broker/authorize?")
    expect(result.authorizationUrl).toContain("code_challenge=")
    expect(mocks.callback).toHaveBeenCalledOnce()
    expect(mocks.delays).toEqual([])
  })

  it("keeps the default authorization-code flow even when device support is advertised", async () => {
    broker()
    const result = await startAuth("broker", fixture.resource, { url: fixture.resource }, options())
    expect(result.authorizationUrl).toContain("/broker/authorize?")
    expect(mocks.callback).toHaveBeenCalledOnce()
    expect(mocks.delays).toEqual([])
  })

  it("uses configured issuer metadata with the bound resource", async () => {
    const requests = broker()
    await authenticate("broker", fixture.resource, {
      ...definition, oauth: { ...definition.oauth, authServerMetadataUrl: `${origin}/.well-known/oauth-authorization-server/broker` },
    }, options())
    expect(requests.filter(request => request.path.includes("oauth-protected-resource"))).toHaveLength(0)
    expect(requests.find(request => request.path === "/broker/token")?.params.get("resource")).toBe(fixture.resource)
  })

  it("expires locally before a too-late poll", async () => {
    const requests = broker({ pairing: { expires_in: 12 }, tokens: [fixture.errors.pending, fixture.errors.pending] })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow("expired")
    expect(mocks.delays).toEqual([5000, 5000, 2000])
    expect(requests.filter(request => request.path === "/broker/token")).toHaveLength(2)
  })

  it("caps a longer server lifetime at thirty minutes", async () => {
    const requests = broker({ pairing: { expires_in: 3600, interval: 3600 } })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow("expired")
    expect(mocks.delays).toEqual([30 * 60 * 1000])
    expect(requests.filter(request => request.path === "/broker/token")).toHaveLength(0)
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
  })

  it.each(["fetch", "body"])("expires during outstanding token %s and rejects late success", async boundary => {
    let finish!: (value: any) => void
    let started!: () => void
    const ready = new Promise<void>(resolve => { started = resolve })
    broker({ tokenHook: async () => {
      if (boundary === "fetch") {
        started()
        return new Promise<Response>(resolve => { finish = resolve })
      }
      const response = json(fixture.success)
      vi.spyOn(response, "json").mockImplementation(() => {
        started()
        return new Promise(resolve => { finish = resolve })
      })
      return response
    } })
    const flow = authenticate("broker", fixture.resource, definition, options())
    const expired = expect(flow).rejects.toThrow("expired")
    await ready
    await vi.advanceTimersByTimeAsync(fixture.device_authorization.expires_in * 1000)
    await expired
    finish(boundary === "fetch" ? json(fixture.success) : fixture.success)
    await Promise.resolve()
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
    expect(hasPendingAuth("broker", storage, runtime)).toBe(false)
  })

  it.each([
    { device_code: "SECRET123", user_code: "Code SECRET123" },
    { device_code: "SECRET123", user_code: "SECRET123" },
    { device_code: "SECRET123", verification_uri: `${issuer}/activate?code=SECRET123` },
    { device_code: "SECRET123", verification_uri: `${issuer}/activate?code=%53%45%43%52%45%54%31%32%33` },
    { device_code: "SECRET123", verification_uri: `${issuer}/activate?code=%2553%2545%2543%2552%2545%2554%2531%2532%2533` },
    { verification_uri: `${issuer}/activate?code=%ZZ%53` },
    { device_code: "secret123", verification_uri: "https://SECRET123.example/activate" },
    { device_code: "secret123", verification_uri: "https://%53%45%43%52%45%54%31%32%33.example/activate" },
    { device_code: "127.0.0.1", verification_uri: "https://0x7f000001/activate" },
    { device_code: "xn--bcher-kva", verification_uri: "https://bücher.example/activate" },
  ])("rejects visible secret aliases before callback or console: %j", async pairing => {
    broker({ pairing })
    const callback = vi.fn()
    const log = vi.spyOn(console, "log").mockImplementation(() => {})
    await expect(authenticate("broker", fixture.resource, definition, { ...options(), onDeviceAuthorization: callback })).rejects.toThrow("Invalid device OAuth verification URI")
    expect(callback).not.toHaveBeenCalled()
    await expect(authenticate("broker", fixture.resource, definition, { runtime, authStorageOptions: storage })).rejects.toThrow("Invalid device OAuth verification URI")
    expect(log).not.toHaveBeenCalled()
  })

  it.each(["callback", "console"])("emits the validated canonical display unchanged through %s", async output => {
    broker({ pairing: { verification_uri: "https://TREBBY.lan:443/broker/./activate?tenant=work%20profile" } })
    const callback = vi.fn()
    const log = vi.spyOn(console, "log").mockImplementation(() => {})
    await authenticate("broker", fixture.resource, definition, {
      runtime, authStorageOptions: storage,
      ...(output === "callback" ? { onDeviceAuthorization: callback } : {}),
    })
    const expectedUri = `${issuer}/activate?tenant=work%20profile`
    if (output === "callback") {
      const visible = callback.mock.calls[0][0]
      expect(visible).toEqual({ verificationUri: expectedUri, userCode: fixture.device_authorization.user_code })
      expect(Object.isFrozen(visible)).toBe(true)
      expect(log).not.toHaveBeenCalled()
    } else {
      expect(log).toHaveBeenCalledWith(`MCP Auth: Open ${expectedUri}\nCode: ${fixture.device_authorization.user_code}`)
    }
  })

  it("preserves legitimate URI query data unrelated to the device secret", async () => {
    broker({ pairing: { verification_uri: `${issuer}/activate?tenant=work%20profile` } })
    await expect(authenticate("broker", fixture.resource, definition, options())).resolves.toBe("authenticated")
  })

  it("defaults to five seconds when no interval is advertised", async () => {
    broker({ pairing: { interval: undefined } })
    await authenticate("broker", fixture.resource, definition, options())
    expect(mocks.delays).toEqual([5000])
  })

  it.each([{ interval: 0 }, { interval: -1 }, { expires_in: 0 }, { user_code: "bad\u001b[2J" }, { device_code: "" }])("rejects malformed pairing data without echoing it: %j", async pairing => {
    broker({ pairing })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow("Invalid device OAuth response")
    expect(mocks.delays).toEqual([])
  })

  it("cancels from the human prompt before token requests", async () => {
    const requests = broker()
    await expect(authenticate("broker", fixture.resource, definition, {
      ...options(), onDeviceAuthorization: (_info, _signal, cancel) => cancel(),
    })).rejects.toThrow("cancelled")
    expect(requests.filter(request => request.path === "/broker/token")).toHaveLength(0)
  })

  it("cancels polling on the caller signal", async () => {
    broker()
    const controller = new AbortController()
    mocks.wait = () => controller.abort(new Error("operator cancelled"))
    await expect(authenticate("broker", fixture.resource, definition, { ...options(), signal: controller.signal })).rejects.toThrow()
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
  })

  it("stops a pending poll immediately on logout", async () => {
    const requests = broker()
    mocks.wait = () => removeAuth("broker", { runtime, authStorageOptions: storage })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow()
    expect(requests.filter(request => request.path === "/broker/token")).toHaveLength(0)
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
  })

  it("replaces an in-flight pairing without allowing its late token to overwrite the new grant", async () => {
    let finishFirst!: (response: Response) => void
    let started!: () => void
    const ready = new Promise<void>(resolve => { started = resolve })
    let polls = 0
    broker({ tokenHook: async () => {
      if (++polls === 1) {
        started()
        return new Promise<Response>(resolve => { finishFirst = resolve })
      }
      return json({ ...fixture.success, access_token: "new-grant" })
    } })
    const first = startAuth("broker", fixture.resource, definition, options())
    const rejected = expect(first).rejects.toThrow("replaced")
    await ready
    await startAuth("broker", fixture.resource, definition, options())
    finishFirst(json({ ...fixture.success, access_token: "stale-grant" }))
    await rejected
    expect(getAuthEntry("broker", storage)?.tokens?.accessToken).toBe("new-grant")
  })

  it.each(["logout", "replacement"])("rejects late token completion after %s", async action => {
    broker({ tokenHook: async () => {
      if (action === "logout") await removeAuth("broker", { runtime, authStorageOptions: storage })
      else await shutdownOAuth(runtime)
      return json(fixture.success)
    } })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow()
    expect(getAuthEntry("broker", storage)?.tokens).toBeUndefined()
  })

  it("keeps concurrent session grants separate and logout local", async () => {
    const second = getAuthStorageOptions(undefined, undefined, "session")
    const requests = broker({ tokenHook: async params => json({ ...fixture.success, access_token: `token-${params.get("client_id")}` }) })
    await Promise.all([
      authenticate("broker", fixture.resource, definition, options()),
      authenticate("broker", fixture.resource, definition, { ...options(), authStorageOptions: second }),
    ])
    expect(storage.sessionId).not.toBe(second.sessionId)
    expect(getAuthEntry("broker", storage)?.tokens?.accessToken).not.toBe(getAuthEntry("broker", second)?.tokens?.accessToken)
    const pairs = requests.filter(request => request.path === "/broker/token")
    expect(new Set(pairs.map(request => request.params.get("device_code"))).size).toBe(2)
    await removeAuth("broker", { runtime, authStorageOptions: storage })
    expect(getAuthEntry("broker", storage)).toBeUndefined()
    expect(getAuthEntry("broker", second)?.tokens?.accessToken).toMatch(/^token-launch-/)
  })

  it("uses existing refresh without another pairing or callback", async () => {
    const requests = broker({ tokenHook: async params => json({ ...fixture.success, access_token: params.get("grant_type") === "refresh_token" ? "refreshed" : "initial", expires_in: 1 }) })
    await authenticate("broker", fixture.resource, definition, options())
    vi.setSystemTime(Date.now() + 2000)
    await expect(getValidToken("broker", fixture.resource, { ...options(), definition })).resolves.toMatchObject({ accessToken: "refreshed" })
    expect(requests.filter(request => request.path === "/broker/device_authorization")).toHaveLength(1)
    expect(mocks.callback).not.toHaveBeenCalled()
  })

  it("sanitizes transport failures that include a device secret", async () => {
    broker({ tokenHook: async () => { throw new Error(fixture.device_authorization.device_code) } })
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow("Device OAuth request failed")
  })

  it("does not echo secrets from token errors", async () => {
    const secret = fixture.device_authorization.device_code
    broker({ tokens: [{ error: secret, error_description: fixture.success.access_token }] })
    const log = vi.spyOn(console, "log").mockImplementation(() => {})
    await expect(authenticate("broker", fixture.resource, definition, options())).rejects.toThrow("request_failed")
    expect(JSON.stringify(log.mock.calls)).not.toContain(secret)
    expect(JSON.stringify(log.mock.calls)).not.toContain(fixture.success.access_token)
  })
})
