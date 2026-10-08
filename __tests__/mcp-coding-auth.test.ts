import { afterEach, describe, expect, it, vi } from "vitest"
import { readFileSync } from "node:fs"
import { randomUUID } from "node:crypto"
import { createServer } from "node:http"
import { once } from "node:events"
import { auth as sdkAuth } from "@modelcontextprotocol/client"
import { CodingAuthClient, validateCodingConfig, type CodingCredentials } from "../mcp-coding-auth.ts"
import { createOAuthFetch } from "../mcp-auth-fetch.ts"
import { McpOAuthProvider } from "../mcp-oauth-provider.ts"
import { completeAuthFromInput, createOAuthRuntime, extractOAuthConfig, getValidToken, removeAuth, shutdownOAuth, startAuth } from "../mcp-auth-flow.ts"
import { getMcpOAuthTokensForUrl } from "../oauth.ts"
import { captureOAuthAuthority, getAuthEntry, getAuthStorageOptions, type AuthStorageOptions } from "../mcp-auth.ts"

// Byte-identical contract from infra@a665b5629c1375f296db7d1be115b1b5dbc24255.
const fixture = JSON.parse(readFileSync(new URL("./fixtures/coding-enrollment-v1.json", import.meta.url), "utf8"))
const nativeFetch = globalThis.fetch
const origin = "https://broker.example"
const url = `${origin}/broker/mcp`
const json = (payload: unknown, status = 200) => new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } })
const storage = () => getAuthStorageOptions(undefined, process.cwd(), "session")
const config = () => ({ codingEnrollment: { version: 1 as const, cohort: randomUUID() } })
const proof = (i: number): CodingCredentials => ({ version: 1, access_token: `synthetic-access-${i}`, refresh_token: `synthetic-refresh-${i}`,
  enrollment_token: `synthetic-enrollment-${i}`, authorization_ref: "coding_test", token_type: "Bearer", scope: "profile:coding", expires_at: new Date(Date.now() + 3600_000).toISOString() })

function broker() {
  let index = 1
  let paused = false
  let expired = false
  const rows = new Map<string, CodingCredentials>()
  const revoked = new Set<string>()
  const requests: { route: string; fields: string[] }[] = []
  const fetchFn = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const path = new URL(input instanceof Request ? input.url : String(input)).pathname
    if (path.includes("oauth-protected-resource")) return json({ resource: url, authorization_servers: [`${origin}/broker`] })
    if (path.includes("oauth-authorization-server")) return json({ issuer: `${origin}/broker`, authorization_endpoint: `${origin}/broker/authorize`, token_endpoint: `${origin}/broker/token`, registration_endpoint: `${origin}/broker/register`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"] })
    if (path === "/broker/register") return json({ ...JSON.parse(String(init?.body)), client_id: "test-client", client_id_issued_at: 1 })
    if (path === "/broker/mcp") return json({}, 401)
    const body = await new Request(input instanceof Request ? input.clone() : String(input), init).text()
    const params = path === "/broker/token" ? Object.fromEntries(new URLSearchParams(body)) : JSON.parse(body)
    requests.push({ route: path, fields: Object.keys(params) })
    if (path.includes("/coding/")) {
      expect(init?.redirect).toBe("error")
      expect(new Headers(init?.headers).get("content-type")).toBe("application/json")
      expect(Object.keys(params).sort()).toEqual([...fixture.requests[path]].sort())
    }
    if (path === "/broker/token") {
      expect(params.grant_type).toBe("authorization_code")
      const issued = { ...proof(index++), cohort_credential: "synthetic-cohort" }
      rows.set(issued.enrollment_token, issued)
      return json(issued)
    }
    const row = rows.get(params.enrollment_token)
    if (path !== "/broker/coding/enroll" && (!row || revoked.has(params.enrollment_token))) return json({ error: "invalid_grant", error_description: "synthetic-cohort" }, 403)
    if (path === "/broker/coding/status") return json({ version: 1, status: paused ? "authorization_paused" : "active", authorization_ref: row!.authorization_ref,
      credential_status: expired ? "expired" : "active", renewal_route: "/broker/coding/renew?authorization_ref=coding_test" })
    if (paused) return json({ error: "authorization_paused" }, 403)
    if (path === "/broker/coding/replace") {
      expect(params.refresh_token).toBe(row!.refresh_token)
      rows.delete(params.enrollment_token)
    } else expect(params.cohort_credential).toBe("synthetic-cohort")
    const issued = proof(index++)
    rows.set(issued.enrollment_token, issued)
    return json(issued)
  })
  vi.stubGlobal("fetch", fetchFn)
  return { rows, revoked, requests, fetchFn, pause: () => { paused = true }, renew: () => { paused = false; expired = true }, expire: () => { expired = true } }
}
const runtimes: ReturnType<typeof createOAuthRuntime>[] = []
afterEach(async () => { for (const runtime of runtimes.splice(0)) await shutdownOAuth(runtime); vi.unstubAllGlobals(); vi.restoreAllMocks() })

async function initial(s: AuthStorageOptions, c: ReturnType<typeof config>) {
  const runtime = createOAuthRuntime(); runtimes.push(runtime)
  const definition = { url, auth: "oauth" as const, oauth: { ...c, redirectUri: "https://callback.example/complete" } }
  const result = await startAuth("broker", url, definition, { runtime, authStorageOptions: s })
  const state = new URL(result.authorizationUrl).searchParams.get("state")!
  await completeAuthFromInput("broker", `https://callback.example/complete?code=synthetic-code&state=${state}&iss=${encodeURIComponent(`${origin}/broker`)}`, { runtime, authStorageOptions: s })
  expect(result.authorizationUrl).not.toMatch(/synthetic-(?:cohort|access|refresh|enrollment)/)
  return { runtime, definition, authStorageOptions: s }
}

describe("coding enrollment v1", () => {
  it("validates opt-in config without accepting proof fields or unsupported grants/storage", () => {
    expect(extractOAuthConfig({ oauth: config() }).codingEnrollment?.version).toBe(1)
    expect(() => validateCodingConfig({ version: 2, cohort: "work" })).toThrow(/version: 1/)
    expect(() => validateCodingConfig({ version: 1, cohort: "work", cohort_credential: "secret" })).toThrow(/non-secret/)
    expect(() => new McpOAuthProvider("broker", url, config(), { onRedirect: vi.fn() })).toThrow(/oauthPersistence/)
    expect(() => new McpOAuthProvider("broker", url, { ...config(), grantType: "device_code" }, { onRedirect: vi.fn() }, storage())).toThrow(/authorization_code/)
    expect(() => new McpOAuthProvider("broker", url, { ...config(), skipIssuerMetadataValidation: true }, { onRedirect: vi.fn() }, storage())).toThrow(/strict issuer/)
    expect(() => new CodingAuthClient("broker", "http://remote.example/broker/mcp", config().codingEnrollment, storage())).toThrow(/HTTPS/)
  })

  it("consumes the actual SDK code response and silently enrolls independent launches", async () => {
    const b = broker(), c = config(), first = storage(), second = storage()
    await initial(first, c)
    expect(getAuthEntry("broker", first)?.tokens?.accessToken).toBe("synthetic-access-1")
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, second)
    const secondTokens = await provider.tokens()
    expect(secondTokens?.access_token).toBe("synthetic-access-2")
    expect(secondTokens?.refresh_token).not.toBe(getAuthEntry("broker", first)?.tokens?.refreshToken)
    expect(getAuthEntry("broker", first)).not.toHaveProperty("cohortCredential")
    expect(getAuthEntry("broker", second)).not.toHaveProperty("cohortCredential")
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
    await expect(startAuth("broker", url, { url, oauth: c }, { authStorageOptions: second })).resolves.toEqual({ authorizationUrl: "" })
  })

  it("pauses several sessions with one common route and recovers after renewal including idle/absolute expiry", async () => {
    const b = broker(), c = config(), stores = [storage(), storage(), storage()]
    await initial(stores[0]!, c)
    const providers = stores.map(s => new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s))
    await Promise.all(providers.map(p => p.tokens()))
    b.pause()
    const errors = await Promise.all(providers.map(p => p.tokens().catch(e => String(e))))
    expect(new Set(errors).size).toBe(1)
    expect(errors[0]).toContain(`${origin}/broker/coding/renew?authorization_ref=coding_test`)
    expect(JSON.stringify(errors)).not.toMatch(/synthetic-(?:cohort|access|refresh|enrollment)/)
    const replaceBefore = b.requests.filter(r => r.route.endsWith("/replace")).length
    expect(replaceBefore).toBe(0)
    const revokedProof = [...b.rows.keys()][2]!
    b.revoked.add(revokedProof)
    b.renew()
    const tokens = await Promise.all(providers.slice(0, 2).map(p => p.tokens()))
    expect(new Set(tokens.map(t => t!.access_token)).size).toBe(2)
    await expect(providers[2]!.tokens()).rejects.toThrow(/revoked/)
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(2)
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
  })

  it("serializes overlapping providers and routes SDK refresh through replacement, not OAuth refresh", async () => {
    const b = broker(), c = config(), s = storage()
    await initial(s, c); b.expire()
    const providers = [0, 1, 2].map(() => new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s))
    const results = await Promise.all(providers.map(p => p.tokens()))
    expect(new Set(results.map(t => t?.access_token)).size).toBe(1)
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(1)
    const provider = providers[0]!
    await provider.saveDiscoveryState({ authorizationServerUrl: `${origin}/broker`, authorizationServerMetadata: { issuer: `${origin}/broker`, authorization_endpoint: `${origin}/broker/authorize`, token_endpoint: `${origin}/broker/token`, response_types_supported: ["code"], token_endpoint_auth_methods_supported: ["none"] } })
    await expect(sdkAuth(provider, { serverUrl: url, fetchFn: provider.getAuthFetch() })).resolves.toBe("AUTHORIZED")
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(2)
  })

  it.each(["logout", "cancel", "deactivate", "fresh-consent"])("prevents late credential installation on %s", async action => {
    const b = broker(), c = config(), s = storage()
    const opts = await initial(s, c); b.expire()
    const controller = new AbortController()
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s, controller.signal)
    let entered!: () => void, finish!: () => void
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { finish = resolve })
    provider.setAuthFetch(createOAuthFetch(url, undefined, controller.signal, { delegate: async (input, init) => {
      const result = await b.fetchFn(input, init)
      if (String(input).endsWith("/replace")) { entered(); await gate }
      return result
    } }))
    const pending = provider.tokens(); void pending.catch(() => {})
    await started
    if (action === "logout") await removeAuth("broker", opts)
    if (action === "cancel") controller.abort()
    if (action === "deactivate") provider.deactivate()
    if (action === "fresh-consent") new CodingAuthClient("broker", url, c.codingEnrollment, s).install(proof(3), captureOAuthAuthority("broker", true, s))
    finish()
    await expect(pending).rejects.toThrow()
    expect(getAuthEntry("broker", s)?.tokens?.accessToken).not.toBe("synthetic-access-2")
    if (action === "fresh-consent") expect(getAuthEntry("broker", s)?.tokens?.accessToken).toBe("synthetic-access-3")
    if (action === "logout") {
      expect(getAuthEntry("broker", s)).toBeUndefined()
      const next = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
      await expect(next.tokens()).rejects.toThrow(/revoked/)
    }
  })

  it("retains proofs across new providers and module reload using the same host store", async () => {
    const b = broker(), c = config(), s = storage()
    await initial(s, c); b.expire()
    vi.resetModules()
    const { CodingAuthClient: Reloaded } = await import("../mcp-coding-auth.ts")
    const reloaded = new Reloaded("broker", url, c.codingEnrollment, s)
    const tokens = await reloaded.tokens(createOAuthFetch(url), captureOAuthAuthority("broker", true, s))
    expect(tokens?.accessToken).toBe("synthetic-access-2")
    expect(b.requests.filter(r => r.route.endsWith("/enroll"))).toHaveLength(0)
  })

  it.each([404, 405, 200])("gives safe version fallback guidance for unsupported response %i", async status => {
    broker(); const c = config(), s = storage(); await initial(s, c)
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    provider.setAuthFetch(createOAuthFetch(url, undefined, undefined, { delegate: async () => json({ version: 2, error: "synthetic-cohort" }, status) }))
    await expect(provider.tokens()).rejects.toThrow(/Broker coding API v1/)
  })

  it("refreshes the cohort backend on host reload without replacing ordinary session credentials", () => {
    const owner = {}, s = getAuthStorageOptions(undefined, process.cwd(), "session", undefined, owner)
    const encrypted = getAuthStorageOptions(undefined, process.cwd(), "session", "encrypted-file", owner)
    expect(encrypted).toBe(s)
    expect(encrypted.cohortCredentialStore).toBe("encrypted-file")
    expect(encrypted.credentialStore).toBeUndefined()
    const os = getAuthStorageOptions(undefined, process.cwd(), "session", undefined, owner)
    expect(os).toBe(s)
    expect(os.cohortCredentialStore).toBeUndefined()
    expect(os.sessionEntries).toBe(s.sessionEntries)
  })

  it("normalizes Request-contained token forms and retains the code request cancellation fence", async () => {
    const b = broker(), c = config(), s = storage(), controller = new AbortController()
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    const request = new Request(`${origin}/broker/token`, { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code" }), signal: controller.signal })
    const response = await provider.getAuthFetch()(request)
    const payload = await response.json()
    expect(request.bodyUsed).toBe(false)
    await provider.saveTokens(payload)
    b.expire()
    await expect(provider.tokens({ issuer: `${origin}/broker` })).resolves.toMatchObject({ access_token: payload.access_token })
    const refreshed = await provider.getAuthFetch()(new Request(`${origin}/broker/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: payload.refresh_token }) }))
    expect((await refreshed.json()).access_token).not.toBe(payload.access_token)
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(1)
    const lateStorage = storage(), late = new McpOAuthProvider("late", url, c, { onRedirect: vi.fn() }, lateStorage)
    const lateResponse = await late.getAuthFetch()(new Request(`${origin}/broker/token`, { method: "POST", body: "grant_type=authorization_code", signal: controller.signal }))
    const latePayload = await lateResponse.json()
    controller.abort()
    await expect(late.saveTokens(latePayload)).rejects.toThrow()
    expect(getAuthEntry("late", lateStorage)).toBeUndefined()
  })

  it("applies active, paused and revoked status gates to both SDK-context and ordinary token reads", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c)
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    const context = { issuer: `${origin}/broker` }
    await expect(provider.tokens(context)).resolves.toMatchObject({ access_token: "synthetic-access-1" })
    await expect(provider.tokens()).resolves.toMatchObject({ access_token: "synthetic-access-1" })
    await expect(provider.tokens({ issuer: "https://wrong.example/broker" })).rejects.toThrow(/issuer mismatch/)
    b.pause()
    await expect(provider.tokens(context)).rejects.toThrow(/paused/)
    await expect(provider.tokens()).rejects.toThrow(/paused/)
    b.revoked.add("synthetic-enrollment-1")
    await expect(provider.tokens(context)).rejects.toThrow(/revoked/)
    await expect(provider.tokens()).rejects.toThrow(/revoked/)
    expect(b.requests.filter(r => r.route.endsWith("/enroll") || r.route.endsWith("/replace"))).toHaveLength(0)
  })

  it("does not coalesce an ensure-credentials call into a concurrent SDK status-only read", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c); b.expire()
    let release!: () => void, entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    const started = new Promise<void>(resolve => { entered = resolve })
    let first = true
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    provider.setAuthFetch(createOAuthFetch(url, undefined, undefined, { delegate: async (input, init) => {
      if (String(input).endsWith("/status") && first) { first = false; entered(); await gate }
      return b.fetchFn(input, init)
    } }))
    const status = provider.tokens({ issuer: `${origin}/broker` })
    await started
    const ensured = provider.tokens()
    release()
    expect((await status)?.access_token).toBe("synthetic-access-1")
    expect((await ensured)?.access_token).toBe("synthetic-access-2")
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(1)
  })

  it("never replays a consumed rotation whose response was lost or falls back to cohort enrollment", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c); b.expire()
    const provider = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    provider.setAuthFetch(createOAuthFetch(url, undefined, undefined, { delegate: async (input, init) => {
      const response = await b.fetchFn(input, init)
      if (String(input).endsWith("/replace")) throw new Error("synthetic-refresh-1")
      return response
    } }))
    const lostResponse = await provider.tokens().catch(error => error as Error)
    expect(String(lostResponse)).toMatch(/request failed/)
    expect(String(lostResponse)).not.toMatch(/synthetic-/)
    expect(getAuthEntry("broker", s)?.tokens?.accessToken).toBe("synthetic-access-1")
    await expect(provider.tokens()).rejects.toThrow(/revoked/)
    await expect(provider.tokens({ issuer: `${origin}/broker` })).rejects.toThrow(/revoked/)
    expect(b.requests.filter(r => r.route.endsWith("/replace"))).toHaveLength(1)
    expect(b.requests.filter(r => r.route.endsWith("/enroll"))).toHaveLength(0)
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
  })

  it("does not submit an existing cohort proof to a different broker URL or cohort slot", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c)
    const before = b.requests.length
    const otherSlot = { codingEnrollment: { version: 1 as const, cohort: "another-slot" } }
    const otherUrl = "https://other.example/broker/mcp"
    await expect(new McpOAuthProvider("broker", url, otherSlot, { onRedirect: vi.fn() }, s).tokens()).resolves.toBeUndefined()
    await expect(getValidToken("broker", url, { authStorageOptions: s, definition: { oauth: otherSlot } })).resolves.toBeNull()
    await expect(new McpOAuthProvider("broker", otherUrl, c, { onRedirect: vi.fn() }, s).tokens()).resolves.toBeUndefined()
    await expect(getValidToken("broker", otherUrl, { authStorageOptions: s, definition: { oauth: c } })).resolves.toBeNull()
    expect(b.requests).toHaveLength(before)
    expect(getAuthEntry("broker", s)?.tokens?.accessToken).toBe("synthetic-access-1")
  })

  it("rejects actual cross-origin coding proof and code-exchange redirects without disclosing secrets", async () => {
    let targetRequests = 0
    const target = createServer((_req, res) => { targetRequests++; res.end(JSON.stringify(proof(99))) })
    target.listen(0, "127.0.0.1"); await once(target, "listening")
    const targetPort = (target.address() as import("node:net").AddressInfo).port
    const source = createServer((_req, res) => { res.writeHead(307, { location: `http://127.0.0.1:${targetPort}/capture` }); res.end() })
    source.listen(0, "127.0.0.1"); await once(source, "listening")
    const sourcePort = (source.address() as import("node:net").AddressInfo).port
    const localUrl = `http://127.0.0.1:${sourcePort}/broker/mcp`, s = storage(), c = config()
    vi.stubGlobal("fetch", nativeFetch)
    try {
      new CodingAuthClient("redirect", localUrl, c.codingEnrollment, s).install(proof(1), captureOAuthAuthority("redirect", true, s))
      const provider = new McpOAuthProvider("redirect", localUrl, c, { onRedirect: vi.fn() }, s)
      const statusError = await provider.tokens().catch(error => error as Error)
      expect(String(statusError)).toMatch(/request failed/)
      expect(String(statusError)).not.toMatch(/synthetic-(?:cohort|refresh|enrollment|access)/)
      const tokenUrl = new URL("/broker/token", localUrl)
      for (const request of [new Request(tokenUrl, { method: "POST", body: "grant_type=authorization_code&code=synthetic-code" }),
        tokenUrl]) {
        await expect(provider.getAuthFetch()(request, request instanceof Request ? undefined : { method: "POST", body: "grant_type=authorization_code&code=synthetic-code" })).rejects.toThrow()
      }
      expect(targetRequests).toBe(0)
      expect(getAuthEntry("redirect", s)?.tokens?.accessToken).toBe("synthetic-access-1")
    } finally {
      source.closeAllConnections(); target.closeAllConnections()
      await Promise.all([new Promise<void>(resolve => source.close(() => resolve())), new Promise<void>(resolve => target.close(() => resolve()))])
    }
  })

  it.each([undefined, { oauth: {} }, { oauth: false as const }])("retains coding status for public reads with omitted coding configuration (%j)", async definition => {
    const b = broker(), c = config(), s = storage(); await initial(s, c)
    const options = { authStorageOptions: s, ...(definition ? { definition } : {}) }
    await expect(getMcpOAuthTokensForUrl("broker", url, options)).resolves.toMatchObject({ accessToken: "synthetic-access-1" })
    b.pause()
    await expect(getMcpOAuthTokensForUrl("broker", url, options)).rejects.toThrow(/coding\/renew\?authorization_ref=coding_test/)
    b.renew()
    await expect(getMcpOAuthTokensForUrl("broker", url, options)).resolves.toMatchObject({ accessToken: "synthetic-access-2" })
    b.revoked.add("synthetic-enrollment-2")
    await expect(getMcpOAuthTokensForUrl("broker", url, options)).rejects.toThrow(/revoked/)
    await expect(getMcpOAuthTokensForUrl("broker", url, options)).rejects.toThrow(/revoked/)
    expect(b.requests.filter(r => r.route.endsWith("/enroll"))).toHaveLength(0)
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
  })

  it("adopts a later enrollment in existing providers and previously captured SDK fetches", async () => {
    const b = broker(), c = config(), s = storage()
    const provider = new McpOAuthProvider("broker", url, {}, { onRedirect: vi.fn() }, s)
    const fetchFn = provider.getAuthFetch()
    await initial(s, c)
    await expect(provider.tokens({ issuer: `${origin}/broker` })).resolves.toMatchObject({ access_token: "synthetic-access-1" })
    b.pause()
    await expect(provider.tokens()).rejects.toThrow(/paused/)
    await expect(fetchFn(`${origin}/broker/token`, { method: "POST", body: "grant_type=refresh_token&refresh_token=synthetic-refresh-1" })).rejects.toThrow(/paused/)
    b.renew()
    expect((await (await fetchFn(`${origin}/broker/token`, { method: "POST", body: "grant_type=refresh_token&refresh_token=synthetic-refresh-1" })).json()).access_token).toBe("synthetic-access-2")
    expect(provider.codingEnrollmentEnabled).toBe(true)
    expect(b.requests.filter(r => r.route === "/broker/token")).toHaveLength(1)
  })

  it("retains omitted-definition gating across module reload and logout without enabling other launches", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c)
    vi.resetModules()
    const { getMcpOAuthTokensForUrl: reloaded } = await import("../oauth.ts")
    b.pause()
    await expect(reloaded("broker", url, { authStorageOptions: s })).rejects.toThrow(/paused/)
    const before = b.requests.length
    await expect(reloaded("broker", url, { authStorageOptions: storage() })).resolves.toBeUndefined()
    await expect(reloaded("other", url, { authStorageOptions: s })).resolves.toBeUndefined()
    expect(b.requests).toHaveLength(before)
    await removeAuth("broker", { authStorageOptions: s })
    await expect(reloaded("broker", url, { authStorageOptions: s })).rejects.toThrow(/revoked/)
    expect(getAuthEntry("broker", s)).toBeUndefined()
    expect(b.requests).toHaveLength(before)
  })

  it("binds implicit reads to the latest URL/slot and fences obsolete providers", async () => {
    const b = broker(), c = config(), s = storage(); await initial(s, c)
    const old = new McpOAuthProvider("broker", url, c, { onRedirect: vi.fn() }, s)
    const otherSlot = { version: 1 as const, cohort: "new-slot" }
    new CodingAuthClient("broker", url, otherSlot, s)
    const before = b.requests.length
    await expect(getMcpOAuthTokensForUrl("broker", url, { authStorageOptions: s })).resolves.toBeUndefined()
    await expect(old.tokens()).rejects.toThrow(/configuration changed/)
    const otherUrl = "https://other.example/broker/mcp"
    new CodingAuthClient("broker", otherUrl, otherSlot, s)
    await expect(getMcpOAuthTokensForUrl("broker", url, { authStorageOptions: s })).rejects.toThrow(/different MCP URL/)
    await expect(getMcpOAuthTokensForUrl("broker", otherUrl, { authStorageOptions: s })).resolves.toBeUndefined()
    expect(b.requests).toHaveLength(before)
  })

  it("does not add coding endpoints or change ordinary OAuth defaults", () => {
    expect(extractOAuthConfig({ url })).toEqual({})
    const provider = new McpOAuthProvider("ordinary", "https://ordinary.example/mcp", {}, { onRedirect: vi.fn() }, storage())
    expect(provider.clientMetadata.grant_types).toEqual(["authorization_code", "refresh_token"])
  })
})
