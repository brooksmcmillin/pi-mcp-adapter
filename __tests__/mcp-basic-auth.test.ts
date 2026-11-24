import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { userInfo } from "node:os"
import { createHash, randomBytes, randomUUID } from "node:crypto"
import { afterEach, expect, it, vi } from "vitest"
import { authenticate, completeAuthFromInput, createOAuthRuntime, getAuthStatus, getValidToken, shutdownOAuth, startAuth } from "../mcp-auth-flow.ts"
import { inspectMcpOAuthTokensForUrl } from "../oauth.ts"
import { inspectAuthForUrl } from "../mcp-auth.ts"
import { McpOAuthProvider } from "../mcp-oauth-provider.ts"
import { clearAllCredentials, getAuthEntry, getAuthStorageOptions } from "../mcp-auth.ts"

const url = "https://broker.example/broker/mcp"
const issuer = "https://broker.example/broker"
const callback = "https://callback.example/complete"
const storage = () => getAuthStorageOptions(undefined, process.cwd(), "session", "encrypted-file")
const basic = (cohort = randomUUID()) => ({ auth: "oauth" as const, oauth: { basicEnrollment: { version: 1 as const, cohort },
  clientId: "test-client", redirectUri: callback } })
const json = (data: unknown, status = 200) => Response.json(data, { status })
const session = (i: number) => ({ version: 1, token_type: "Bearer", scope: "profile:default", access_token: `synthetic-session-${i}`,
  expires_at: new Date(Date.now() + 60_000).toISOString() })
const proof = "synthetic-host-proof"
function broker(consent: Record<string, unknown>) {
  let revoked = false, exchanges = 0
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(input instanceof Request ? input.url : String(input)).pathname
    if (path.includes("oauth-protected-resource")) return json({ resource: url, authorization_servers: [issuer] })
    if (path.includes("oauth-authorization-server")) return json({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, response_types_supported: ["code"], code_challenge_methods_supported: ["S256"] })
    if (path === "/broker/mcp") return json({}, 401)
    expect(path).toBe("/broker/token")
    expect(init?.method).toBe("POST")
    const fields = new URLSearchParams(String(init?.body))
    if (fields.get("grant_type") === "authorization_code") {
      expect(fields.get("code_verifier")).toBeTruthy()
      return json(consent)
    }
    expect([...fields]).toEqual([["grant_type", "urn:mcp-broker:grant-type:basic-enrollment:v1"], ["basic_enrollment_token", proof]])
    expect(init?.redirect).toBe("error")
    exchanges++
    return revoked ? json({ error: "invalid_grant", error_description: proof }, 400) : json(session(exchanges + 1))
  })
  vi.stubGlobal("fetch", fetch)
  return { fetch, revoke: () => { revoked = true }, count: () => exchanges }
}
afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs() })

it("uses PKCE once, then a scoped proof for independent launches; revocation requires explicit consent", async () => {
  vi.stubEnv("PI_MCP_ADAPTER_OAUTH_FILE_KEY", randomBytes(32).toString("base64"))
  const runtime = createOAuthRuntime(), authStorageOptions = storage(), definition = basic()
  const opts = { runtime, authStorageOptions, definition }
  const b = broker({ ...session(1), basic_enrollment_token: proof })
  try {
    await expect(getValidToken("broker", url, opts)).rejects.toThrow(/Run \/mcp-auth/)
    expect(b.fetch).not.toHaveBeenCalled()
    const { authorizationUrl } = await startAuth("broker", url, definition, { ...opts, firstBasicEnrollmentOnly: true })
    const params = new URL(authorizationUrl).searchParams
    expect(params.get("code_challenge_method")).toBe("S256")
    expect(authorizationUrl).not.toContain(proof)
    await completeAuthFromInput("broker", `${callback}?code=test&state=${params.get("state")}`, opts)
    expect((await getValidToken("broker", url, opts))?.accessToken).toBe("synthetic-session-1")
    expect(await getValidToken("broker", url, { runtime, authStorageOptions })).toBeNull()
    const ordinary = new McpOAuthProvider("broker", url, {}, { onRedirect() {} }, authStorageOptions)
    expect(await ordinary.tokens()).toBeUndefined()
    expect([...authStorageOptions.sessionEntries!.values()].join()).not.toContain(proof)
    const persistent = { credentialStore: "encrypted-file" as const }
    const cohort = definition.oauth.basicEnrollment.cohort
    const account = `basic-enrollment-${createHash("sha256").update(JSON.stringify([url, userInfo().username, cohort])).digest("hex")}`
    expect(getAuthEntry(account, persistent)).toEqual({ cohortCredential: proof, serverUrl: url })
    expect(getAuthEntry("broker", persistent)).toBeUndefined()
    execFileSync(process.execPath, ["--import", "tsx", fileURLToPath(new URL("./fixtures/basic-enrollment-restart.mjs", import.meta.url)), cohort], { timeout: 10_000 })
    expect(await getValidToken("broker", url, { authStorageOptions: storage(), definition: { oauth: { codingEnrollment: definition.oauth.basicEnrollment } } })).toBeNull()
    expect(await getValidToken("broker", url, { ...opts, definition: { oauth: { codingEnrollment: definition.oauth.basicEnrollment } } })).toBeNull()
    expect(inspectMcpOAuthTokensForUrl("broker", url, authStorageOptions)).toEqual({ status: "absent" })
    expect(inspectAuthForUrl("broker", url, authStorageOptions, cohort).status).toBe("present")
    expect(inspectAuthForUrl("broker", url, authStorageOptions, "other-cohort").status).toBe("absent")
    expect(await getAuthStatus("broker", { ...opts, serverUrl: url })).toBe("authenticated")
    expect(await getAuthStatus("broker", { ...opts, serverUrl: url.replace("broker.example", "other.example") })).toBe("not_authenticated")
    expect(await getAuthStatus("broker", { runtime, authStorageOptions })).toBe("not_authenticated")
    const cleared = { ...opts, authStorageOptions: storage() }
    clearAllCredentials("broker", cleared.authStorageOptions)
    await expect(getValidToken("broker", url, cleared)).rejects.toThrow(/fresh consent/)
    expect(b.count()).toBe(0)
    const restart = { ...opts, authStorageOptions: storage() }
    const reads = await Promise.all([getValidToken("broker", url, restart), getValidToken("broker", url, restart)])
    expect(reads.map(t => t?.accessToken)).toEqual(["synthetic-session-2", "synthetic-session-2"])
    expect(reads[0]?.refreshToken).toBeUndefined()
    await expect(getValidToken("broker", url, { ...restart, definition: basic() })).rejects.toThrow(/fresh consent/)
    await expect(getValidToken("broker", url.replace("broker.example", "other.example"), restart)).rejects.toThrow(/fresh consent/)
    expect(b.count()).toBe(1)
    const sdk = new McpOAuthProvider("broker", url, definition.oauth, { onRedirect() {} }, restart.authStorageOptions)
    expect((await sdk.tokens())?.access_token).toBe("synthetic-session-2")
    await sdk.invalidateCredentials("tokens")
    const peer = new McpOAuthProvider("broker", url, definition.oauth, { onRedirect() {} }, restart.authStorageOptions)
    const fresh = await Promise.all([peer.tokens(), getValidToken("broker", url, restart)])
    await sdk.invalidateCredentials("tokens")
    expect((await peer.tokens())?.access_token).toBe("synthetic-session-3")
    expect(fresh[0]?.access_token).toBe("synthetic-session-3")
    expect(fresh[1]?.accessToken).toBe("synthetic-session-3")
    expect(b.count()).toBe(2)
    const shared = { ...opts, authStorageOptions: storage() }
    let release!: (value: Response) => void
    b.fetch.mockImplementationOnce(() => new Promise<Response>(resolve => { release = resolve }))
    const owner = getValidToken("broker", url, shared)
    await vi.waitFor(() => expect(release).toBeTypeOf("function"))
    const controller = new AbortController()
    const joined = getValidToken("broker", url, { ...shared, signal: controller.signal })
    controller.abort(new Error("join cancelled"))
    await expect(joined).rejects.toThrow("join cancelled")
    release(json(session(4)))
    expect((await owner)?.accessToken).toBe("synthetic-session-4")
    const expired = { ...opts, authStorageOptions: storage() }
    b.fetch.mockResolvedValueOnce(json({ ...session(4), expires_at: "2000-01-01T00:00:00Z" }))
    await expect(getValidToken("broker", url, expired)).rejects.toThrow("Broker basic enrollment exchange failed")
    expect(getAuthEntry("broker", expired.authStorageOptions)?.tokens).toBeUndefined()
    b.revoke()
    const denied = { ...opts, authStorageOptions: storage() }
    const rejected = getValidToken("broker", url, denied)
    await expect(rejected).rejects.toThrow(/fresh consent/)
    await expect(rejected).rejects.not.toThrow(proof)
    await expect(getValidToken("broker", url, denied)).rejects.toThrow(/fresh consent/)
    const automatic = startAuth("broker", url, definition, { ...denied, firstBasicEnrollmentOnly: true })
    await expect(automatic).rejects.toThrow(/fresh consent/)
    expect((await startAuth("broker", url, definition, denied)).authorizationUrl).toContain("code_challenge=")
    expect(b.count()).toBe(3)
  } finally { await shutdownOAuth(runtime) }
})

it.each([{}, { basic_enrollment_token: proof, expires_at: "2000-01-01T00:00:00Z" }, { basic_enrollment_token: proof, refresh_token: "unexpected" }, { basic_enrollment_token: proof, scope: "profile:coding" }])("rejects non-basic consent without installing credentials", async extra => {
  vi.stubEnv("PI_MCP_ADAPTER_OAUTH_FILE_KEY", randomBytes(32).toString("base64"))
  const runtime = createOAuthRuntime(), definition = basic(), opts = { runtime, definition, authStorageOptions: storage() }
  broker({ ...session(1), ...extra })
  try {
    const { authorizationUrl } = await startAuth("broker", url, definition, opts)
    await expect(completeAuthFromInput("broker", `${callback}?code=test&state=${new URL(authorizationUrl).searchParams.get("state")}`, opts)).rejects.toThrow(/fresh consent/)
    expect(getAuthEntry("broker", opts.authStorageOptions)?.tokens).toBeUndefined()
    await expect(getValidToken("broker", url, { ...opts, authStorageOptions: storage() })).rejects.toThrow(/fresh consent/)
  } finally { await shutdownOAuth(runtime) }
})

it("can restart an explicit enrollment immediately after clearing pending consent", async () => {
  vi.stubEnv("PI_MCP_ADAPTER_OAUTH_FILE_KEY", randomBytes(32).toString("base64"))
  const runtime = createOAuthRuntime(), definition = basic(), opts = { runtime, definition, authStorageOptions: storage() }
  broker({ ...session(1), basic_enrollment_token: proof })
  try {
    const first = await startAuth("broker", url, definition, opts)
    clearAllCredentials("broker", opts.authStorageOptions)
    const next = await startAuth("broker", url, definition, opts)
    const oldState = new URL(first.authorizationUrl).searchParams.get("state")
    expect(new URL(next.authorizationUrl).searchParams.get("state")).not.toBe(oldState)
    await expect(completeAuthFromInput("broker", `${callback}?code=test&state=${oldState}`, opts)).rejects.toThrow()
    expect(getAuthEntry("broker", opts.authStorageOptions)?.tokens).toBeUndefined()
  } finally { await shutdownOAuth(runtime) }
})

it("starts a new interactive attempt after a pending basic consent is cleared", async () => {
  vi.stubEnv("PI_MCP_ADAPTER_OAUTH_FILE_KEY", randomBytes(32).toString("base64"))
  const runtime = createOAuthRuntime(), definition = basic(), opts = { runtime, authStorageOptions: storage(), openAuthorizationUrl: async () => {} }
  broker({ ...session(1), basic_enrollment_token: proof })
  const waiting = vi.fn((_link: string) => new Promise<string>(() => {}))
  try {
    const first = authenticate("broker", url, definition, { ...opts, onAuthorizationInput: waiting }).catch(() => "cancelled")
    await vi.waitFor(() => expect(waiting).toHaveBeenCalledOnce())
    clearAllCredentials("broker", opts.authStorageOptions)
    const retry = authenticate("broker", url, definition, { ...opts, onAuthorizationInput: async link => {
      const state = new URL(link).searchParams.get("state")
      expect(state).not.toBe(new URL(waiting.mock.calls[0][0]).searchParams.get("state"))
      return `${callback}?code=test&state=${state}`
    } })
    await expect(retry).resolves.toBe("authenticated")
    await expect(first).resolves.toBe("cancelled")
  } finally { await shutdownOAuth(runtime) }
})

it.each(["before-response", "before-save"])("discards consent cleared %s", async phase => {
  vi.stubEnv("PI_MCP_ADAPTER_OAUTH_FILE_KEY", randomBytes(32).toString("base64"))
  const opts = storage(), definition = basic()
  const consent = { ...session(1), basic_enrollment_token: proof }
  const provider = new McpOAuthProvider("broker", url, definition.oauth, { onRedirect() {} }, opts)
  provider.requestEnrollmentConsent()
  let respond!: (response: Response) => void
  const fetch = vi.fn(() => new Promise<Response>(resolve => { respond = resolve }))
  vi.stubGlobal("fetch", fetch)
  const pending = provider.getAuthFetch()(issuer + "/token", { method: "POST", body: "grant_type=authorization_code" })
  await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
  if (phase === "before-response") clearAllCredentials("broker", opts)
  respond(json(consent))
  if (phase === "before-response") await expect(pending).rejects.toThrow(/no longer active/)
  else { await pending; await provider.invalidateCredentials("all") }
  await expect(provider.saveTokens({ token_type: "Bearer", access_token: consent.access_token })).rejects.toThrow(/no longer active/)
  expect(getAuthEntry("broker", opts)?.tokens).toBeUndefined()
  await expect(getValidToken("broker", url, { definition, authStorageOptions: storage() })).rejects.toThrow(/fresh consent/)
})

it("omits credential-bearing causes when consent transport fails", async () => {
  const provider = new McpOAuthProvider("broker", url, basic().oauth, { onRedirect() {} }, storage())
  provider.requestEnrollmentConsent()
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error(proof)))
  const attempt = provider.getAuthFetch()(issuer + "/token", { method: "POST", body: "grant_type=authorization_code" })
  await expect(attempt).rejects.toThrow(/^Broker basic consent exchange failed$/)
  await expect(attempt).rejects.not.toHaveProperty("cause")
})
