import { createServer, type Server } from "node:http"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { McpServerManager } from "../server-manager.ts"
import { CodingAuthClient } from "../mcp-coding-auth.ts"
import { CodingAuthorizationPaused, CodingCredentialPaused } from "../coding-call-recovery.ts"
import { captureOAuthAuthority, getAuthForUrl, getAuthStorageOptions, resetTestAuthSecretStore } from "../mcp-auth.ts"

vi.mock("node:timers/promises", () => ({ setTimeout: vi.fn(async (_ms, _value, { signal }) => { signal.throwIfAborted() }) }))

const reference = "coding_connection"
const config = { version: 1 as const, cohort: "connection" }
const credentials = (n: number) => ({ version: 1 as const, token_type: "Bearer" as const, scope: "profile:coding" as const,
  access_token: `synthetic-access-${n}`, refresh_token: `synthetic-refresh-${n}`, enrollment_token: `synthetic-enrollment-${n}`,
  authorization_ref: reference, expires_at: new Date(Date.now() + 3600_000).toISOString() })
const managers: McpServerManager[] = []
const servers: Server[] = []

async function fixture(enrolled = true) {
  let renewed = false, revoked = false, loseReplacement = false, issued = false
  const paths: string[] = [], initialized: string[] = []
  const server = createServer(async (request, response) => {
    const path = request.url!
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined
    const json = (payload: unknown, status = 200) => {
      response.writeHead(status, { "content-type": "application/json" })
      response.end(JSON.stringify(payload))
    }
    if (path.startsWith("/broker/coding/")) {
      paths.push(path)
      if (revoked) return json({ error: "invalid_grant" }, 403)
      if (path.endsWith("/enroll")) {
        expect(body).toEqual({ cohort_credential: "synthetic-cohort" })
        if (!renewed) return json({ error: "authorization_paused" }, 403)
        issued = true
        return json(credentials(2))
      }
      if (path.endsWith("/status")) return json({ version: 1, status: renewed ? "active" : "authorization_paused",
        authorization_ref: reference, credential_status: issued ? "active" : "expired", renewal_route: `/broker/coding/renew?authorization_ref=${reference}` })
      expect(path).toBe("/broker/coding/replace")
      expect(body).toEqual({ enrollment_token: "synthetic-enrollment-1", refresh_token: "synthetic-refresh-1" })
      if (loseReplacement) { response.destroy(); return }
      issued = true
      return json(credentials(2))
    }
    if (request.method !== "POST") { response.writeHead(405); response.end(); return }
    if (body.id === undefined) { response.writeHead(202); response.end(); return }
    if (body.method === "initialize") {
      if (!request.headers.authorization) return json({ jsonrpc: "2.0", id: body.id,
        error: { code: -32001, message: "Bearer authentication required" } }, 401)
      initialized.push(request.headers.authorization)
      return json({ jsonrpc: "2.0", id: body.id, result: {
        protocolVersion: body.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "renewal-fixture", version: "1" },
      } })
    }
    return json({ jsonrpc: "2.0", id: body.id, result: { tools: [{ name: "fixture_read", inputSchema: { type: "object" } }] } })
  })
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve))
  const address = server.address() as { port: number }
  const url = `http://127.0.0.1:${address.port}/broker/mcp`
  const storage = getAuthStorageOptions(undefined, process.cwd(), "session")
  // First human consent seeds the secure cohort slot. A new launch has no session proofs.
  const consentStorage = enrolled ? storage : getAuthStorageOptions(undefined, process.cwd(), "session")
  new CodingAuthClient("broker", url, config, consentStorage).install(
    { ...credentials(1), cohort_credential: "synthetic-cohort" }, captureOAuthAuthority("broker", true, consentStorage),
  )
  const manager = new McpServerManager()
  manager.setAuthStorageOptions(storage)
  managers.push(manager)
  return { manager, url, storage, paths, initialized, renew: () => { renewed = true }, revoke: () => { revoked = true },
    loseReplacement: () => { loseReplacement = true },
    connect: (signal?: AbortSignal) => manager.connect("broker", { url, auth: "oauth", oauth: { codingEnrollment: config } }, signal),
  }
}

beforeEach(() => { vi.stubEnv("PI_MCP_ADAPTER_TEST_AUTH_STORE", "memory"); resetTestAuthSecretStore() })
afterEach(async () => {
  await Promise.all(managers.splice(0).map(manager => manager.closeAll()))
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()) })))
  vi.unstubAllEnvs(); vi.restoreAllMocks(); resetTestAuthSecretStore()
})

describe("real SDK coding connection renewal", () => {
  it.each([true, false])("waits for human renewal and connects automatically (enrolled=%s)", async enrolled => {
    const f = await fixture(enrolled)
    const prompt = vi.fn((_name, pause, signal) => {
      expect(pause.renewalUrl).toBe(`${f.url.replace("/mcp", "")}/coding/renew?authorization_ref=${reference}`)
      expect(signal.aborted).toBe(false)
      f.renew()
    })
    f.manager.setCodingRenewalPrompt(prompt)
    const connection = await f.connect()
    expect(connection.status).toBe("connected")
    expect(connection.tools.map(tool => tool.name)).toEqual(["fixture_read"])
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(prompt.mock.calls[0]![2].aborted).toBe(true)
    expect(f.initialized).toEqual(["Bearer synthetic-access-2"])
    expect(f.paths.filter(path => path.endsWith("/replace"))).toHaveLength(enrolled ? 1 : 0)
    expect(f.paths.filter(path => path.endsWith("/enroll"))).toHaveLength(enrolled ? 0 : 2)
    expect(getAuthForUrl("broker", f.url, f.storage)?.tokens?.accessToken).toBe("synthetic-access-2")
  })

  it("keeps manual guidance when no interactive prompt is configured", async () => {
    const f = await fixture(false)
    await expect(f.connect()).rejects.toBeInstanceOf(CodingCredentialPaused)
    expect(f.initialized).toEqual([])
    expect(f.paths).toEqual(["/broker/coding/enroll"])
  })

  it("cancels the prompt without enrolling or initializing", async () => {
    const f = await fixture(false)
    f.manager.setCodingRenewalPrompt((_name, _pause, _signal, cancel) => cancel())
    await expect(f.connect()).rejects.toThrow("Coding renewal cancelled")
    expect(f.paths).toEqual(["/broker/coding/enroll"])
    expect(f.initialized).toEqual([])
  })

  it("stops on revocation instead of falling back to fresh enrollment", async () => {
    const f = await fixture()
    f.manager.setCodingRenewalPrompt(() => f.revoke())
    await expect(f.connect()).rejects.toThrow("revoked or invalid")
    expect(f.paths.every(path => path.endsWith("/status"))).toBe(true)
    expect(f.initialized).toEqual([])
  })

  it("does not replay a replacement whose response was lost", async () => {
    const f = await fixture()
    f.manager.setCodingRenewalPrompt(() => { f.renew(); f.loseReplacement() })
    await expect(f.connect()).rejects.toThrow("do not replay a credential rotation")
    expect(f.paths.filter(path => path.endsWith("/replace"))).toHaveLength(1)
    expect(f.initialized).toEqual([])
  })

  it("cancels on runtime shutdown before connection dispatch", async () => {
    const f = await fixture()
    const controller = new AbortController()
    f.manager.setRuntimeSignal(controller.signal)
    f.manager.setCodingRenewalPrompt(() => controller.abort())
    await expect(f.connect()).rejects.toBeInstanceOf(Error)
    expect(f.initialized).toEqual([])
    expect(f.paths).toEqual(["/broker/coding/status"])
  })

  it("exhausts the bounded wait and closes the prompt without dispatching", async () => {
    const f = await fixture()
    let promptSignal: AbortSignal | undefined
    f.manager.setCodingRenewalPrompt((_name, _pause, signal) => { promptSignal = signal })
    await expect(f.connect()).rejects.toThrow("Coding renewal wait ended")
    expect(promptSignal?.aborted).toBe(true)
    expect(f.paths.filter(path => path.endsWith("/status"))).toHaveLength(41)
    expect(f.initialized).toEqual([])
  })

  it("preserves the typed enrolled pause without an irrelevant Bearer probe", async () => {
    const f = await fixture()
    await expect(f.connect()).rejects.toBeInstanceOf(CodingAuthorizationPaused)
    await expect(f.connect()).rejects.not.toThrow("probe:")
  })
})
