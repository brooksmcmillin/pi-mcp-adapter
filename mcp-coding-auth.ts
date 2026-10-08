import { createHash } from "node:crypto"
import type { FetchLike } from "@modelcontextprotocol/client"
import { z } from "zod"
import { abortable } from "./abort.ts"
import { combineAbortSignals } from "./runtime-owner.ts"
import { CodingAuthorizationPaused, rejectedCodingReference, waitForCodingRenewal, CODING_WAIT_BUDGET_MS, type CodingWaitOptions } from "./coding-call-recovery.ts"
import {
  getAuthForUrl, getAuthStorageIdentity, invalidateAuthEntryCache, saveAuthEntry,
  type AuthStorageOptions, type OAuthAuthority, type StoredTokens,
} from "./mcp-auth.ts"

export interface CodingEnrollmentConfig { version: 1; cohort: string }
const credentialSchema = z.object({
  version: z.literal(1), token_type: z.literal("Bearer"), scope: z.literal("profile:coding"),
  access_token: z.string().min(1), refresh_token: z.string().min(1), enrollment_token: z.string().min(1),
  authorization_ref: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  expires_at: z.string().datetime({ offset: true }), cohort_credential: z.string().min(1).optional(),
})
export type CodingCredentials = z.infer<typeof credentialSchema>
const statusSchema = z.object({
  version: z.literal(1), status: z.enum(["active", "authorization_paused"]),
  authorization_ref: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  credential_status: z.enum(["active", "expired"]), renewal_route: z.string(),
})
const unsupported = "Broker coding API v1 is required; upgrade the broker or disable oauth.codingEnrollment and use ordinary human OAuth consent."
const terminal = "Coding enrollment revoked or invalid; start fresh human consent."

type RecoveryMode = "ensure" | "status" | "replace"
type LaunchState = { epoch: number; calls?: Promise<unknown> | undefined; credentials?: CodingCredentials | undefined; denied: boolean; pending?: Promise<StoredTokens | null> | undefined; pendingMode?: RecoveryMode; selectedConfig?: CodingEnrollmentConfig | undefined }
const REGISTRY = Symbol.for("pi-mcp-adapter.coding-launches.v1")
const host = globalThis as typeof globalThis & { [REGISTRY]?: WeakMap<object, Map<string, LaunchState>> }
const registry = host[REGISTRY] ??= new WeakMap<object, Map<string, LaunchState>>()

function launchStates(storage: AuthStorageOptions): Map<string, LaunchState> {
  if (!storage.sessionEntries) throw new Error("Coding enrollment requires adapter-owned session storage")
  let states = registry.get(storage.sessionEntries)
  if (!states) { states = new Map(); registry.set(storage.sessionEntries, states) }
  return states
}

export function getRetainedCodingConfig(name: string, url: string, storage: AuthStorageOptions): CodingEnrollmentConfig | undefined {
  if (storage.persistence !== "session" || !storage.sessionEntries) return undefined
  const identity = getAuthStorageIdentity(storage)
  for (const [key, state] of launchStates(storage)) {
    const [launchName, launchUrl, launchIdentity] = JSON.parse(key) as string[]
    if (launchName === name && launchIdentity === identity && state.selectedConfig) {
      if (launchUrl !== url) throw new Error("Coding session is bound to a different MCP URL")
      return { ...state.selectedConfig }
    }
  }
  return undefined
}

export function logoutCodingLaunch(name: string, storage: AuthStorageOptions): void {
  if (storage.persistence !== "session" || !storage.sessionEntries) return
  for (const [key, state] of launchStates(storage)) {
    if ((JSON.parse(key) as string[])[0] === name) { state.epoch = (state.epoch ?? 0) + 1; state.denied = true; state.credentials = undefined }
  }
}

export function validateCodingConfig(value: unknown): CodingEnrollmentConfig {
  const parsed = z.object({ version: z.literal(1), cohort: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/) }).strict().safeParse(value)
  if (!parsed.success) throw new Error("oauth.codingEnrollment requires version: 1 and a non-secret cohort slot (letters, digits, _ or -)")
  return parsed.data
}

/** Cohort names select private secure-store entries; they are never authority. */
export class CodingAuthClient {
  private readonly state: LaunchState
  private readonly cohortAccount: string
  private readonly persistent: AuthStorageOptions
  readonly issuer: string

  constructor(private name: string, private url: string, config: CodingEnrollmentConfig, private storage: AuthStorageOptions) {
    const endpoint = new URL(url)
    if (endpoint.pathname !== "/broker/mcp" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password
      || (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(endpoint.hostname)))) {
      throw new Error("Coding enrollment requires the broker /broker/mcp HTTPS endpoint (HTTP is allowed only on loopback)")
    }
    if (storage.persistence !== "session") throw new Error("Coding enrollment requires settings.oauthPersistence: session; access/refresh tokens must never be shared")
    this.issuer = `${endpoint.origin}/broker`
    this.persistent = { ...(storage.cohortCredentialStore ? { credentialStore: storage.cohortCredentialStore } : {}) }
    this.cohortAccount = `coding-cohort-${createHash("sha256").update(JSON.stringify([url, config.cohort])).digest("hex")}`
    const key = JSON.stringify([name, url, getAuthStorageIdentity(storage), config.cohort])
    const launches = launchStates(storage)
    let state = launches.get(key)
    if (!state) { state = { epoch: 0, denied: false }; launches.set(key, state) }
    state.epoch ??= 0
    // Keep the active binding with the existing host-owned launch state, not
    // ambient configuration or persisted bearer credentials.
    for (const [launchKey, launch] of launches) {
      const [launchName, , identity] = JSON.parse(launchKey) as string[]
      if (launchName === name && identity === getAuthStorageIdentity(storage)) {
        if (launch !== state && launch.selectedConfig) launch.epoch = (launch.epoch ?? 0) + 1
        launch.selectedConfig = undefined
      }
    }
    state.selectedConfig = { ...config }
    this.state = state
  }

  parseCredentials(payload: unknown): CodingCredentials {
    const parsed = credentialSchema.safeParse(payload)
    if (!parsed.success) throw new Error(unsupported + " Select shared coding in the human consent form.")
    return parsed.data
  }

  install(payload: CodingCredentials, check: OAuthAuthority, recovery = false): void {
    check()
    if (!this.state.selectedConfig) throw new Error("Coding session configuration changed; use the current configuration")
    if (payload.cohort_credential) {
      saveAuthEntry(this.cohortAccount, { cohortCredential: payload.cohort_credential, cohortReference: payload.authorization_ref }, this.url, this.persistent)
    }
    check()
    const entry = getAuthForUrl(this.name, this.url, this.storage) ?? {}
    saveAuthEntry(this.name, { ...entry, tokens: this.toStored(payload) }, this.url, this.storage)
    if (!recovery) this.state.epoch++
    this.state.credentials = payload
    this.state.denied = false
  }

  private toStored(payload: CodingCredentials): StoredTokens {
    return { accessToken: payload.access_token, refreshToken: payload.refresh_token, expiresAt: Date.parse(payload.expires_at) / 1000,
      scope: payload.scope, issuer: this.issuer }
  }

  logout(): void {
    this.state.epoch++
    this.state.denied = true
    this.state.credentials = undefined
  }

  async tokens(fetchFn: FetchLike, check: OAuthAuthority, signal?: AbortSignal, mode: RecoveryMode = "ensure"): Promise<StoredTokens | null> {
    const assert = () => {
      check(); signal?.throwIfAborted()
      if (this.state.denied) throw new Error(terminal)
      if (!this.state.selectedConfig) throw new Error("Coding session configuration changed; use the current configuration")
    }
    assert()
    // One rotation per launch, even when different SDK providers overlap.
    if (this.state.pending) {
      const pending = this.state.pending, pendingMode = this.state.pendingMode
      const result = await abortable(pending, signal)
      assert()
      if (pendingMode === mode) return result
      if (this.state.pending === pending) this.state.pending = undefined
      return this.tokens(fetchFn, check, signal, mode)
    }
    const operation = this.recover(fetchFn, assert, signal, mode)
    this.state.pending = operation
    this.state.pendingMode = mode
    try { const result = await operation; assert(); return result }
    finally { if (this.state.pending === operation) this.state.pending = undefined }
  }

  async runPending<T>(call: () => Promise<T>, fetchFn: FetchLike, options: CodingWaitOptions): Promise<T> {
    const epoch = this.state.epoch
    const check = () => {
      options.check(); options.signal?.throwIfAborted()
      if (this.state.epoch !== epoch || this.state.denied || !this.state.selectedConfig) throw new Error("Coding pending call cancelled by credential or configuration change")
    }
    const previous = this.state.calls
    const operation = (async () => {
      if (previous) {
        const deadline = AbortSignal.timeout(CODING_WAIT_BUDGET_MS)
        const queueSignal = combineAbortSignals(options.signal, deadline)!
        try { await abortable(previous.catch(() => {}), queueSignal) }
        catch (error) {
          options.signal?.throwIfAborted()
          if (deadline.aborted) throw new Error("Coding call queue wait ended before dispatch; manually continue with the original tool and arguments. No background retry remains.")
          throw error
        }
      }
      check()
      try { return await call() }
      catch (error) {
        check()
        const reference = error instanceof CodingAuthorizationPaused ? error.reference : rejectedCodingReference(error)
        if (!reference || reference !== this.state.credentials?.authorization_ref) throw error
        const pause = new CodingAuthorizationPaused(reference, new URL(`/broker/coding/renew?authorization_ref=${reference}`, this.issuer).toString())
        await waitForCodingRenewal(pause, async (signal) => {
          await this.tokens(fetchFn, check, signal)
        }, { ...options, check })
        check()
        // One retry only. Any ambiguous failure (including a lost retry response) escapes.
        return call()
      }
    })()
    // A cancelled queued caller must not let the next caller overtake its predecessor.
    const tail = Promise.allSettled([previous, operation])
    this.state.calls = tail
    try { return await operation }
    finally { void tail.then(() => { if (this.state.calls === tail) this.state.calls = undefined }) }
  }

  private paused(reference: string | undefined): Error {
    if (!reference || !/^[A-Za-z0-9_-]{1,128}$/.test(reference)) return new Error("Coding authorization paused; use the common human renewal page, then continue")
    const route = new URL(`/broker/coding/renew?authorization_ref=${reference}`, this.issuer).toString()
    return new CodingAuthorizationPaused(reference, route)
  }

  private async recover(fetchFn: FetchLike, check: OAuthAuthority, signal: AbortSignal | undefined, mode: RecoveryMode): Promise<StoredTokens | null> {
    let pausedError = new Error(this.paused(this.state.credentials?.authorization_ref).message)
    const request = async (route: string, body: Record<string, string>): Promise<unknown> => {
      check()
      const requestSignal = combineAbortSignals(signal, AbortSignal.timeout(30_000))!
      try {
        const response = await abortable(fetchFn(`${this.issuer}/coding/${route}`, {
          method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body), redirect: "error", signal: requestSignal,
        }), requestSignal)
        const payload: unknown = await abortable(response.json(), requestSignal)
        check()
        if (!response.ok) {
          const error = z.object({ error: z.string() }).safeParse(payload)
          if (error.success && error.data.error === "invalid_grant") {
            this.state.denied = true
            throw new Error(terminal)
          }
          if (error.success && error.data.error === "authorization_paused") throw pausedError
          if ([404, 405].includes(response.status)) throw new Error(unsupported)
          throw new Error("Broker coding request failed")
        }
        return payload
      } catch (error) {
        check()
        if (error === pausedError || (error instanceof Error && [terminal, unsupported, "Broker coding request failed"].includes(error.message))) throw error
        throw new Error("Broker coding request failed; continue to check status (do not replay a credential rotation)")
      }
    }
    const current = this.state.credentials
    if (!current) {
      invalidateAuthEntryCache(this.cohortAccount, this.persistent)
      const cohort = getAuthForUrl(this.cohortAccount, this.url, this.persistent)
      check()
      if (!cohort?.cohortCredential) return null
      pausedError = new Error(this.paused(cohort.cohortReference).message)
      const payload = this.parseCredentials(await request("enroll", { cohort_credential: cohort.cohortCredential }))
      check()
      if (this.state.credentials !== undefined) throw new Error("Coding credentials changed while enrolling")
      this.install(payload, check, true)
      return this.toStored(payload)
    }
    const parsed = statusSchema.safeParse(await request("status", { enrollment_token: current.enrollment_token }))
    if (!parsed.success) throw new Error(unsupported)
    const status = parsed.data
    const expectedRoute = `/broker/coding/renew?authorization_ref=${current.authorization_ref}`
    if (status.authorization_ref !== current.authorization_ref || status.renewal_route !== expectedRoute) throw new Error("Invalid coding renewal guidance")
    check()
    if (status.status === "authorization_paused") {
      throw this.paused(current.authorization_ref)
    }
    // SDK auth reads need the old refresh pair after the status gate, not a first
    // rotation followed by a second rotation in its token-endpoint request.
    if (mode === "status" || (mode !== "replace" && status.credential_status === "active" && Date.parse(current.expires_at) > Date.now())) {
      return this.toStored(current)
    }
    const replacement = this.parseCredentials(await request("replace", { enrollment_token: current.enrollment_token, refresh_token: current.refresh_token }))
    if (replacement.authorization_ref !== current.authorization_ref || replacement.cohort_credential !== undefined) throw new Error("Invalid coding replacement response")
    check()
    if (this.state.credentials !== current) throw new Error("Coding credentials changed while rotating")
    this.install(replacement, check, true)
    return this.toStored(replacement)
  }
}
