import { createHash } from "node:crypto"
import { userInfo } from "node:os"
import { UnauthorizedError, type FetchLike } from "@modelcontextprotocol/client"
import { z } from "zod"
import { abortable } from "./abort.ts"
import { brokerEnrollmentIssuer } from "./mcp-coding-auth.ts"
import { captureBasicEnrollmentAuthority, getAuthForUrl, readBasicEnrollmentProof, saveAuthEntry, type AuthStorageOptions, type StoredTokens } from "./mcp-auth.ts"

const session = z.object({
  version: z.literal(1), scope: z.literal("profile:default"), token_type: z.literal("Bearer"),
  access_token: z.string().min(1), expires_at: z.string().datetime({ offset: true }).refine(value => Date.parse(value) > Date.now()),
}).strict()
const enrollment = session.extend({ basic_enrollment_token: z.string().min(1) })
export type BasicEnrollment = z.infer<typeof enrollment>

export class BasicConsentRequired extends UnauthorizedError {
  constructor(readonly firstEnrollment = false) { super("Basic host enrollment requires fresh consent. Run /mcp-auth, select default and approve basic host enrollment.") }
}

export function parseBasicEnrollment(payload: unknown): BasicEnrollment {
  const result = enrollment.safeParse(payload)
  if (!result.success) throw new BasicConsentRequired()
  return result.data
}

type Exchange = { checkOwner: () => void; promise: Promise<StoredTokens> }
const exchanges = new WeakMap<Map<string, string>, Map<string, Exchange>>()

export class BasicAuthClient {
  readonly assertActive: () => void
  readonly issuer: string
  private readonly account: string
  private readonly persistent: AuthStorageOptions
  private readonly deniedKey: string

  constructor(private name: string, private url: string, private slot: string, private storage: AuthStorageOptions) {
    this.issuer = brokerEnrollmentIssuer(url)
    if (storage.persistence !== "session" || !storage.sessionEntries) throw new Error("Basic enrollment requires settings.oauthPersistence: session")
    this.persistent = storage.cohortCredentialStore ? { credentialStore: storage.cohortCredentialStore } : {}
    this.account = `basic-enrollment-${createHash("sha256").update(JSON.stringify([url, userInfo().username, slot])).digest("hex")}`
    this.deniedKey = JSON.stringify(["basic-consent-required", name, this.account])
    this.assertActive = captureBasicEnrollmentAuthority(name, storage, this.deniedKey)
  }

  invalidateAccessToken(observed: string | undefined): void {
    this.assertActive()
    const entry = getAuthForUrl(this.name, this.url, this.storage)
    const current = entry?.tokens
    if (current?.basicEnrollmentSlot !== this.slot || current.accessToken !== observed) return
    saveAuthEntry(this.name, { ...entry, tokens: { ...current, expiresAt: Math.floor(Date.now() / 1000) - 1 } }, this.url, this.storage)
  }

  install(payload: BasicEnrollment): void {
    this.assertActive()
    parseBasicEnrollment(payload)
    saveAuthEntry(this.account, { cohortCredential: payload.basic_enrollment_token }, this.url, this.persistent)
    this.saveSession(payload)
    this.storage.sessionEntries!.delete(this.deniedKey)
  }

  private saveSession(payload: z.infer<typeof session>): StoredTokens {
    const tokens = { accessToken: payload.access_token, scope: payload.scope, expiresAt: Date.parse(payload.expires_at) / 1000,
      issuer: this.issuer, basicEnrollmentSlot: this.slot }
    const entry = getAuthForUrl(this.name, this.url, this.storage)
    saveAuthEntry(this.name, { ...entry, tokens }, this.url, this.storage)
    return tokens
  }

  async tokens(fetchFn: FetchLike, check: () => void, signal?: AbortSignal): Promise<StoredTokens> {
    this.assertActive()
    const entries = this.storage.sessionEntries!
    if (entries.has(this.deniedKey)) throw new BasicConsentRequired()
    const current = getAuthForUrl(this.name, this.url, this.storage)?.tokens
    if (current?.basicEnrollmentSlot === this.slot && current.expiresAt !== undefined && current.expiresAt * 1000 > Date.now()) return current
    let pending = exchanges.get(entries)
    if (!pending) { pending = new Map(); exchanges.set(entries, pending) }
    const existing = pending.get(this.deniedKey)
    if (existing) {
      try { existing.checkOwner(); return abortable(existing.promise, signal) } catch { pending.delete(this.deniedKey) }
    }
    const proof = readBasicEnrollmentProof(this.account, this.url, this.persistent)
    if (!proof) throw new BasicConsentRequired(true)
    const operation = this.exchange(proof, fetchFn, check, signal, current?.basicEnrollmentSlot === this.slot ? current.accessToken : undefined)
    const owner = { promise: operation, checkOwner: () => { check(); this.assertActive() } }
    pending.set(this.deniedKey, owner)
    try { return await operation } finally {
      if (pending.get(this.deniedKey) === owner) pending.delete(this.deniedKey)
    }
  }

  private async exchange(proof: string, fetchFn: FetchLike, check: () => void, signal?: AbortSignal, previousAccessToken?: string): Promise<StoredTokens> {
    const response = await fetchFn(`${this.issuer}/token`, {
      method: "POST", redirect: "error", headers: { "content-type": "application/x-www-form-urlencoded" },
      ...(signal ? { signal } : {}),
      body: new URLSearchParams({ grant_type: "urn:mcp-broker:grant-type:basic-enrollment:v1", basic_enrollment_token: proof }),
    }).catch(() => {
      check()
      throw new Error("Broker basic enrollment exchange failed")
    })
    const payload: unknown = await response.json().catch(() => null)
    check()
    this.assertActive()
    if (!response.ok && z.object({ error: z.enum(["invalid_grant", "invalid_request"]) }).safeParse(payload).success) {
      this.storage.sessionEntries!.set(this.deniedKey, "1")
      throw new BasicConsentRequired()
    }
    const result = session.safeParse(payload)
    if (!response.ok || !result.success || result.data.access_token === previousAccessToken) throw new Error("Broker basic enrollment exchange failed")
    return this.saveSession(result.data)
  }
}
