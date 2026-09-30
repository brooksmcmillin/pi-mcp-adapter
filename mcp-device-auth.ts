import { setTimeout as delay } from "node:timers/promises"
import {
  assertSecureTokenEndpoint,
  discoverOAuthServerInfo,
  registerClient,
  selectResourceURL,
  type AuthOptions,
  type FetchLike,
} from "@modelcontextprotocol/client"
import { OAuthTokensSchema } from "@modelcontextprotocol/core"
import { z } from "zod"
import { abortable, throwIfAborted } from "./abort.ts"
import { combineAbortSignals } from "./runtime-owner.ts"
import type { McpOAuthProvider } from "./mcp-oauth-provider.ts"
import type { OAuthAuthority } from "./mcp-auth.ts"

export const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
const MAX_PAIRING_MS = 30 * 60 * 1000
const deviceResponseSchema = z.object({
  device_code: z.string().min(1),
  user_code: z.string().regex(/^[A-Za-z0-9 -]{1,64}$/),
  verification_uri: z.string().max(2048).url(),
  expires_in: z.number().int().positive().finite(),
  interval: z.number().int().positive().finite().optional(),
})

/** Only human-visible fields, never the device secret or token response. */
export interface DeviceAuthorization {
  verificationUri: string
  userCode: string
}

export interface DeviceAuthOptions {
  discovery: Pick<AuthOptions, "resourceMetadataUrl" | "scope" | "skipIssuerMetadataValidation">
  signal?: AbortSignal
  authority: OAuthAuthority
  onDeviceAuthorization?: (authorization: DeviceAuthorization, signal: AbortSignal, cancel: () => void) => void | Promise<void>
}

function secureEndpoint(value: string): URL {
  try {
    const url = assertSecureTokenEndpoint(value)
    if (url.username || url.password || url.hash) throw new Error()
    return url
  } catch {
    throw new Error("Invalid device OAuth endpoint")
  }
}

function echoesDeviceSecret(value: string, secret: string): boolean {
  for (;;) {
    if (value.includes(secret)) return true
    if (!/%[\da-f]{2}/i.test(value)) return false
    try {
      const decoded = decodeURIComponent(value)
      if (decoded === value) return false
      value = decoded
    } catch {
      throw new Error("Invalid device OAuth verification URI")
    }
  }
}

/** Returns false only when discovery does not advertise device authorization. */
export async function authenticateDevice(
  provider: McpOAuthProvider,
  serverUrl: string,
  fetchFn: FetchLike,
  options: DeviceAuthOptions,
): Promise<boolean> {
  const check = () => { options.authority(); throwIfAborted(options.signal) }
  check()
  const discovery = await abortable(provider.discoveryState().then(state => state ?? discoverOAuthServerInfo(serverUrl, {
    ...(options.discovery.resourceMetadataUrl ? { resourceMetadataUrl: options.discovery.resourceMetadataUrl } : {}),
    ...(options.discovery.skipIssuerMetadataValidation === undefined ? {} : { skipIssuerMetadataValidation: options.discovery.skipIssuerMetadataValidation }),
    fetchFn,
  })), options.signal)
  check()
  const metadata = discovery.authorizationServerMetadata
  const endpoint = (metadata as { device_authorization_endpoint?: unknown } | undefined)?.device_authorization_endpoint
  if (typeof endpoint !== "string" || !metadata?.grant_types_supported?.includes(DEVICE_GRANT)) return false
  const deviceEndpoint = secureEndpoint(endpoint)
  if (!metadata.token_endpoint) throw new Error("Device OAuth metadata has no token endpoint")
  const tokenEndpoint = secureEndpoint(metadata.token_endpoint)
  await provider.saveDiscoveryState(discovery)
  check()
  let client = await provider.clientInformation()
  check()
  if (!client) {
    client = await abortable(registerClient(discovery.authorizationServerUrl, {
      metadata, clientMetadata: provider.clientMetadata, fetchFn,
    }), options.signal)
    check()
    await provider.saveClientInformation(client)
  }
  const resource = await selectResourceURL(serverUrl, provider, discovery.resourceMetadata)
  check()

  const request = async (url: URL, params: URLSearchParams, signal?: AbortSignal) => {
    check()
    throwIfAborted(signal)
    const headers = new Headers({ "content-type": "application/x-www-form-urlencoded", accept: "application/json" })
    await provider.addClientAuthentication(headers, params, url.toString(), metadata)
    check()
    throwIfAborted(signal)
    try {
      const response = await abortable(fetchFn(url, { method: "POST", headers, body: params, redirect: "error", ...(signal ? { signal } : {}) }), signal)
      const payload: unknown = await abortable(response.json(), signal)
      check()
      throwIfAborted(signal)
      return { ok: response.ok, payload }
    } catch (error) {
      check()
      throwIfAborted(signal)
      // A remote error body or transport diagnostic can contain pairing secrets.
      throw new Error("Device OAuth request failed")
    }
  }
  const initialParams = new URLSearchParams()
  if (resource) initialParams.set("resource", resource.toString())
  if (options.discovery.scope) initialParams.set("scope", options.discovery.scope)
  const initiatedAt = Date.now()
  const initiation = await request(deviceEndpoint, initialParams, options.signal)
  if (!initiation.ok) throw new Error("Device OAuth initiation failed")
  const parsed = deviceResponseSchema.safeParse(initiation.payload)
  if (!parsed.success) throw new Error("Invalid device OAuth response")
  const pairing = parsed.data
  const visible = Object.freeze({
    verificationUri: secureEndpoint(pairing.verification_uri).toString(),
    userCode: pairing.user_code,
  })
  if (Object.values(visible).some(value => echoesDeviceSecret(value, pairing.device_code))) {
    throw new Error("Invalid device OAuth verification URI")
  }
  const duration = Math.min(pairing.expires_in * 1000, MAX_PAIRING_MS)
  const remaining = initiatedAt + duration - Date.now()
  if (remaining <= 0) throw new Error("Device OAuth pairing expired")
  const lifetime = new AbortController()
  const timer = setTimeout(() => lifetime.abort(new Error("Device OAuth pairing expired")), remaining)
  const signal = combineAbortSignals(options.signal, lifetime.signal)!
  const deadline = initiatedAt + duration
  let interval = (pairing.interval ?? 5) * 1000
  try {
    if (options.onDeviceAuthorization) {
      await abortable(Promise.resolve(options.onDeviceAuthorization(visible, signal, () => lifetime.abort(new Error("Device OAuth pairing cancelled")))), signal)
    } else {
      console.log(`MCP Auth: Open ${visible.verificationUri}\nCode: ${visible.userCode}`)
    }
    for (;;) {
      check()
      throwIfAborted(signal)
      if (Date.now() + interval >= deadline) {
        await delay(Math.max(1, deadline - Date.now()), undefined, { signal })
        throw new Error("Device OAuth pairing expired")
      }
      await delay(interval, undefined, { signal })
      check()
      const params = new URLSearchParams({ grant_type: DEVICE_GRANT, device_code: pairing.device_code })
      if (resource) params.set("resource", resource.toString())
      const response = await request(tokenEndpoint, params, signal)
      if (response.ok) {
        const tokens = OAuthTokensSchema.safeParse(response.payload)
        if (!tokens.success) throw new Error("Invalid device OAuth token response")
        check()
        throwIfAborted(signal)
        await provider.saveTokens(tokens.data)
        check()
        throwIfAborted(signal)
        return true
      }
      const error = z.object({ error: z.string() }).safeParse(response.payload)
      if (error.success && error.data.error === "authorization_pending") continue
      if (error.success && error.data.error === "slow_down") { interval += 5000; continue }
      const reason = error.success && ["access_denied", "expired_token", "invalid_client", "invalid_grant", "invalid_target"].includes(error.data.error)
        ? error.data.error : "request_failed"
      throw new Error(`Device OAuth ${reason}; restart pairing to try again`)
    }
  } finally {
    clearTimeout(timer)
    lifetime.abort(new Error("Device OAuth pairing finished"))
  }
}
