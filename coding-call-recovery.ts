import { ProtocolError } from "@modelcontextprotocol/client"
import { setTimeout as sleep } from "node:timers/promises"
import { z } from "zod"
import { abortable } from "./abort.ts"
import { combineAbortSignals } from "./runtime-owner.ts"

const pauseSchema = z.object({
  version: z.literal(1), status: z.literal("authorization_paused"),
  authorization_ref: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  expires_at: z.string().datetime({ offset: true }), revision: z.number().int().positive(),
  status_route: z.literal("authorization.status"), renewal_requires_human: z.literal(true),
  retryable: z.literal(true), execution: z.literal("not_executed"), forwarded: z.literal(false),
})

/** Also used by the validated credential preflight, before the SDK sends a call. */
export class CodingAuthorizationPaused extends Error {
  constructor(readonly reference: string, readonly renewalUrl: string) {
    super(`Coding authorization paused. Open ${renewalUrl} for human renewal, then continue.`)
  }
}

export function rejectedCodingReference(error: unknown): string | undefined {
  if (!(error instanceof ProtocolError) || error.code !== -32003) return undefined
  const parsed = pauseSchema.safeParse(error.data)
  return parsed.success ? parsed.data.authorization_ref : undefined
}

/** Normalize only a matching tools/call HTTP rejection; never parse error prose. */
export async function codingHttpRejection(response: Response, body: string): Promise<ProtocolError | undefined> {
  if (response.status !== 403 || !response.headers.get("content-type")?.startsWith("application/json")) return undefined
  try {
    const request = JSON.parse(body)
    if (request.jsonrpc !== "2.0" || request.method !== "tools/call" || !["string", "number"].includes(typeof request.id)) return undefined
    const envelope = await response.clone().json()
    if (envelope.jsonrpc !== "2.0" || envelope.id !== request.id || "result" in envelope || typeof envelope.error?.message !== "string") return undefined
    const error = new ProtocolError(envelope.error.code, envelope.error.message, envelope.error.data)
    return rejectedCodingReference(error) ? error : undefined
  } catch { return undefined }
}

export const CODING_WAIT_BUDGET_MS = 5 * 60_000
export const CODING_WAIT_MAX_CHECKS = 40

export interface CodingWaitOptions {
  signal?: AbortSignal | undefined
  check: () => void
  notify?: ((message: string) => void) | undefined
}

/** Holds only this invocation's closure; no model turn, persisted bearer or background replay. */
export async function waitForCodingRenewal(
  pause: CodingAuthorizationPaused,
  recover: (signal: AbortSignal) => Promise<void>,
  options: CodingWaitOptions,
): Promise<void> {
  const deadline = AbortSignal.timeout(CODING_WAIT_BUDGET_MS)
  const signal = combineAbortSignals(options.signal, deadline)!
  options.notify?.(`Waiting up to 5 minutes for coding renewal: ${pause.renewalUrl}. Cancel to discard this pending call.`)
  try {
    for (let attempt = 0; attempt < CODING_WAIT_MAX_CHECKS; attempt++) {
      options.check(); signal.throwIfAborted()
      try {
        await abortable(recover(signal), signal)
        options.check(); signal.throwIfAborted()
        return
      } catch (error) {
        options.check(); signal.throwIfAborted()
        if (!(error instanceof CodingAuthorizationPaused) || error.reference !== pause.reference) throw error
      }
      const delay = Math.min(10_000, 1000 * 1.6 ** attempt) * (0.8 + Math.random() * 0.4)
      await sleep(delay, undefined, { signal })
    }
  } catch (error) {
    options.signal?.throwIfAborted()
    if (!deadline.aborted) throw error
  }
  throw new Error(`Coding renewal wait ended; this call was not executed. Open ${pause.renewalUrl}, then manually continue to retry the original tool and arguments in this conversation. No background retry remains.`)
}
