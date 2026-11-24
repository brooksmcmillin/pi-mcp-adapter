import { createHash } from "node:crypto";
import { userInfo } from "node:os";
import { UnauthorizedError } from "@modelcontextprotocol/client";
import { z } from "zod";
import { abortable } from "./abort.js";
import { brokerEnrollmentIssuer } from "./mcp-coding-auth.js";
import { captureBasicEnrollmentAuthority, getAuthForUrl, readBasicEnrollmentProof, saveAuthEntry } from "./mcp-auth.js";
const session = z.object({
    version: z.literal(1), scope: z.literal("profile:default"), token_type: z.literal("Bearer"),
    access_token: z.string().min(1), expires_at: z.string().datetime({ offset: true }).refine(value => Date.parse(value) > Date.now()),
}).strict();
const enrollment = session.extend({ basic_enrollment_token: z.string().min(1) });
export class BasicConsentRequired extends UnauthorizedError {
    firstEnrollment;
    constructor(firstEnrollment = false) {
        super("Basic host enrollment requires fresh consent. Run /mcp-auth, select default and approve basic host enrollment.");
        this.firstEnrollment = firstEnrollment;
    }
}
export function parseBasicEnrollment(payload) {
    const result = enrollment.safeParse(payload);
    if (!result.success)
        throw new BasicConsentRequired();
    return result.data;
}
const exchanges = new WeakMap();
export class BasicAuthClient {
    name;
    url;
    slot;
    storage;
    assertActive;
    issuer;
    account;
    persistent;
    deniedKey;
    constructor(name, url, slot, storage) {
        this.name = name;
        this.url = url;
        this.slot = slot;
        this.storage = storage;
        this.issuer = brokerEnrollmentIssuer(url);
        if (storage.persistence !== "session" || !storage.sessionEntries)
            throw new Error("Basic enrollment requires settings.oauthPersistence: session");
        this.persistent = storage.cohortCredentialStore ? { credentialStore: storage.cohortCredentialStore } : {};
        this.account = `basic-enrollment-${createHash("sha256").update(JSON.stringify([url, userInfo().username, slot])).digest("hex")}`;
        this.deniedKey = JSON.stringify(["basic-consent-required", name, this.account]);
        this.assertActive = captureBasicEnrollmentAuthority(name, storage, this.deniedKey);
    }
    invalidateAccessToken(observed) {
        this.assertActive();
        const entry = getAuthForUrl(this.name, this.url, this.storage);
        const current = entry?.tokens;
        if (current?.basicEnrollmentSlot !== this.slot || current.accessToken !== observed)
            return;
        saveAuthEntry(this.name, { ...entry, tokens: { ...current, expiresAt: Math.floor(Date.now() / 1000) - 1 } }, this.url, this.storage);
    }
    install(payload) {
        this.assertActive();
        parseBasicEnrollment(payload);
        saveAuthEntry(this.account, { cohortCredential: payload.basic_enrollment_token }, this.url, this.persistent);
        this.saveSession(payload);
        this.storage.sessionEntries.delete(this.deniedKey);
    }
    saveSession(payload) {
        const tokens = { accessToken: payload.access_token, scope: payload.scope, expiresAt: Date.parse(payload.expires_at) / 1000,
            issuer: this.issuer, basicEnrollmentSlot: this.slot };
        const entry = getAuthForUrl(this.name, this.url, this.storage);
        saveAuthEntry(this.name, { ...entry, tokens }, this.url, this.storage);
        return tokens;
    }
    async tokens(fetchFn, check, signal) {
        this.assertActive();
        const entries = this.storage.sessionEntries;
        if (entries.has(this.deniedKey))
            throw new BasicConsentRequired();
        const current = getAuthForUrl(this.name, this.url, this.storage)?.tokens;
        if (current?.basicEnrollmentSlot === this.slot && current.expiresAt !== undefined && current.expiresAt * 1000 > Date.now())
            return current;
        let pending = exchanges.get(entries);
        if (!pending) {
            pending = new Map();
            exchanges.set(entries, pending);
        }
        const existing = pending.get(this.deniedKey);
        if (existing) {
            try {
                existing.checkOwner();
                return abortable(existing.promise, signal);
            }
            catch {
                pending.delete(this.deniedKey);
            }
        }
        const proof = readBasicEnrollmentProof(this.account, this.url, this.persistent);
        if (!proof)
            throw new BasicConsentRequired(true);
        const operation = this.exchange(proof, fetchFn, check, signal, current?.basicEnrollmentSlot === this.slot ? current.accessToken : undefined);
        const owner = { promise: operation, checkOwner: () => { check(); this.assertActive(); } };
        pending.set(this.deniedKey, owner);
        try {
            return await operation;
        }
        finally {
            if (pending.get(this.deniedKey) === owner)
                pending.delete(this.deniedKey);
        }
    }
    async exchange(proof, fetchFn, check, signal, previousAccessToken) {
        const response = await fetchFn(`${this.issuer}/token`, {
            method: "POST", redirect: "error", headers: { "content-type": "application/x-www-form-urlencoded" },
            ...(signal ? { signal } : {}),
            body: new URLSearchParams({ grant_type: "urn:mcp-broker:grant-type:basic-enrollment:v1", basic_enrollment_token: proof }),
        }).catch(() => {
            check();
            throw new Error("Broker basic enrollment exchange failed");
        });
        const payload = await response.json().catch(() => null);
        check();
        this.assertActive();
        if (!response.ok && z.object({ error: z.enum(["invalid_grant", "invalid_request"]) }).safeParse(payload).success) {
            this.storage.sessionEntries.set(this.deniedKey, "1");
            throw new BasicConsentRequired();
        }
        const result = session.safeParse(payload);
        if (!response.ok || !result.success || result.data.access_token === previousAccessToken)
            throw new Error("Broker basic enrollment exchange failed");
        return this.saveSession(result.data);
    }
}
//# sourceMappingURL=mcp-basic-auth.js.map