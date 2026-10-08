import { createHash } from "node:crypto";
import { z } from "zod";
import { abortable } from "./abort.js";
import { combineAbortSignals } from "./runtime-owner.js";
import { getAuthForUrl, getAuthStorageIdentity, invalidateAuthEntryCache, saveAuthEntry, } from "./mcp-auth.js";
const credentialSchema = z.object({
    version: z.literal(1), token_type: z.literal("Bearer"), scope: z.literal("profile:coding"),
    access_token: z.string().min(1), refresh_token: z.string().min(1), enrollment_token: z.string().min(1),
    authorization_ref: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
    expires_at: z.string().datetime({ offset: true }), cohort_credential: z.string().min(1).optional(),
});
const statusSchema = z.object({
    version: z.literal(1), status: z.enum(["active", "authorization_paused"]),
    authorization_ref: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
    credential_status: z.enum(["active", "expired"]), renewal_route: z.string(),
});
const unsupported = "Broker coding API v1 is required; upgrade the broker or disable oauth.codingEnrollment and use ordinary human OAuth consent.";
const terminal = "Coding enrollment revoked or invalid; start fresh human consent.";
const REGISTRY = Symbol.for("pi-mcp-adapter.coding-launches.v1");
const host = globalThis;
const registry = host[REGISTRY] ??= new WeakMap();
function launchStates(storage) {
    if (!storage.sessionEntries)
        throw new Error("Coding enrollment requires adapter-owned session storage");
    let states = registry.get(storage.sessionEntries);
    if (!states) {
        states = new Map();
        registry.set(storage.sessionEntries, states);
    }
    return states;
}
export function logoutCodingLaunch(name, storage) {
    if (storage.persistence !== "session" || !storage.sessionEntries)
        return;
    for (const [key, state] of launchStates(storage)) {
        if (JSON.parse(key)[0] === name) {
            state.denied = true;
            state.credentials = undefined;
        }
    }
}
export function validateCodingConfig(value) {
    const parsed = z.object({ version: z.literal(1), cohort: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/) }).strict().safeParse(value);
    if (!parsed.success)
        throw new Error("oauth.codingEnrollment requires version: 1 and a non-secret cohort slot (letters, digits, _ or -)");
    return parsed.data;
}
/** Cohort names select private secure-store entries; they are never authority. */
export class CodingAuthClient {
    name;
    url;
    storage;
    state;
    cohortAccount;
    persistent;
    issuer;
    constructor(name, url, config, storage) {
        this.name = name;
        this.url = url;
        this.storage = storage;
        const endpoint = new URL(url);
        if (endpoint.pathname !== "/broker/mcp" || endpoint.search || endpoint.hash || endpoint.username || endpoint.password
            || (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(endpoint.hostname)))) {
            throw new Error("Coding enrollment requires the broker /broker/mcp HTTPS endpoint (HTTP is allowed only on loopback)");
        }
        if (storage.persistence !== "session")
            throw new Error("Coding enrollment requires settings.oauthPersistence: session; access/refresh tokens must never be shared");
        this.issuer = `${endpoint.origin}/broker`;
        this.persistent = { ...(storage.cohortCredentialStore ? { credentialStore: storage.cohortCredentialStore } : {}) };
        this.cohortAccount = `coding-cohort-${createHash("sha256").update(JSON.stringify([url, config.cohort])).digest("hex")}`;
        const key = JSON.stringify([name, url, getAuthStorageIdentity(storage), config.cohort]);
        const launches = launchStates(storage);
        let state = launches.get(key);
        if (!state) {
            state = { denied: false };
            launches.set(key, state);
        }
        this.state = state;
    }
    parseCredentials(payload) {
        const parsed = credentialSchema.safeParse(payload);
        if (!parsed.success)
            throw new Error(unsupported + " Select shared coding in the human consent form.");
        return parsed.data;
    }
    install(payload, check) {
        check();
        if (payload.cohort_credential) {
            saveAuthEntry(this.cohortAccount, { cohortCredential: payload.cohort_credential, cohortReference: payload.authorization_ref }, this.url, this.persistent);
        }
        check();
        const entry = getAuthForUrl(this.name, this.url, this.storage) ?? {};
        saveAuthEntry(this.name, { ...entry, tokens: this.toStored(payload) }, this.url, this.storage);
        this.state.credentials = payload;
        this.state.denied = false;
    }
    toStored(payload) {
        return { accessToken: payload.access_token, refreshToken: payload.refresh_token, expiresAt: Date.parse(payload.expires_at) / 1000,
            scope: payload.scope, issuer: this.issuer };
    }
    logout() {
        this.state.denied = true;
        this.state.credentials = undefined;
    }
    async tokens(fetchFn, check, signal, mode = "ensure") {
        const assert = () => { check(); signal?.throwIfAborted(); if (this.state.denied)
            throw new Error(terminal); };
        assert();
        // One rotation per launch, even when different SDK providers overlap.
        if (this.state.pending) {
            const pending = this.state.pending, pendingMode = this.state.pendingMode;
            const result = await abortable(pending, signal);
            assert();
            if (pendingMode === mode)
                return result;
            if (this.state.pending === pending)
                this.state.pending = undefined;
            return this.tokens(fetchFn, check, signal, mode);
        }
        const operation = this.recover(fetchFn, assert, signal, mode);
        this.state.pending = operation;
        this.state.pendingMode = mode;
        try {
            const result = await operation;
            assert();
            return result;
        }
        finally {
            if (this.state.pending === operation)
                this.state.pending = undefined;
        }
    }
    paused(reference) {
        if (!reference || !/^[A-Za-z0-9_-]{1,128}$/.test(reference))
            return new Error("Coding authorization paused; use the common human renewal page, then continue");
        const route = new URL(`/broker/coding/renew?authorization_ref=${reference}`, this.issuer).toString();
        return new Error(`Coding authorization paused. Open ${route} for human renewal, then continue.`);
    }
    async recover(fetchFn, check, signal, mode) {
        let pausedError = this.paused(this.state.credentials?.authorization_ref);
        const request = async (route, body) => {
            check();
            const requestSignal = combineAbortSignals(signal, AbortSignal.timeout(30_000));
            try {
                const response = await abortable(fetchFn(`${this.issuer}/coding/${route}`, {
                    method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
                    body: JSON.stringify(body), redirect: "error", signal: requestSignal,
                }), requestSignal);
                const payload = await abortable(response.json(), requestSignal);
                check();
                if (!response.ok) {
                    const error = z.object({ error: z.string() }).safeParse(payload);
                    if (error.success && error.data.error === "invalid_grant") {
                        this.state.denied = true;
                        throw new Error(terminal);
                    }
                    if (error.success && error.data.error === "authorization_paused")
                        throw pausedError;
                    if ([404, 405].includes(response.status))
                        throw new Error(unsupported);
                    throw new Error("Broker coding request failed");
                }
                return payload;
            }
            catch (error) {
                check();
                if (error === pausedError || (error instanceof Error && [terminal, unsupported, "Broker coding request failed"].includes(error.message)))
                    throw error;
                throw new Error("Broker coding request failed; continue to check status (do not replay a credential rotation)");
            }
        };
        const current = this.state.credentials;
        if (!current) {
            invalidateAuthEntryCache(this.cohortAccount, this.persistent);
            const cohort = getAuthForUrl(this.cohortAccount, this.url, this.persistent);
            check();
            if (!cohort?.cohortCredential)
                return null;
            pausedError = this.paused(cohort.cohortReference);
            const payload = this.parseCredentials(await request("enroll", { cohort_credential: cohort.cohortCredential }));
            check();
            if (this.state.credentials !== undefined)
                throw new Error("Coding credentials changed while enrolling");
            this.install(payload, check);
            return this.toStored(payload);
        }
        const parsed = statusSchema.safeParse(await request("status", { enrollment_token: current.enrollment_token }));
        if (!parsed.success)
            throw new Error(unsupported);
        const status = parsed.data;
        const expectedRoute = `/broker/coding/renew?authorization_ref=${current.authorization_ref}`;
        if (status.authorization_ref !== current.authorization_ref || status.renewal_route !== expectedRoute)
            throw new Error("Invalid coding renewal guidance");
        check();
        if (status.status === "authorization_paused") {
            throw pausedError;
        }
        // SDK auth reads need the old refresh pair after the status gate, not a first
        // rotation followed by a second rotation in its token-endpoint request.
        if (mode === "status" || (mode !== "replace" && status.credential_status === "active" && Date.parse(current.expires_at) > Date.now())) {
            return this.toStored(current);
        }
        const replacement = this.parseCredentials(await request("replace", { enrollment_token: current.enrollment_token, refresh_token: current.refresh_token }));
        if (replacement.authorization_ref !== current.authorization_ref || replacement.cohort_credential !== undefined)
            throw new Error("Invalid coding replacement response");
        check();
        if (this.state.credentials !== current)
            throw new Error("Coding credentials changed while rotating");
        this.install(replacement, check);
        return this.toStored(replacement);
    }
}
//# sourceMappingURL=mcp-coding-auth.js.map