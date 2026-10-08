import type { FetchLike } from "@modelcontextprotocol/client";
import { z } from "zod";
import { type CodingWaitOptions } from "./coding-call-recovery.ts";
import { type AuthStorageOptions, type OAuthAuthority, type StoredTokens } from "./mcp-auth.ts";
export interface CodingEnrollmentConfig {
    version: 1;
    cohort: string;
}
declare const credentialSchema: z.ZodObject<{
    version: z.ZodLiteral<1>;
    token_type: z.ZodLiteral<"Bearer">;
    scope: z.ZodLiteral<"profile:coding">;
    access_token: z.ZodString;
    refresh_token: z.ZodString;
    enrollment_token: z.ZodString;
    authorization_ref: z.ZodString;
    expires_at: z.ZodString;
    cohort_credential: z.ZodOptional<z.ZodString>;
}, z.core.$strip>;
export type CodingCredentials = z.infer<typeof credentialSchema>;
type RecoveryMode = "ensure" | "status" | "replace";
export declare function getRetainedCodingConfig(name: string, url: string, storage: AuthStorageOptions): CodingEnrollmentConfig | undefined;
export declare function logoutCodingLaunch(name: string, storage: AuthStorageOptions): void;
export declare function validateCodingConfig(value: unknown): CodingEnrollmentConfig;
/** Cohort names select private secure-store entries; they are never authority. */
export declare class CodingAuthClient {
    private name;
    private url;
    private storage;
    private readonly state;
    private readonly cohortAccount;
    private readonly persistent;
    readonly issuer: string;
    constructor(name: string, url: string, config: CodingEnrollmentConfig, storage: AuthStorageOptions);
    parseCredentials(payload: unknown): CodingCredentials;
    install(payload: CodingCredentials, check: OAuthAuthority, recovery?: boolean): void;
    private toStored;
    logout(): void;
    tokens(fetchFn: FetchLike, check: OAuthAuthority, signal?: AbortSignal, mode?: RecoveryMode): Promise<StoredTokens | null>;
    runPending<T>(call: () => Promise<T>, fetchFn: FetchLike, options: CodingWaitOptions): Promise<T>;
    private paused;
    private recover;
}
export {};
