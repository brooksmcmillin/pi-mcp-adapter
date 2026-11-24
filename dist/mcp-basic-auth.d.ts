import { UnauthorizedError, type FetchLike } from "@modelcontextprotocol/client";
import { z } from "zod";
import { type AuthStorageOptions, type StoredTokens } from "./mcp-auth.ts";
declare const enrollment: z.ZodObject<{
    version: z.ZodLiteral<1>;
    scope: z.ZodLiteral<"profile:default">;
    token_type: z.ZodLiteral<"Bearer">;
    access_token: z.ZodString;
    expires_at: z.ZodString;
    basic_enrollment_token: z.ZodString;
}, z.core.$strict>;
export type BasicEnrollment = z.infer<typeof enrollment>;
export declare class BasicConsentRequired extends UnauthorizedError {
    readonly firstEnrollment: boolean;
    constructor(firstEnrollment?: boolean);
}
export declare function parseBasicEnrollment(payload: unknown): BasicEnrollment;
export declare class BasicAuthClient {
    private name;
    private url;
    private slot;
    private storage;
    readonly assertActive: () => void;
    readonly issuer: string;
    private readonly account;
    private readonly persistent;
    private readonly deniedKey;
    constructor(name: string, url: string, slot: string, storage: AuthStorageOptions);
    invalidateAccessToken(observed: string | undefined): void;
    install(payload: BasicEnrollment): void;
    private saveSession;
    tokens(fetchFn: FetchLike, check: () => void, signal?: AbortSignal): Promise<StoredTokens>;
    private exchange;
}
export {};
