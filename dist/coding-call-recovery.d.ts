import { ProtocolError } from "@modelcontextprotocol/client";
/** Also used by the validated credential preflight, before the SDK sends a call. */
export declare class CodingAuthorizationPaused extends Error {
    readonly reference: string;
    readonly renewalUrl: string;
    constructor(reference: string, renewalUrl: string);
}
export declare function rejectedCodingReference(error: unknown): string | undefined;
/** Normalize only a matching tools/call HTTP rejection; never parse error prose. */
export declare function codingHttpRejection(response: Response, body: string): Promise<ProtocolError | undefined>;
export declare const CODING_WAIT_BUDGET_MS: number;
export declare const CODING_WAIT_MAX_CHECKS = 40;
export interface CodingWaitOptions {
    signal?: AbortSignal | undefined;
    check: () => void;
    notify?: ((message: string) => void) | undefined;
}
/** Holds only this invocation's closure; no model turn, persisted bearer or background replay. */
export declare function waitForCodingRenewal(pause: CodingAuthorizationPaused, recover: (signal: AbortSignal) => Promise<void>, options: CodingWaitOptions): Promise<void>;
