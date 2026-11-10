import type { ElicitRequestFormParams, ElicitResult } from "@modelcontextprotocol/client";
import type { ElicitationHandlerOptions, ElicitationUIContext } from "./elicitation-handler.ts";
export type ApprovalPreference = "totp" | "push" | "ask";
export type ApprovalMethod = "totp" | "passkey";
export declare function validateApprovalPreference(value: unknown): asserts value is ApprovalPreference;
export declare function selectApprovalMethod(ui: ElicitationUIContext, methods: ApprovalMethod[], preference?: ApprovalPreference, signal?: AbortSignal): Promise<ApprovalMethod | undefined>;
export declare const PERMISSION_REQUEST_META = "com.brooksmcmillin/permission-request";
interface PermissionRequest {
    request_id: string;
    deadline: number;
    methods: ApprovalMethod[];
    approval_url?: string;
}
export declare function permissionRequest(params: ElicitRequestFormParams): PermissionRequest | undefined;
export declare function handlePermissionApproval(options: ElicitationHandlerOptions, params: ElicitRequestFormParams, request: PermissionRequest, form: (signal: AbortSignal, switchToPush?: () => Promise<ElicitResult>) => Promise<ElicitResult>, signal?: AbortSignal): Promise<ElicitResult>;
export {};
