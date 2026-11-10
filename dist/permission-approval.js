import { setTimeout as delay } from "node:timers/promises";
import open from "open";
import { abortable, throwIfAborted } from "./abort.js";
import { combineAbortSignals } from "./runtime-owner.js";
export function validateApprovalPreference(value) {
    if (value !== "totp" && value !== "push" && value !== "ask") {
        throw new Error("settings.approvalPreference must be totp, push, or ask");
    }
}
export async function selectApprovalMethod(ui, methods, preference = "totp", signal) {
    const preferred = preference === "push" ? "passkey" : preference;
    if (preferred !== "ask" && methods.includes(preferred))
        return preferred;
    if (methods.length === 1)
        return methods[0];
    if (methods.length === 0)
        return undefined;
    const choices = [
        ...(methods.includes("totp") ? ["Use TOTP"] : []),
        ...(methods.includes("passkey") ? ["Use Push"] : []),
        "Cancel",
    ];
    const selected = await abortable(ui.select("Permission approval method", choices, signal ? { signal } : undefined), signal);
    return selected === "Use TOTP" ? "totp" : selected === "Use Push" ? "passkey" : undefined;
}
export const PERMISSION_REQUEST_META = "com.brooksmcmillin/permission-request";
function record(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
export function permissionRequest(params) {
    const raw = params._meta?.[PERMISSION_REQUEST_META];
    if (raw === undefined)
        return undefined;
    if (!record(raw) || typeof raw.request_id !== "string" || !raw.request_id
        || typeof raw.deadline !== "number" || !Number.isFinite(raw.deadline)
        || !Array.isArray(raw.methods) || raw.methods.length === 0
        || raw.methods.some(method => method !== "totp" && method !== "passkey")) {
        throw new Error("Invalid request-bound approval metadata; nothing approved");
    }
    let approval_url;
    if (raw.approval_url !== undefined) {
        const url = new URL(String(raw.approval_url));
        if (url.protocol !== "https:" || url.username || url.password) {
            throw new Error("Approval page must be an HTTPS URL without credentials");
        }
        approval_url = url.href;
    }
    return { request_id: raw.request_id, deadline: raw.deadline, methods: raw.methods, ...(approval_url ? { approval_url } : {}) };
}
export async function handlePermissionApproval(options, params, request, form, signal) {
    if (!options.approvalClient)
        throw new Error("Request-bound approval requires a connected MCP client");
    const client = options.approvalClient;
    const deadline = new AbortController();
    const waitSignal = combineAbortSignals(signal, deadline.signal) ?? deadline.signal;
    const timer = setTimeout(() => deadline.abort(new Error("Broker approval deadline expired")), Math.max(0, Math.min(request.deadline * 1000 - Date.now(), 2 ** 31 - 1)));
    let resolved = false;
    let submitted = false;
    const submitForm = async (switchToPush) => {
        const result = await form(waitSignal, switchToPush);
        submitted = result.action !== "cancel";
        return result;
    };
    const readState = async (name, callSignal) => {
        const result = await client.callTool({ name, arguments: { request_id: request.request_id } }, { signal: callSignal, timeout: 5000 });
        throwIfAborted(callSignal);
        const state = result.structuredContent;
        if (result.isError || !record(state) || state.request_id !== request.request_id || typeof state.status !== "string"
            || !["pending", "approved", "denied", "expired", "cancelled", "stale"].includes(state.status)) {
            throw new Error("Broker approval outcome is unconfirmed; no operation was retried");
        }
        if (state.status === "approved" && (typeof state.grant_id !== "number" || state.grant_id <= 0)) {
            throw new Error("Broker returned approval without a grant");
        }
        return state;
    };
    const waitForPhone = async () => {
        const finished = new AbortController();
        const active = combineAbortSignals(waitSignal, finished.signal) ?? finished.signal;
        const poll = async () => {
            let deliveryWarning = false;
            while (true) {
                throwIfAborted(active);
                const state = await readState("permission_request.status", active);
                if (state.status !== "pending") {
                    resolved = true;
                    if (state.status === "approved") {
                        options.ui.notify("iPhone approval confirmed by broker. No operation was replayed.", "info");
                        try {
                            await options.onApprovalConfirmed?.();
                        }
                        catch {
                            options.ui.notify("Approved; tool refresh failed. Refresh the tool list explicitly.", "warning");
                        }
                        return { action: "accept", content: {} };
                    }
                    options.ui.notify(`Permission request ${state.status}. Nothing approved; no automatic retry.`, "warning");
                    return { action: state.status === "denied" ? "decline" : "cancel" };
                }
                if (!deliveryWarning && Array.isArray(state.delivery) && state.delivery.some(item => record(item) && item.status === "failed")) {
                    deliveryWarning = true;
                    options.ui.notify("Push delivery failed. The request is still pending; open the approval page or explicitly use TOTP if offered.", "warning");
                }
                await delay(1000, undefined, { signal: active });
            }
        };
        const interaction = async () => {
            while (true) {
                const choices = [
                    ...(request.methods.includes("totp") ? ["Use TOTP"] : []),
                    ...(request.approval_url && options.allowUrl ? ["Open approval page"] : []),
                    "Cancel",
                ];
                const choice = await abortable(options.ui.select(`Waiting for iPhone approval\nServer: ${options.serverName}\nRequest: ${request.request_id}${request.approval_url ? `\nPage: ${request.approval_url}` : ""}\n\n${params.message}`, choices, { signal: active }), active);
                if (choice === "Use TOTP" && request.methods.includes("totp"))
                    return "totp";
                if (choice !== "Open approval page")
                    return { action: "cancel" };
                await abortable(open(request.approval_url), active);
            }
        };
        let result;
        try {
            result = await Promise.race([poll(), interaction()]);
        }
        finally {
            finished.abort();
        }
        return result === "totp" ? submitForm(waitForPhone) : result;
    };
    try {
        throwIfAborted(waitSignal);
        if (request.deadline * 1000 <= Date.now())
            throw new Error("Broker approval deadline expired");
        const method = await selectApprovalMethod(options.ui, request.methods, options.approvalPreference, waitSignal);
        if (!method)
            return { action: "cancel" };
        return method === "passkey" ? await waitForPhone()
            : await submitForm(request.methods.includes("passkey") ? waitForPhone : undefined);
    }
    catch (error) {
        options.ui.notify(deadline.signal.aborted ? "Broker approval deadline expired; no automatic retry."
            : `Approval stopped: ${error instanceof Error ? error.message : String(error)}. Outcome must be checked before retrying.`, "warning");
        return { action: "cancel" };
    }
    finally {
        clearTimeout(timer);
        // A local close/cancel is not proof of a broker-side cancellation. Reconcile
        // the same identity once, never replay create or the privileged operation.
        if (!resolved && !submitted) {
            try {
                const state = await readState("permission_request.cancel", AbortSignal.timeout(5000));
                if (state.status === "pending") {
                    options.ui.notify("Cancellation unconfirmed. Check request status before creating another request.", "warning");
                }
                else {
                    options.ui.notify(state.status === "approved"
                        ? "Approval won the cancellation race. No operation was replayed."
                        : `Permission request ${state.status}. No operation was replayed.`, "warning");
                }
            }
            catch {
                options.ui.notify("Cancellation unconfirmed. Check request status before creating another request.", "warning");
            }
        }
    }
}
//# sourceMappingURL=permission-approval.js.map