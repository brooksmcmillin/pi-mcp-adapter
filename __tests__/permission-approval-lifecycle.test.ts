import { afterEach, describe, expect, it, vi } from "vitest";
import open from "open";
import type { ElicitRequest, ElicitRequestFormParams } from "@modelcontextprotocol/client";
import { handleElicitationRequest, type ElicitationHandlerOptions } from "../elicitation-handler.ts";
import { PERMISSION_REQUEST_META, permissionRequest } from "../permission-approval.ts";

vi.mock("open", () => ({ default: vi.fn().mockResolvedValue(undefined) }));
afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); });

const pending = { request_id: "request-1", status: "pending", methods: ["totp", "passkey"], grant_id: null };
const approved = { ...pending, status: "approved", grant_id: 42 };
interface MockApprovalState {
  request_id: string;
  status: string;
  grant_id: number | null;
  methods?: string[];
  delivery?: { status: string; attempts: number }[];
}
function envelope(state: MockApprovalState) { return { content: [], structuredContent: state }; }
function request(methods = ["totp", "passkey"], seconds = 300): ElicitRequest {
  return {
    method: "elicitation/create",
    params: {
      message: "Trusted capability details; untrusted rationale separately labelled",
      requestedSchema: { type: "object", properties: {
        totp: { type: "string", pattern: "^[0-9]{6}$", title: "Human-presence code" },
      }, required: ["totp"] },
      _meta: { [PERMISSION_REQUEST_META]: {
        request_id: pending.request_id, methods, deadline: Date.now() / 1000 + seconds,
        approval_url: "https://broker.example/phone/?request=request-1",
      } },
    },
  };
}
function options(): ElicitationHandlerOptions & { ui: { select: ReturnType<typeof vi.fn>; input: ReturnType<typeof vi.fn>; notify: ReturnType<typeof vi.fn> } } {
  return {
    serverName: "broker", allowUrl: true, approvalPreference: "push",
    ui: { select: vi.fn().mockImplementation(() => new Promise(() => {})), input: vi.fn().mockResolvedValue("123456"), notify: vi.fn() },
    approvalClient: { callTool: vi.fn().mockResolvedValue(envelope(pending)) },
    onApprovalConfirmed: vi.fn().mockResolvedValue(undefined),
  };
}
const tick = () => new Promise<void>(resolve => setImmediate(resolve));

describe("request-bound permission approval", () => {
  it("old brokers retain the ordinary TOTP form even with push preference", async () => {
    const opts = options();
    opts.ui.select.mockResolvedValueOnce("Continue").mockResolvedValueOnce("Enter value").mockResolvedValueOnce("Submit");
    const legacy = request();
    delete legacy.params._meta;
    expect(await handleElicitationRequest(opts, legacy)).toEqual({ action: "accept", content: { totp: "123456" } });
    expect(opts.approvalClient!.callTool).not.toHaveBeenCalled();
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
  });

  it("only authoritative matching approval accepts and refreshes tools, once", async () => {
    const opts = options();
    vi.mocked(opts.approvalClient!.callTool).mockResolvedValue(envelope(approved));
    expect(await handleElicitationRequest(opts, request())).toEqual({ action: "accept", content: {} });
    expect(opts.approvalClient!.callTool).toHaveBeenCalledExactlyOnceWith(
      { name: "permission_request.status", arguments: { request_id: "request-1" } }, expect.objectContaining({ timeout: 5000 }));
    expect(opts.onApprovalConfirmed).toHaveBeenCalledTimes(1);
    expect(opts.ui.select.mock.calls[0][1]).toEqual(["Use TOTP", "Open approval page", "Cancel"]);
    expect(opts.ui.select.mock.calls[0][2].signal.aborted).toBe(true);
  });

  it.each(["denied", "expired", "cancelled", "stale"])("shows %s without retry, fallback or refresh", async status => {
    const opts = options();
    vi.mocked(opts.approvalClient!.callTool).mockResolvedValue(envelope({ ...pending, status }));
    expect((await handleElicitationRequest(opts, request())).action).toBe(status === "denied" ? "decline" : "cancel");
    expect(opts.ui.notify).toHaveBeenCalledWith(expect.stringContaining(status), "warning");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(opts.approvalClient!.callTool).toHaveBeenCalledTimes(1);
  });

  it("TOTP fallback is explicit and submits proof to the broker without locally granting or cancelling it", async () => {
    const opts = options();
    opts.ui.select.mockResolvedValueOnce("Use TOTP").mockResolvedValueOnce("Continue").mockResolvedValueOnce("Enter value").mockResolvedValueOnce("Submit");
    expect(await handleElicitationRequest(opts, request())).toEqual({ action: "accept", content: { totp: "123456" } });
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(vi.mocked(opts.approvalClient!.callTool).mock.calls.map(c => c[0].name)).toEqual(["permission_request.status"]);
  });

  it("TOTP form can switch to push on the same request", async () => {
    const opts = options();
    opts.approvalPreference = "totp";
    opts.ui.select.mockResolvedValueOnce("Use Push");
    vi.mocked(opts.approvalClient!.callTool).mockResolvedValue(envelope(approved));
    expect(await handleElicitationRequest(opts, request())).toEqual({ action: "accept", content: {} });
    expect(opts.ui.select.mock.calls[0][1]).toContain("Use Push");
    expect(opts.ui.input).not.toHaveBeenCalled();
  });

  it("never offers or uses TOTP under passkey-only policy", async () => {
    const opts = options();
    opts.ui.select.mockResolvedValueOnce("Cancel");
    vi.mocked(opts.approvalClient!.callTool).mockImplementation(async ({ name }) => name === "permission_request.cancel"
      ? envelope({ ...pending, status: "cancelled" }) : envelope(pending));
    expect((await handleElicitationRequest(opts, request(["passkey"]))).action).toBe("cancel");
    expect(opts.ui.select.mock.calls[0][1]).toEqual(["Open approval page", "Cancel"]);
    expect(opts.ui.input).not.toHaveBeenCalled();
  });

  it("opens the page only on explicit selection; opening alone cannot approve", async () => {
    const opts = options();
    opts.ui.select.mockResolvedValueOnce("Open approval page").mockResolvedValueOnce("Cancel");
    expect((await handleElicitationRequest(opts, request())).action).toBe("cancel");
    expect(opts.ui.select.mock.calls[0][0]).toContain("Page: https://broker.example/phone/?request=request-1");
    expect(open).toHaveBeenCalledWith("https://broker.example/phone/?request=request-1");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(opts.approvalClient!.callTool).toHaveBeenLastCalledWith(expect.objectContaining({ name: "permission_request.cancel" }), expect.anything());
  });

  it("delivery failure stays pending and exposes explicit fallback/page rather than approving", async () => {
    const opts = options();
    vi.mocked(opts.approvalClient!.callTool).mockResolvedValue(envelope({ ...pending, delivery: [{ status: "failed", attempts: 3 }] }));
    const controller = new AbortController();
    const result = handleElicitationRequest(opts, request(), controller.signal);
    await tick();
    expect(opts.ui.notify).toHaveBeenCalledWith(expect.stringContaining("Push delivery failed"), "warning");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    controller.abort();
    expect((await result).action).toBe("cancel");
  });

  it("the broker deadline bounds waiting even while prompts pause tool deadlines", async () => {
    vi.useFakeTimers();
    const opts = options();
    const result = handleElicitationRequest(opts, request(["passkey"], 2));
    await vi.advanceTimersByTimeAsync(2001);
    expect((await result).action).toBe("cancel");
    expect(opts.ui.notify).toHaveBeenCalledWith(expect.stringContaining("deadline expired"), "warning");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(vi.mocked(opts.approvalClient!.callTool).mock.calls.every(c => ["permission_request.status", "permission_request.cancel"].includes(c[0].name))).toBe(true);
  });

  it("disconnect cancels the matching request and ignores a late approval from an uncooperative transport", async () => {
    const opts = options();
    let late!: (value: ReturnType<typeof envelope>) => void;
    vi.mocked(opts.approvalClient!.callTool).mockImplementation(({ name }) => name === "permission_request.status"
      ? new Promise(resolve => { late = resolve; }) : Promise.resolve(envelope({ ...pending, status: "cancelled" })));
    const controller = new AbortController();
    const result = handleElicitationRequest(opts, request(), controller.signal);
    await tick();
    controller.abort();
    expect((await result).action).toBe("cancel");
    late(envelope(approved));
    await tick();
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(opts.approvalClient!.callTool).toHaveBeenCalledTimes(2);
  });

  it("reports ambiguous cancellation and does not replay any operation", async () => {
    const opts = options();
    opts.ui.select.mockResolvedValue("Cancel");
    vi.mocked(opts.approvalClient!.callTool).mockRejectedValue(new Error("connection closed"));
    expect((await handleElicitationRequest(opts, request())).action).toBe("cancel");
    expect(opts.ui.notify).toHaveBeenCalledWith(expect.stringContaining("Cancellation unconfirmed"), "warning");
    expect(vi.mocked(opts.approvalClient!.callTool).mock.calls.every(c => c[0].name !== "permission_request.create")).toBe(true);
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
  });

  it.each([
    { ...approved, request_id: "another-request" }, { ...approved, grant_id: null },
  ])("cannot accept a substituted request or grantless approval", async state => {
    const opts = options();
    vi.mocked(opts.approvalClient!.callTool).mockResolvedValue(envelope(state));
    expect((await handleElicitationRequest(opts, request())).action).toBe("cancel");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
  });

  it.each(["pending", "unknown"])("marks %s cancellation outcome unconfirmed", async status => {
    const opts = options();
    opts.ui.select.mockResolvedValue("Cancel");
    vi.mocked(opts.approvalClient!.callTool).mockImplementation(async ({ name }) => envelope({
      ...pending, status: name === "permission_request.cancel" ? status : "pending",
    }));
    expect((await handleElicitationRequest(opts, request())).action).toBe("cancel");
    expect(opts.ui.notify).toHaveBeenCalledWith(expect.stringContaining("Cancellation unconfirmed"), "warning");
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
  });

  it("repeated TOTP/Push switching preserves cancellation and ignores every obsolete late approval", async () => {
    const opts = options();
    opts.approvalPreference = "totp";
    opts.ui.select.mockResolvedValueOnce("Use Push").mockResolvedValueOnce("Use TOTP")
      .mockResolvedValueOnce("Use Push").mockResolvedValueOnce("Use TOTP");
    const late: ((value: ReturnType<typeof envelope>) => void)[] = [];
    vi.mocked(opts.approvalClient!.callTool).mockImplementation(({ name }) => name === "permission_request.status"
      ? new Promise(resolve => { late.push(resolve); }) : Promise.resolve(envelope({ ...pending, status: "cancelled" })));
    const controller = new AbortController();
    const result = handleElicitationRequest(opts, request(), controller.signal);
    await vi.waitFor(() => expect(opts.ui.select).toHaveBeenCalledTimes(5));
    expect(late).toHaveLength(2);
    controller.abort();
    expect((await result).action).toBe("cancel");
    for (const resolve of late) resolve(envelope(approved));
    await tick();
    expect(opts.onApprovalConfirmed).not.toHaveBeenCalled();
    expect(opts.ui.input).not.toHaveBeenCalled();
    expect(vi.mocked(opts.approvalClient!.callTool).mock.calls.map(c => c[0])).toEqual([
      { name: "permission_request.status", arguments: { request_id: "request-1" } },
      { name: "permission_request.status", arguments: { request_id: "request-1" } },
      { name: "permission_request.cancel", arguments: { request_id: "request-1" } },
    ]);
  });

  it("invalid metadata fails closed instead of falling back to ordinary acceptance", () => {
    const params = request().params as ElicitRequestFormParams;
    params._meta![PERMISSION_REQUEST_META] = { methods: ["passkey"] };
    expect(() => permissionRequest(params)).toThrow("Invalid request-bound");
  });
});
