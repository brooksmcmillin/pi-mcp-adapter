import { afterEach, expect, it, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { McpServerManager } from "../server-manager.ts";
import { callToolPausingForElicitation } from "../elicitation-handler.ts";

const managers: McpServerManager[] = [];
afterEach(async () => { await Promise.all(managers.splice(0).map(manager => manager.closeAll())); });
const fixture = fileURLToPath(new URL("./fixtures/permission-approval-server.mjs", import.meta.url));

it.each(["approved", "denied"])("real SDK preserves request metadata and %s outcome without privileged replay", async outcome => {
  const manager = new McpServerManager();
  managers.push(manager);
  const ui = { select: vi.fn(() => new Promise<string | undefined>(() => {})), input: vi.fn(), notify: vi.fn() };
  manager.setElicitationConfig({ ui, allowUrl: false, approvalPreference: "push" });
  const connection = await manager.connect("broker", { command: process.execPath, args: [fixture, outcome], tasks: false });
  expect(connection.tools.map(t => t.name)).not.toContain("privileged");
  expect(connection.tools.map(t => t.name)).toContain("always_second_page");
  const result = await connection.client.callTool({ name: "permission_request.create", arguments: {} });
  expect(result.structuredContent).toEqual({ request_id: "bound-request", status: outcome, grant_id: outcome === "approved" ? 7 : null });
  const text = result.content.find(item => item.type === "text");
  expect(text && JSON.parse(text.text).creates).toBe(1);
  expect(connection.tools.some(t => t.name === "privileged")).toBe(outcome === "approved");
  expect(connection.tools.map(t => t.name)).toContain("always_second_page");
  expect(ui.select).toHaveBeenCalledWith(expect.stringContaining("Waiting for iPhone approval"), ["Cancel"], expect.anything());
});

it("outer tool cancellation dismisses its correlated elicitation and cancels the same broker request", async () => {
  const manager = new McpServerManager();
  managers.push(manager);
  const ui = { select: vi.fn(() => new Promise<string | undefined>(() => {})), input: vi.fn(), notify: vi.fn() };
  manager.setElicitationConfig({ ui, allowUrl: false, approvalPreference: "push" });
  const connection = await manager.connect("broker", { command: process.execPath, args: [fixture, "pending"], tasks: false });
  const controller = new AbortController();
  const call = callToolPausingForElicitation(connection.client, { name: "permission_request.create", arguments: {} }, { signal: controller.signal });
  const stopped = expect(call).rejects.toThrow();
  await vi.waitFor(() => expect(ui.select).toHaveBeenCalled());
  controller.abort();
  await stopped;
  await vi.waitFor(() => expect(ui.select.mock.calls[0]?.[2]?.signal.aborted).toBe(true));
  await vi.waitFor(async () => {
    const result = await connection.client.callTool({ name: "permission_request.status", arguments: { request_id: "bound-request" } });
    expect(result.structuredContent?.status).toBe("cancelled");
  });
  expect(connection.tools.map(t => t.name)).not.toContain("privileged");
});
