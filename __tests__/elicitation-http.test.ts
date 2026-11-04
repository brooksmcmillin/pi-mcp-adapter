import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExtensionUIContext } from "@earendil-works/pi-coding-agent";
import { McpServerManager } from "../server-manager.ts";

const logs = vi.hoisted(() => ({ append: vi.fn() }));
vi.mock("../server-log.ts", () => ({ appendServerLogMessage: logs.append }));
const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
  logs.append.mockClear();
});

async function connect(ui: ExtensionUIContext, cancel = false) {
  const replies: unknown[] = [];
  let callResponse: http.ServerResponse | undefined;
  let callId: unknown;
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }
    let body = "";
    for await (const chunk of req) body += chunk;
    const message = JSON.parse(body);
    const json = (result: unknown) => res.writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
    if (message.method === "initialize") {
      json({ protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "approval", version: "1" } });
    } else if (message.method === "tools/list") {
      json({ tools: [{ name: "approve", inputSchema: { type: "object" } }] });
    } else if (message.method === "tools/call") {
      callResponse = res;
      callId = message.id;
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: "elicit-test", method: "elicitation/create", params: {
        message: "Approve synthetic access", requestedSchema: { type: "object", properties: {} },
      } })}\n\n`);
    } else if (message.id === "elicit-test") {
      replies.push(message);
      res.writeHead(202).end();
      callResponse?.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: callId, result: {
        content: [{ type: "text", text: JSON.stringify(message.result ?? message.error) }],
      } })}\n\n`);
    } else if (message.method === "notifications/initialized") {
      res.writeHead(202).end();
    } else {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }));
    }
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  cleanup.push(async () => {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No test port");
  const manager = new McpServerManager();
  cleanup.push(() => manager.closeAll());
  manager.setElicitationConfig({ ui, allowUrl: false });
  const connection = await manager.connect("approval", { url: `http://127.0.0.1:${address.port}/mcp` });
  const call = connection.client.callTool({ name: "approve", arguments: {} }, { timeout: 2000 });
  if (cancel) {
    await vi.waitFor(() => expect(ui.select).toHaveBeenCalled());
    callResponse!.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "elicit-test", reason: "Approval expired" } })}\n\n`);
    callResponse!.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: callId, result: { content: [{ type: "text", text: "timeout" }], isError: true } })}\n\n`);
  }
  return { result: await call, replies };
}

describe("HTTP POST SSE elicitation", () => {
  it.each(["Continue", "Decline", undefined])("delivers the prompt and posts the %s response", async choice => {
    const ui = { select: vi.fn(async () => choice), input: vi.fn(), notify: vi.fn() } as unknown as ExtensionUIContext;
    const { result, replies } = await connect(ui);
    expect(ui.select).toHaveBeenCalledWith(expect.stringContaining("MCP Input Request"), ["Continue", "Decline"], { signal: expect.any(AbortSignal) });
    const action = choice === "Continue" ? "accept" : choice === "Decline" ? "decline" : "cancel";
    expect(replies).toEqual([expect.objectContaining({ id: "elicit-test", result: expect.objectContaining({ action }) })]);
    expect(result.isError).not.toBe(true);
    expect(logs.append.mock.calls.map(call => call[2])).toEqual([
      { level: "info", logger: "elicitation", data: "received" },
      { level: "info", logger: "elicitation", data: "prompt_requested" },
      { level: "info", logger: "elicitation", data: "response_ready" },
    ]);
  });

  it("dismisses an open Pi dialog when the server cancels its request", async () => {
    let dismissed = false;
    const ui = { select: vi.fn((_title, _choices, options) => new Promise(resolve => {
      options?.signal?.addEventListener("abort", () => { dismissed = true; resolve(undefined); }, { once: true });
    })), input: vi.fn(), notify: vi.fn() } as unknown as ExtensionUIContext;
    const { result, replies } = await connect(ui, true);
    expect(result.isError).toBe(true);
    await vi.waitFor(() => expect(dismissed).toBe(true));
    expect(replies).toEqual([]);
    expect(logs.append).toHaveBeenLastCalledWith(expect.any(String), "approval", {
      level: "info", logger: "elicitation", data: "cancelled",
    });
  });
});
