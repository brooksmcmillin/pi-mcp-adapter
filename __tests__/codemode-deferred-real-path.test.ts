import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  createAgentSession,
  createCodemodeExtension,
  DefaultResourceLoader,
  SessionManager,
  SettingsManager,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";

type Session = Awaited<ReturnType<typeof createAgentSession>>["session"];

// Real Pi session, registered tools, nested-call pipeline, and stdio MCP transport.
async function withPiSession(
  options: { codemode?: boolean; extend?: (pi: ExtensionAPI) => void },
  run: (pi: { session: Session; toolCalls: Array<{ name: string; id: string; parent: string | undefined }> }) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "pi-mcp-codemode-deferred-"));
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  const originalArgv = [...process.argv];
  let session: Session | undefined;
  try {
    const agentDir = join(root, "agent");
    const cwd = join(root, "project");
    await Promise.all([mkdir(agentDir), mkdir(cwd)]);
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const configPath = join(agentDir, "mcp-adapter.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        fixture: { command: process.execPath, args: [resolve("__tests__/fixtures/structured-echo-server.mjs")] },
      },
      settings: { sampling: false, elicitation: false },
    }));
    process.argv.push("--mcp-config", configPath);
    const errors: string[] = [];
    const toolCalls: Array<{ name: string; id: string; parent: string | undefined }> = [];
    const settingsManager = SettingsManager.inMemory();
    const loader = new DefaultResourceLoader({
      cwd, agentDir, settingsManager, additionalExtensionPaths: [resolve("index.ts")],
      extensionFactories: [
        ...(options.codemode ? [createCodemodeExtension()] : []),
        (pi) => {
          pi.on("tool_call", (event) => {
            toolCalls.push({ name: event.toolName, id: event.toolCallId, parent: event.parentToolCallId });
          });
          options.extend?.(pi);
        },
      ],
    });
    await loader.reload();
    ({ session } = await createAgentSession({
      cwd, agentDir, resourceLoader: loader,
      sessionManager: SessionManager.inMemory(cwd), settingsManager, noTools: "builtin",
    }));
    await session.bindExtensions({ mode: "print", onError: error => errors.push(error.error) });
    await session.extensionRunner.emit({ type: "agent_start" });
    // Pi runs a nested call on behalf of the assistant message that issued the calling tool.
    session.agent.state.messages = [...session.agent.state.messages, {
      role: "assistant", content: [], api: "test", provider: "test", model: "test", stopReason: "toolUse", timestamp: Date.now(),
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    }];
    await run({ session, toolCalls });
    expect(errors).toEqual([]);
  } finally {
    try {
      await session?.extensionRunner.emit({ type: "session_shutdown", reason: "test" });
    } finally {
      session?.dispose();
      process.argv.splice(0, process.argv.length, ...originalArgv);
      if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
      await rm(root, { recursive: true, force: true });
    }
  }
}

// The documentation is the consumer implementation; execute its exact snippets to prevent drift.
const scriptingDoc = await readFile(resolve("docs/scripting.md"), "utf8");
const resultReader = scriptingDoc.match(/```js\n(function mcpValue[\s\S]*?)\n```/)![1];
const taskSummary = scriptingDoc.match(/```js\n(const result = await tools\.mcp__tasks__get_task[\s\S]*?)\n```/)![1];

describe("documented MCP result reader in Pi codemode", () => {
  it.each(["structured", "envelope", "text", "split-text"])("reads a bounded task from %s in one call", async (format) => {
    await withPiSession({ codemode: true }, async ({ session, toolCalls }) => {
      const runner = session.extensionRunner;
      await vi.waitFor(() => expect(runner.createToolContext("probe", undefined).tools.map(tool => tool.name))
        .toContain("mcp__fixture__get_task"), { timeout: 10_000 });
      const codemode = runner.getAllRegisteredTools().find(tool => tool.definition.name === "codemode")!.definition;
      const consumer = taskSummary.replace("tools.mcp__tasks__get_task", "tools.mcp__fixture__get_task")
        .replace('{ task_id: "task_123" }', JSON.stringify({ task_id: "task_123", format }));
      const result = await codemode.execute("read-task", { code: `${resultReader}\n${consumer}` }, undefined, undefined,
        runner.createToolContext("read-task", undefined));
      const text = result.content.map(block => block.type === "text" ? block.text : "").join("");
      expect(text).toContain("Script completed");
      expect(JSON.parse(text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)))
        .toEqual({ id: "task_123", title: "Sanitized task", status: "pending" });
      expect(text).not.toContain("not for model output");
      expect(toolCalls).toEqual([{ name: "mcp__fixture__get_task", id: "read-task/1", parent: "read-task" }]);
    });
  }, 20_000);

  it.each([
    ["plain", "Expected a complete task summary"],
    ["error", "MCP call failed"],
    ["omitted", "MCP result is incomplete"],
    ["truncated", "MCP result is incomplete"],
    ["partial", "Expected a complete task summary"],
    ["malformed-envelope", "Script error:"],
    ["ambiguous-text", "Expected a complete task summary"],
  ])("does not accept %s as a task body", async (format, message) => {
    await withPiSession({ codemode: true }, async ({ session, toolCalls }) => {
      const runner = session.extensionRunner;
      await vi.waitFor(() => expect(runner.createToolContext("probe", undefined).tools.map(tool => tool.name))
        .toContain("mcp__fixture__get_task"), { timeout: 10_000 });
      const codemode = runner.getAllRegisteredTools().find(tool => tool.definition.name === "codemode")!.definition;
      const consumer = taskSummary.replace("tools.mcp__tasks__get_task", "tools.mcp__fixture__get_task")
        .replace('{ task_id: "task_123" }', JSON.stringify({ task_id: "task_123", format }));
      const result = await codemode.execute("read-task", { code: `${resultReader}\n${consumer}` }, undefined, undefined,
        runner.createToolContext("read-task", undefined));
      const text = result.content.map(block => block.type === "text" ? block.text : "").join("");
      expect(text).toContain("Script failed");
      expect(text).toContain(message);
      expect(text).not.toContain("not for model output");
      expect(toolCalls).toHaveLength(1);
    });
  }, 20_000);

  it("preserves legitimate plain text and result fields without envelope opt-in", async () => {
    await withPiSession({ codemode: true }, async ({ session }) => {
      const runner = session.extensionRunner;
      const codemode = runner.getAllRegisteredTools().find(tool => tool.definition.name === "codemode")!.definition;
      const code = `${resultReader}\nreturn [
        mcpValue({ content: [{ type: "text", text: "Service is healthy" }] }),
        mcpValue({ structuredContent: { result: '{"domain":"value"}' } })
      ];`;
      const result = await codemode.execute("read-values", { code }, undefined, undefined,
        runner.createToolContext("read-values", undefined));
      const text = result.content.map(block => block.type === "text" ? block.text : "").join("");
      expect(text).toContain("Script completed");
      const values = JSON.parse(text.slice(text.indexOf("["), text.lastIndexOf("]") + 1));
      expect(values).toEqual(["Service is healthy", { result: '{"domain":"value"}' }]);
    });
  }, 20_000);
});

describe("Pi codemode reach to proxy-only MCP tools", () => {
  it("calls a proxy-only server's tool through ctx.executeTool and gets its CallToolResult", async () => {
    const originalDirectTools = process.env.MCP_DIRECT_TOOLS;
    delete process.env.MCP_DIRECT_TOOLS;
    try {
      await withPiSession({}, async ({ session }) => {
        const ctx = session.extensionRunner.createToolContext("codemode-call", undefined);

        await vi.waitFor(() => expect(ctx.tools.map(tool => tool.name)).toContain("mcp__fixture__echo"), { timeout: 10_000 });
        const outcome = await ctx.executeTool("mcp__fixture__echo", { value: "hi" });

        expect(outcome.isError).toBe(false);
        expect(outcome.result.structuredContent).toEqual({ content: outcome.result.content, structuredContent: { value: "hi" } });
        expect(outcome.result.content).toContainEqual({ type: "text", text: "hi" });
        expect(session.getActiveToolNames()).not.toContain("mcp__fixture__echo");
      });
    } finally {
      if (originalDirectTools !== undefined) process.env.MCP_DIRECT_TOOLS = originalDirectTools;
    }
  }, 20_000);

  // Runs under the suite's environment (`env -u MCP_DIRECT_TOOLS`), so it fails where the adapter's
  // kill switch keeps proxy calls in the proxy: MCP_DIRECT_TOOLS=__none__ registers no mcp__<ns>__<tool>.
  it("hands a script's namespace-proxy call off to the registered tool, one level below the proxy", async () => {
    await withPiSession({ codemode: true }, async ({ session, toolCalls }) => {
      const runner = session.extensionRunner;
      await vi.waitFor(() => expect(runner.createToolContext("probe", undefined).tools.map(tool => tool.name))
        .toContain("mcp__fixture__echo"), { timeout: 10_000 });
      const codemode = runner.getAllRegisteredTools().find(tool => tool.definition.name === "codemode")!.definition;

      const result = await codemode.execute(
        "cm-1",
        { code: 'return await tools.mcp__fixture({ tool: "echo", args: { value: "hi" } });' },
        undefined,
        undefined,
        runner.createToolContext("cm-1", undefined),
      );

      expect(result.content.map(block => block.type === "text" ? block.text : "").join("")).toContain("Script completed");
      expect(toolCalls).toEqual([
        { name: "mcp__fixture", id: "cm-1/1", parent: "cm-1" },
        { name: "mcp__fixture__echo", id: "cm-1/1/1", parent: "cm-1/1" },
      ]);
    });
  }, 20_000);

  // The fixture's `large` result is over the 50 KB output guard limit.
  it("gives a codemode script the whole result, called directly and through the namespace proxy", async () => {
    let flood: (() => Promise<void>) | undefined;
    // Between the script's two calls: thousands of other calls of the script that never finish.
    // However many there are, the script's own record must survive them.
    const extend = (pi: ExtensionAPI) => pi.on("tool_result", async (event) => {
      if (event.toolCallId === "cm-1/1") await flood?.();
    });
    await withPiSession({ codemode: true, extend }, async ({ session, toolCalls }) => {
      const runner = session.extensionRunner;
      await vi.waitFor(() => expect(runner.createToolContext("probe", undefined).tools.map(tool => tool.name))
        .toContain("mcp__fixture__large"), { timeout: 10_000 });
      const codemode = runner.getAllRegisteredTools().find(tool => tool.definition.name === "codemode")!.definition;
      flood = async () => {
        for (let index = 0; index < 4100; index++) {
          await runner.emitToolCall({ type: "tool_call", toolName: "mcp__fixture__large", toolCallId: `cm-1/blocked-${index}`, parentToolCallId: "cm-1", input: {} } as never);
        }
      };
      const code = `
        const direct = (await tools.mcp__fixture__large({})).content[0].text;
        const proxied = await tools.mcp__fixture({ tool: "large", args: {} });
        return JSON.stringify({ direct: JSON.parse(direct).length, directBytes: direct.length, proxied: JSON.parse(proxied).length, proxiedBytes: proxied.length });
      `;

      // As Pi runs a model-issued call: its tool_call hooks first, then the tool.
      await runner.emitToolCall({ type: "tool_call", toolName: "codemode", toolCallId: "cm-1", input: { code } });
      const result = await codemode.execute("cm-1", { code }, undefined, undefined, runner.createToolContext("cm-1", undefined));

      const output = result.content.map(block => block.type === "text" ? block.text : "").join("");
      expect(output).toContain("Script completed");
      expect(output).not.toMatch(/truncated|Full text saved/);
      const counts = JSON.parse(output.slice(output.indexOf("{"), output.lastIndexOf("}") + 1));
      expect(counts).toMatchObject({ direct: 2000, proxied: 2000 });
      expect(counts.directBytes).toBeGreaterThan(50 * 1024);
      expect(counts.proxiedBytes).toBe(counts.directBytes);
      expect(toolCalls.filter(call => call.id.includes("blocked"))).toHaveLength(4100);
      expect(toolCalls.filter(call => !call.id.includes("blocked")).map(call => [call.name, call.id])).toEqual([
        ["codemode", "cm-1"],
        ["mcp__fixture__large", "cm-1/1"],
        ["mcp__fixture", "cm-1/2"],
        ["mcp__fixture__large", "cm-1/2/1"],
      ]);
    });
  }, 20_000);

  it("still truncates the same result for the model's own proxy call and saves the full text", async () => {
    await withPiSession({}, async ({ session }) => {
      const runner = session.extensionRunner;
      await vi.waitFor(() => expect(runner.createToolContext("probe", undefined).tools.map(tool => tool.name))
        .toContain("mcp__fixture__large"), { timeout: 10_000 });
      const proxies = { mcp: { tool: "fixture_large" }, mcp__fixture: { tool: "large" } };
      for (const [name, params] of Object.entries(proxies)) {
        const proxy = runner.getAllRegisteredTools().find(tool => tool.definition.name === name)!.definition;
        // Recorded as the model's own call, so a proxy ancestor is classified, not just unknown.
        await runner.emitToolCall({ type: "tool_call", toolName: name, toolCallId: `${name}-call`, input: params });
        const result = await proxy.execute(`${name}-call`, params, undefined, undefined, runner.createToolContext(`${name}-call`, undefined));
        const text = result.content.map(block => block.type === "text" ? block.text : "").join("");
        expect(text, name).toContain("[MCP text output truncated");
        expect(text, name).toContain("Full MCP result saved as JSON to");
        expect(text.length, name).toBeLessThan(50 * 1024);
      }
    });
  }, 20_000);
});
