import { createServer } from "node:http";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import {
  createAgentSession,
  DefaultResourceLoader,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { getAuthStorageOptions, saveAuthEntry } from "../mcp-auth.ts";

it("reconnects with the same memory-only OAuth credential through real Pi reloads", async () => {
  const root = await mkdtemp(join(tmpdir(), "pi-oauth-reload-"));
  const agentDir = join(root, "agent");
  const cwd = join(root, "project");
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  const originalOAuthDir = process.env.MCP_OAUTH_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  delete process.env.MCP_OAUTH_DIR;
  const authorizations: Array<string | undefined> = [];
  let initializes = 0;
  const server = createServer(async (request, response) => {
    if (request.method !== "POST") {
      response.writeHead(request.method === "DELETE" ? 202 : 405).end();
      return;
    }
    authorizations.push(request.headers.authorization);
    if (request.headers.authorization !== "Bearer reload-token") {
      response.writeHead(401).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    if (body.id === undefined) {
      response.writeHead(202).end();
      return;
    }
    const result = body.method === "initialize"
      ? (initializes++, {
          protocolVersion: "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: "oauth-reload-fixture", version: "1" },
        })
      : { tools: [] };
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture address");
  const url = `http://127.0.0.1:${address.port}/mcp`;
  const configPath = join(agentDir, "mcp-adapter.json");
  const sessionManager = SessionManager.inMemory(cwd);
  let session: Awaited<ReturnType<typeof createAgentSession>>["session"] | undefined;
  const argvIndex = process.argv.length;
  try {
    await Promise.all([mkdir(agentDir, { recursive: true }), mkdir(cwd, { recursive: true })]);
    await writeFile(configPath, JSON.stringify({
      mcpServers: { broker: { url, auth: "oauth", lifecycle: "lazy" } },
      settings: { oauthPersistence: "session", sampling: false, elicitation: false },
    }));
    process.argv.push("--mcp-config", configPath);
    const settingsManager = SettingsManager.inMemory();
    const loader = new DefaultResourceLoader({
      cwd,
      agentDir,
      settingsManager,
      additionalExtensionPaths: [resolve("index.ts")],
    });
    const storage = getAuthStorageOptions(undefined, cwd, "session", undefined, sessionManager);
    // Stand in for completed pairing; the real transport must consume this entry.
    saveAuthEntry("broker", {
      tokens: { accessToken: "reload-token", refreshToken: "reload-refresh" },
      clientInfo: { clientId: "reload-client" },
    }, url, storage);
    await loader.reload();
    ({ session } = await createAgentSession({
      cwd, agentDir, resourceLoader: loader, sessionManager, settingsManager, noTools: "all",
    }));
    const errors: string[] = [];
    await session.bindExtensions({
      mode: "tui",
      uiContext: {
        notify: () => undefined,
        setStatus: () => undefined,
        theme: { fg: (_color: string, value: string) => value },
      } as any,
      onError: error => errors.push(error.error),
    });

    let previousInitializes = 0;
    for (let generation = 0; generation < 3; generation++) {
      if (generation > 0) await session.reload();
      const runner = session.extensionRunner!;
      const gateway = runner.getAllRegisteredTools().find(tool => tool.definition.name === "mcp");
      expect(gateway).toBeDefined();
      const result = await gateway!.definition.execute(
        `connect-${generation}`, { connect: "broker" }, undefined, undefined, runner.createContext(),
      );
      expect(result.content).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ text: expect.stringContaining("Failed to connect") }),
      ]));
      expect(initializes).toBeGreaterThan(previousInitializes);
      previousInitializes = initializes;
    }
    expect(authorizations.length).toBeGreaterThanOrEqual(3);
    expect(authorizations).toEqual(authorizations.map(() => "Bearer reload-token"));
    expect(errors).toEqual([]);
    const entries = await readdir(agentDir);
    expect(entries.some(name => name.startsWith("mcp-oauth"))).toBe(false);
  } finally {
    try {
      await session?.extensionRunner?.emit({ type: "session_shutdown", reason: "test-finally" });
    } finally {
      session?.dispose();
      process.argv.splice(argvIndex);
      if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
      if (originalOAuthDir === undefined) delete process.env.MCP_OAUTH_DIR;
      else process.env.MCP_OAUTH_DIR = originalOAuthDir;
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      await rm(root, { recursive: true, force: true });
    }
  }
}, 20_000);
