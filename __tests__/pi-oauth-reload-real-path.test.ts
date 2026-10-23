import { createServer } from "node:http";
import { mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, it, vi } from "vitest";
import {
  createAgentSession,
  DefaultResourceLoader,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { getAuthStorageOptions, resetTestAuthSecretStore, saveAuthEntry } from "../mcp-auth.ts";
import { CodingAuthClient } from "../mcp-coding-auth.ts";

it.each([
  { coding: false, replaceManager: false, programmaticFile: false },
  { coding: false, replaceManager: true, programmaticFile: false },
  { coding: true, replaceManager: false, programmaticFile: false },
  { coding: true, replaceManager: true, programmaticFile: false },
  { coding: false, replaceManager: true, programmaticFile: true },
  { coding: true, replaceManager: true, programmaticFile: true },
])("keeps OAuth lifecycle ownership ($coding coding, $replaceManager replacement, $programmaticFile factory)", async ({ coding, replaceManager, programmaticFile }) => {
  const root = await mkdtemp(join(tmpdir(), "pi-oauth-reload-"));
  const agentDir = join(root, "agent");
  const cwd = join(root, "project");
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  const originalOAuthDir = process.env.MCP_OAUTH_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  delete process.env.MCP_OAUTH_DIR;
  vi.stubEnv("PI_MCP_ADAPTER_TEST_AUTH_STORE", "memory");
  resetTestAuthSecretStore();
  const authorizations: Array<string | undefined> = [];
  let initializes = 0;
  let statusChecks = 0;
  const server = createServer(async (request, response) => {
    if (request.method !== "POST") {
      response.writeHead(request.method === "DELETE" ? 202 : 405).end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    if (request.url === "/broker/coding/status") {
      statusChecks++;
      expect(body).toEqual({ enrollment_token: "reload-enrollment" });
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ version: 1, status: "active", authorization_ref: "reload",
        credential_status: "active", renewal_route: "/broker/coding/renew?authorization_ref=reload" }));
      return;
    }
    authorizations.push(request.headers.authorization);
    if (request.headers.authorization !== "Bearer reload-token"
      || request.headers["x-mcp-broker-identity"] !== "broker-reload123") {
      response.writeHead(403).end();
      return;
    }
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
  const url = `http://127.0.0.1:${address.port}/broker/mcp`;
  const configPath = join(agentDir, "mcp-adapter.json");
  const codingConfig = { version: 1 as const, cohort: "reload" };
  let sessionManager = SessionManager.inMemory(cwd);
  let session: Awaited<ReturnType<typeof createAgentSession>>["session"] | undefined;
  const argvIndex = process.argv.length;
  const errors: string[] = [];
  const start = async () => {
    const settingsManager = SettingsManager.inMemory();
    const { createMcpAdapter } = await import("../index.ts");
    const loader = new DefaultResourceLoader({
      cwd, agentDir, settingsManager,
      ...(programmaticFile
        ? { extensionFactories: [{ name: "adapter", factory: createMcpAdapter({ configPath }) }] }
        : { additionalExtensionPaths: [resolve("index.ts")] }),
    });
    await loader.reload();
    ({ session } = await createAgentSession({
      cwd, agentDir, resourceLoader: loader, sessionManager, settingsManager, noTools: "all",
    }));
    await session.bindExtensions({
      mode: "tui",
      uiContext: {
        notify: () => undefined,
        setStatus: () => undefined,
        theme: { fg: (_color: string, value: string) => value },
      } as any,
      onError: error => errors.push(error.error),
    });
  };
  const stop = async () => {
    await session?.extensionRunner?.emit({ type: "session_shutdown", reason: "test-replacement" });
    session?.dispose();
    session = undefined;
  };
  try {
    await Promise.all([mkdir(agentDir, { recursive: true }), mkdir(cwd, { recursive: true })]);
    await writeFile(configPath, JSON.stringify({
      mcpServers: { broker: { url, auth: "oauth", lifecycle: "lazy",
        headers: { "X-MCP-Broker-Identity": "broker-reload123" },
        ...(coding ? { oauth: { codingEnrollment: codingConfig } } : {}),
      } },
      settings: { oauthPersistence: "session", sampling: false, elicitation: false },
    }));
    process.argv.push("--mcp-config", configPath);
    const storage = getAuthStorageOptions(undefined, cwd, "session", undefined, sessionManager,
      programmaticFile ? undefined : configPath);
    // Stand in for completed consent; real Pi initialization and SDK transports consume the retained entry.
    if (coding) {
      new CodingAuthClient("broker", url, codingConfig, storage).install({
        version: 1, token_type: "Bearer", scope: "profile:coding",
        access_token: "reload-token", refresh_token: "reload-refresh", enrollment_token: "reload-enrollment",
        authorization_ref: "reload", expires_at: new Date(Date.now() + 3600_000).toISOString(),
      }, () => {});
    } else {
      saveAuthEntry("broker", {
        tokens: { accessToken: "reload-token", refreshToken: "reload-refresh" },
        clientInfo: { clientId: "reload-client" },
      }, url, storage);
    }
    await start();
    let previousInitializes = 0;
    for (let generation = 0; generation < 3; generation++) {
      if (generation > 0) {
        if (replaceManager) {
          await stop();
          sessionManager = SessionManager.inMemory(cwd);
          await start();
        } else {
          await session!.reload();
        }
      }
      const runner = session!.extensionRunner!;
      const gateway = runner.getAllRegisteredTools().find(tool => tool.definition.name === "mcp");
      expect(gateway).toBeDefined();
      const result = await gateway!.definition.execute(
        `connect-${generation}`, { connect: "broker" }, undefined, undefined, runner.createContext(),
      );
      if (programmaticFile && generation > 0) {
        expect(result.content).toEqual(expect.arrayContaining([
          expect.objectContaining({ text: expect.stringContaining("Failed to connect") }),
        ]));
        expect(initializes).toBe(previousInitializes);
        continue;
      }
      expect(authorizations).toContain("Bearer reload-token");
      expect(result.content).not.toEqual(expect.arrayContaining([
        expect.objectContaining({ text: expect.stringContaining("Failed to connect") }),
      ]));
      expect(initializes).toBeGreaterThan(previousInitializes);
      previousInitializes = initializes;
    }
    expect(authorizations.length).toBeGreaterThanOrEqual(3);
    if (!programmaticFile) expect(authorizations).toEqual(authorizations.map(() => "Bearer reload-token"));
    expect(statusChecks > 0).toBe(coding);
    expect(errors).toEqual([]);
    const entries = await readdir(agentDir);
    expect(entries.some(name => name.startsWith("mcp-oauth"))).toBe(false);
  } finally {
    try {
      await stop();
    } finally {
      process.argv.splice(argvIndex);
      if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
      if (originalOAuthDir === undefined) delete process.env.MCP_OAUTH_DIR;
      else process.env.MCP_OAUTH_DIR = originalOAuthDir;
      vi.unstubAllEnvs();
      resetTestAuthSecretStore();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      await rm(root, { recursive: true, force: true });
    }
  }
}, 30_000);
