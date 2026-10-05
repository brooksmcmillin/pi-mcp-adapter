import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { McpServerManager } from "../server-manager.ts";
import { initializeMcp } from "../init.ts";
import { saveMetadataCache } from "../metadata-cache.ts";

const mocks = vi.hoisted(() => ({
  authenticateServer: vi.fn(),
  started: vi.fn(),
  tempDirs: [] as string[],
}));
vi.mock("../commands.ts", () => ({ authenticateServer: mocks.authenticateServer }));
vi.mock("../metadata-cache.ts", () => ({
  computeServerHash: vi.fn(() => "hash"),
  createCachedToolSelectorCandidateIndex: vi.fn(() => undefined),
  getMetadataCachePath: vi.fn(() => {
    const dir = mkdtempSync(join(tmpdir(), "pi-mcp-auto-auth-cache-"));
    mocks.tempDirs.push(dir);
    return join(dir, "cache.json");
  }),
  getMissingConfiguredDirectToolServers: vi.fn(() => []),
  isServerCacheValid: vi.fn(() => false),
  keepOutputShapes: vi.fn(() => undefined),
  loadMetadataCache: vi.fn(() => null),
  reconstructPromptMetadata: vi.fn(() => []),
  reconstructToolMetadata: vi.fn(() => []),
  saveMetadataCache: vi.fn(),
  serializePrompts: vi.fn(() => []),
  serializeResources: vi.fn(() => []),
  serializeTools: vi.fn(() => []),
}));

const states: Array<Awaited<ReturnType<typeof initializeMcp>>> = [];
const needsAuth = { status: "needs-auth", tools: [], resources: [] } as any;
const connected = { status: "connected", tools: [], resources: [], prompts: [] } as any;

async function boot(autoAuth = true, mode = "tui", hasUI = true, servers = ["broker"]) {
  const cwd = mkdtempSync(join(tmpdir(), "pi-mcp-auto-auth-init-"));
  mocks.tempDirs.push(cwd);
  const notify = vi.fn();
  const state = await initializeMcp({ getFlag: vi.fn() } as any, {
    cwd, hasUI, mode, ui: { notify, setStatus: vi.fn() },
    signal: new AbortController().signal,
  } as any, undefined, {
    onProjectTrustResolved: mocks.started,
    config: {
      mcpServers: Object.fromEntries(servers.map(name => [name, {
        url: `https://example.com/${name}/mcp`, auth: "oauth", lifecycle: "eager",
      }])),
      settings: { autoAuth, oauthPersistence: "session" },
    },
  });
  states.push(state);
  return { state, notify };
}

describe("startup autoAuth", () => {
  beforeEach(() => {
    mocks.authenticateServer.mockReset().mockResolvedValue({ ok: true });
    mocks.started.mockReset();
    vi.mocked(saveMetadataCache).mockClear();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(McpServerManager.prototype, "getConnection").mockReturnValue(needsAuth);
    vi.spyOn(McpServerManager.prototype, "close").mockResolvedValue();
  });
  afterEach(async () => {
    await Promise.all(states.splice(0).map(state => state.owner.stop("test cleanup")));
    for (const dir of mocks.tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("pairs using session credentials and reconnects before registering metadata", async () => {
    const connect = vi.spyOn(McpServerManager.prototype, "connect")
      .mockResolvedValueOnce(needsAuth).mockResolvedValue(connected);
    const { state, notify } = await boot();
    expect(mocks.authenticateServer).toHaveBeenCalledWith(
      "broker", state.config, expect.objectContaining({ hasUI: true }),
      expect.any(AbortSignal), state.oauthRuntime, state.authStorageOptions,
    );
    expect(connect).toHaveBeenCalledTimes(2);
    expect(state.sessionMetadata?.get("broker")).toMatchObject({ configHash: "hash", tools: [] });
    expect(saveMetadataCache).toHaveBeenCalledWith(
      { version: 1, servers: { broker: expect.objectContaining({ configHash: "hash", tools: [] }) } },
      { startupSnapshot: {} },
    );
    expect(state.failureTracker.has("broker")).toBe(false);
    expect(notify.mock.calls.some(([message]) => String(message).includes("Failed to connect"))).toBe(false);
  });

  it.each([
    [false, "tui", true], [true, "json", false], [true, "rpc", true], [true, "tui", false],
  ])("does not open pairing for autoAuth=%s mode=%s hasUI=%s", async (autoAuth, mode, hasUI) => {
    const connect = vi.spyOn(McpServerManager.prototype, "connect").mockResolvedValue(needsAuth);
    await boot(autoAuth, mode, hasUI);
    expect(mocks.authenticateServer).not.toHaveBeenCalled();
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("does not pair an already authenticated server", async () => {
    vi.spyOn(McpServerManager.prototype, "getConnection").mockReturnValue(connected);
    vi.spyOn(McpServerManager.prototype, "connect").mockResolvedValue(connected);
    await boot();
    expect(mocks.authenticateServer).not.toHaveBeenCalled();
  });

  it("leaves manual authentication available after cancelled pairing", async () => {
    mocks.authenticateServer.mockResolvedValue({ ok: false });
    const connect = vi.spyOn(McpServerManager.prototype, "connect").mockResolvedValue(needsAuth);
    const { state, notify } = await boot();
    expect(connect).toHaveBeenCalledTimes(1);
    expect(state.failureTracker.has("broker")).toBe(true);
    expect(notify).toHaveBeenCalledWith(expect.stringContaining("Run /mcp-auth broker"), "error");
  });

  it("does not overlap pairing dialogs for multiple eager servers", async () => {
    vi.spyOn(McpServerManager.prototype, "connect").mockResolvedValue(needsAuth);
    let active = 0;
    mocks.authenticateServer.mockImplementation(async () => {
      expect(active++).toBe(0);
      await Promise.resolve();
      active--;
      return { ok: false };
    });
    await boot(true, "tui", true, ["one", "two"]);
    expect(mocks.authenticateServer).toHaveBeenCalledTimes(2);
  });

  it("holds the session_start boundary until pairing settles", async () => {
    vi.spyOn(McpServerManager.prototype, "connect")
      .mockResolvedValueOnce(needsAuth).mockResolvedValue(connected);
    let finishPairing!: (result: { ok: boolean }) => void;
    const pairing = new Promise<{ ok: boolean }>(resolve => { finishPairing = resolve; });
    mocks.authenticateServer.mockImplementation(() => pairing);
    const pending = boot();
    await vi.waitFor(() => expect(mocks.authenticateServer).toHaveBeenCalledTimes(1));
    expect(mocks.started).not.toHaveBeenCalled();
    finishPairing({ ok: true });
    await pending;
    expect(mocks.started).toHaveBeenCalledTimes(1);
  });

  it("reports a reconnect failure without aborting initialization", async () => {
    vi.spyOn(McpServerManager.prototype, "connect")
      .mockResolvedValueOnce(needsAuth).mockRejectedValue(new Error("connection refused"));
    const { notify } = await boot();
    expect(notify).toHaveBeenCalledWith("MCP: Failed to connect to broker: connection refused", "error");
  });
});
