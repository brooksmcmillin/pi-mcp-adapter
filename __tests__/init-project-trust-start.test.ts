import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

vi.mock("../server-manager.ts", () => ({
  McpServerManager: vi.fn().mockImplementation(function (this: any) {
    this.setDefaultRequestTimeoutMs = vi.fn();
    this.setAuthStorageOptions = vi.fn();
    this.setSamplingConfig = vi.fn();
    this.setElicitationConfig = vi.fn();
    this.getConnection = vi.fn();
    this.connect = vi.fn();
  }),
}));

describe("initializeMcp project trust start signal", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "mcp-trust-start-"));
    vi.stubEnv("HOME", join(root, "home"));
    vi.stubEnv("PI_PACKAGE_DIR", "");
    vi.stubEnv("PI_CODING_AGENT_DIR", join(root, "home", ".pi", "agent"));
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    rmSync(root, { recursive: true, force: true });
  });

  it.each([
    { settings: { oauthPersistence: "session" }, expected: { persistence: "session", sessionEntries: expect.any(Map) } },
    { settings: { oauthCredentialStore: "encrypted-file" }, expected: { credentialStore: "encrypted-file" } },
  ])("preserves OAuth storage $settings after project trust resolves", async ({ settings, expected }) => {
    const agentDir = join(root, "home", ".pi", "agent");
    mkdirSync(agentDir, { recursive: true });
    writeFileSync(join(agentDir, "mcp-adapter.json"), JSON.stringify({ settings }));
    const cwd = join(root, "project");
    mkdirSync(cwd, { recursive: true });
    writeFileSync(join(cwd, ".mcp.json"), JSON.stringify({ mcpServers: { local: { command: "node" } } }));
    let answer!: (value: string | undefined) => void;
    const select = vi.fn(() => new Promise<string | undefined>((resolve) => { answer = resolve; }));
    const onProjectTrustResolved = vi.fn();
    const { initializeMcp } = await import("../init.ts");

    const initialization = initializeMcp(
      { getFlag: vi.fn() } as unknown as ExtensionAPI,
      {
        cwd,
        hasUI: true,
        mode: "tui",
        isProjectTrusted: () => true,
        ui: { select, notify: vi.fn(), setStatus: vi.fn() },
        modelRegistry: {},
        signal: undefined,
      } as unknown as ExtensionContext,
      undefined,
      { onProjectTrustResolved },
    );
    await vi.waitFor(() => expect(select).toHaveBeenCalledTimes(1));
    expect(onProjectTrustResolved).not.toHaveBeenCalled();

    answer(undefined);
    const state = await initialization;
    expect(onProjectTrustResolved).toHaveBeenCalledTimes(1);
    expect(state.authStorageOptions).toMatchObject(expected);
    expect(state.manager.setAuthStorageOptions).toHaveBeenCalledWith(state.authStorageOptions);
    expect(state.blockedProjectServers?.has("local")).toBe(true);
  });
});
