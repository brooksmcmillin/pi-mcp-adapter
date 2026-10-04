import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { visibleWidth } from "@earendil-works/pi-tui";
import extension from "../examples/broker-profile.ts";

const channel = "pi-mcp-adapter/status/v1";

function load(args: string[], mode = "tui") {
  const saved = process.argv;
  const events = new EventEmitter();
  const handlers = new Map<string, Function>();
  let header: { render(width: number): string[]; dispose(): void } | undefined;
  let renders = 0;
  process.argv = ["node", "pi", ...args];
  try { extension({ events, on: (name: string, handler: Function) => handlers.set(name, handler) } as any); }
  finally { process.argv = saved; }
  const start = () => handlers.get("session_start")?.({}, {
    mode,
    ui: { setHeader: (factory: Function) => {
      header = factory({ requestRender: () => renders++ }, { fg: (_color: string, text: string) => text });
    } },
  });
  return { events, start, get header() { return header; }, get renders() { return renders; } };
}

function status(profile?: string, state = "connected") {
  return { version: 1, servers: [{ name: "broker-slot-daily", status: state, brokerProfile: profile, credential: "NEVER_SHOW" }] };
}

describe("broker profile header", () => {
  it("leaves ordinary and non-interactive Pi unchanged", () => {
    for (const args of [[], ["--mcp-config=/tmp/other.json"]]) {
      const run = load(args);
      run.start();
      expect(run.header).toBeUndefined();
      expect(run.events.listenerCount(channel)).toBe(0);
    }
    const run = load(["--mcp-config=/tmp/mcp-broker-abc.json"], "rpc");
    run.start();
    expect(run.header).toBeUndefined();
  });

  it("renders pre-startup authenticated profile at narrow widths without credentials", () => {
    const run = load(["--mcp-config", "/tmp/mcp-broker-slot-daily.json"]);
    run.events.emit(channel, status("ui-coding"));
    run.start();
    expect(run.header?.render(100)[0]).toBe("Pi · MCP broker profile: ui-coding");
    expect(visibleWidth(run.header!.render(15)[0])).toBeLessThanOrEqual(15);
    expect(run.header?.render(100).join("")).not.toContain("NEVER_SHOW");
  });

  it("handles authentication, older brokers, reconnection, controls and disposal", () => {
    const run = load(["--mcp-config=/tmp/mcp-broker-abc.json"]);
    run.start();
    expect(run.header?.render(100)[0]).toContain("connecting");
    run.events.emit(channel, status(undefined, "needs-auth"));
    expect(run.header?.render(100)[0]).toContain("needs-auth");
    run.events.emit(channel, status());
    expect(run.header?.render(100)[0]).toContain("unavailable (broker update needed)");
    run.events.emit(channel, status("personal-trusted"));
    expect(run.header?.render(100)[0]).toContain("personal-trusted");
    run.events.emit(channel, status(undefined, "not-connected"));
    expect(run.header?.render(100)[0]).not.toContain("personal-trusted");
    run.events.emit(channel, status("ui-\x1bcoding\n"));
    expect(run.header?.render(100)[0]).not.toMatch(/[\x00-\x1f]/);
    const before = run.renders;
    run.header?.dispose();
    run.events.emit(channel, status("coding"));
    expect(run.renders).toBe(before);
  });
});
