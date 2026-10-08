import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { CodingAuthClient } from "../mcp-coding-auth.ts";
import { captureOAuthAuthority, getAuthStorageOptions } from "../mcp-auth.ts";
import { createOAuthRuntime, shutdownOAuth } from "../mcp-auth-flow.ts";
import { McpServerManager } from "../server-manager.ts";
import { withSessionRecovery } from "../session-recovery.ts";

// Synthetic credentials only; never touches the operator's secure store.
process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "memory";
const infra = process.env.CODING_BROKER_INFRA;
assert(infra, "Set CODING_BROKER_INFRA to a trusted coding API v1 infra checkout");
const server = spawn("uv", ["run", "--project", infra, "python", fileURLToPath(new URL("./fixtures/coding-broker-smoke.py", import.meta.url)), infra],
  { cwd: infra, stdio: ["ignore", "pipe", "pipe"] });
let diagnostic = "";
server.stderr.on("data", chunk => { diagnostic = (diagnostic + chunk).slice(-2000); });
const clients = [], started = Date.now();
try {
  const origin = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Fixture startup timeout: ${diagnostic}`)), 120_000);
    server.once("exit", code => { clearTimeout(timer); reject(new Error(`Fixture exited ${code}: ${diagnostic}`)); });
    server.stdout.once("data", chunk => { clearTimeout(timer); resolve(String(chunk).trim()); });
  });
  const request = (route, init = {}) => fetch(`${origin}${route}`, { method: "POST", ...init, signal: AbortSignal.timeout(30_000) });
  for (let i = 0; ; i++) {
    try { assert((await request("/__test/counts")).ok); break; }
    catch (error) { if (i >= 20) throw error; await new Promise(resolve => setTimeout(resolve, 50)); }
  }
  const url = `${origin}/broker/mcp`, codingEnrollment = { version: 1, cohort: "pending-smoke" };
  const config = { mcpServers: { broker: { url, auth: "oauth", oauth: { codingEnrollment } } } };
  const waiting = new Set();
  for (let i = 0; i < 20; i++) {
    const storage = getAuthStorageOptions(undefined, process.cwd(), "session");
    const coding = new CodingAuthClient("broker", url, codingEnrollment, storage);
    const check = captureOAuthAuthority("broker", true, storage);
    if (i === 0) coding.install(coding.parseCredentials(await (await request("/__test/initial")).json()), check);
    else assert(await coding.tokens(fetch, check));
    const runtime = createOAuthRuntime(), manager = new McpServerManager();
    manager.setAuthStorageOptions(storage); manager.setOAuthRuntime(runtime);
    const controller = new AbortController();
    clients.push({ manager, runtime, controller });
    await manager.connect("broker", config.mcpServers.broker);
  }
  const invoke = (i) => {
    const { manager, controller } = clients[i];
    return withSessionRecovery({ manager, config, signal: controller.signal, pendingCodingCall: true,
      onCodingWait: () => waiting.add(i) }, "broker", conn => conn.client.callTool({ name: "nexus.get_task", arguments: { operation: `call-${i}` } }, { signal: controller.signal }));
  };
  assert(!(await invoke(18)).isError); // Finished before expiry; must never be revived.
  const { reference } = await (await request("/__test/pause-on-call")).json();
  const pending = [invoke(0)];
  const firstWaiting = Date.now();
  while (!waiting.has(0)) {
    assert(Date.now() - firstWaiting < 10_000, "HTTP-rejected client did not enter waiting");
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  // The remaining SDK calls encounter the validated status preflight instead.
  for (let i = 1; i < 18; i++) pending.push(invoke(i));
  const cancelled = pending[17].then(() => { throw new Error("Cancelled call executed"); }, error => assert(error instanceof Error));
  const allWaiting = Date.now();
  while (waiting.size < 18) {
    assert(Date.now() - allWaiting < 10_000, `Only ${waiting.size} clients waiting`);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  const cancelStarted = Date.now();
  clients[17].controller.abort(); await cancelled;
  const cancellationMs = Date.now() - cancelStarted;
  assert(cancellationMs < 1000);
  const renewal = `/broker/coding/renew?authorization_ref=${reference}`;
  const form = await request(renewal, { method: "GET" });
  const cookie = form.headers.get("set-cookie").split(";")[0];
  const nonce = (await form.text()).match(/name="request_id" value="([^"]+)"/)[1];
  const { totp } = await (await request("/__test/totp")).json();
  assert.equal((await request("/broker/coding/renew", { headers: { cookie, origin, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request_id: nonce, decision: "approve", window_seconds: "28800", totp }) })).status, 200);
  const results = await Promise.race([Promise.all(pending.slice(0, 17)), new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error("Pending calls failed to recover")), 30_000); timer.unref();
  })]);
  assert(results.every(result => !result.isError));
  const counts = await (await request("/__test/counts")).json();
  assert.equal(counts.renewals, 1); assert(counts.rejected_calls > 0, "Real HTTP pre-execution rejection was not exercised");
  for (let i = 0; i < 17; i++) assert.equal(counts.forwards[`call-${i}`], 1);
  assert.equal(counts.forwards["call-17"], undefined);
  assert.equal(counts.forwards["call-18"], 1);
  assert.equal(counts.forwards["call-19"], undefined);
  console.log(JSON.stringify({ result: "passed", clients: 20, pending: 18, automaticallyResumed: 17, cancelled: 1,
    idleRevived: 0, completedReplayed: 0, humanRenewals: counts.renewals, httpRejections: counts.rejected_calls,
    cancellationMs, elapsedMs: Date.now() - started,
    brokerRevision: execFileSync("git", ["-C", infra, "rev-parse", "HEAD"], { encoding: "utf8" }).trim() }));
} finally {
  for (const { manager, runtime, controller } of clients) { controller.abort(); await manager.closeAll(); await shutdownOAuth(runtime); }
  if (server.exitCode === null) { server.kill("SIGTERM"); await once(server, "exit"); }
}
