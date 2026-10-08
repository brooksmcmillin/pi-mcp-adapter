import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { fork, spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CodingAuthClient } from "../mcp-coding-auth.ts";
import { captureOAuthAuthority, getAuthStorageOptions } from "../mcp-auth.ts";
import { createOAuthRuntime, getValidToken, shutdownOAuth } from "../mcp-auth-flow.ts";

const file = fileURLToPath(import.meta.url);
const timeoutMs = 30_000;
if (process.argv[2] === "--worker") {
  const origin = process.argv[3];
  const url = `${origin}/broker/mcp`;
  const runtime = createOAuthRuntime();
  const storage = getAuthStorageOptions(undefined, process.cwd(), "session", "encrypted-file");
  const codingEnrollment = { version: 1, cohort: "smoke" };
  const options = { runtime, authStorageOptions: storage, definition: { oauth: { codingEnrollment } } };
  if (process.argv[4] === "initial") {
    const client = new CodingAuthClient("broker", url, codingEnrollment, storage);
    const response = await fetch(`${origin}/__test/initial`, { method: "POST" });
    client.install(client.parseCredentials(await response.json()), captureOAuthAuthority("broker", true, storage));
  }
  process.on("message", async ({ id, command }) => {
    try {
      const tokens = await getValidToken("broker", url, options);
      assert(tokens);
      if (command === "extra" || command === "baseline") {
        const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens.accessToken}` },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: command === "extra" ? "nexus.extra" : "nexus.get_task" } }) });
        const result = await response.json();
        process.send({ id, status: result.error || result.result?.isError ? "denied" : "allowed" });
      } else process.send({ id, status: "active", access: createHash("sha256").update(tokens.accessToken).digest("hex"), refresh: createHash("sha256").update(tokens.refreshToken).digest("hex") });
    } catch (error) {
      // Only local curated guidance is sent; never token responses or causes.
      const message = error instanceof Error ? error.message : "failed";
      process.send({ id, status: message.includes("paused") ? "paused" : "denied", guidance: message });
    }
  });
  process.on("disconnect", async () => { await shutdownOAuth(runtime); process.exit(0); });
  process.send({ status: "ready" });
} else {
  const infra = process.env.CODING_BROKER_INFRA;
  assert(infra, "Set CODING_BROKER_INFRA to the trusted infra checkout implementing coding API v1");
  const directory = mkdtempSync(join(tmpdir(), "coding-adapter-smoke-"));
  const children = [];
  const server = spawn("uv", ["run", "--project", infra, "python", fileURLToPath(new URL("./fixtures/coding-broker-smoke.py", import.meta.url)), infra],
    { cwd: infra, stdio: ["ignore", "pipe", "pipe"] });
  let diagnostic = "";
  server.stderr.on("data", chunk => { diagnostic = (diagnostic + chunk).slice(-2000); });
  const started = Date.now();
  try {
    const origin = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Broker fixture startup timed out: ${diagnostic}`)), timeoutMs);
      server.once("exit", code => { clearTimeout(timer); reject(new Error(`Broker fixture exit ${code}: ${diagnostic}`)); });
      server.stdout.once("data", chunk => { clearTimeout(timer); resolve(String(chunk).trim()); });
    });
    const request = async (route, init = {}) => fetch(`${origin}${route}`, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    // Only fixture startup readiness is retried; credential operations are never replayed.
    for (let attempt = 0; ; attempt++) {
      try { const response = await request("/__test/counts", { method: "POST" }); assert(response.ok); break; }
      catch (error) { if (attempt >= 20) throw error; await new Promise(resolve => setTimeout(resolve, 50)); }
    }
    const key = randomBytes(32).toString("base64");
    let requestId = 0;
    const command = (worker, value) => new Promise((resolve, reject) => {
      const id = ++requestId;
      const listener = message => { if (message.id === id) { clearTimeout(timer); worker.off("message", listener); resolve(message); } };
      const timer = setTimeout(() => { worker.off("message", listener); reject(new Error("Adapter worker timed out")); }, timeoutMs);
      worker.on("message", listener); worker.send({ id, command: value });
    });
    for (let i = 0; i < 4; i++) {
      const child = fork(file, ["--worker", origin, i === 0 ? "initial" : "enroll"], { execArgv: ["--import", "tsx"],
        env: { ...process.env, PI_CODING_AGENT_DIR: directory, PI_MCP_ADAPTER_OAUTH_FILE_KEY: key, PI_MCP_ADAPTER_TEST_AUTH_STORE: "", MCP_OAUTH_DIR: "" },
        stdio: ["ignore", "ignore", "pipe", "ipc"] });
      children.push(child);
      const ready = await Promise.race([once(child, "message"), once(child, "exit").then(() => { throw new Error("Adapter worker exited before ready"); })]);
      assert.equal(ready[0].status, "ready");
      const result = await command(child, "continue");
      assert.equal(result.status, "active");
    }
    const original = await Promise.all(children.map(child => command(child, "continue")));
    assert.equal(new Set(original.map(r => r.access)).size, 4);
    assert.equal(new Set(original.map(r => r.refresh)).size, 4);
    assert.equal((await command(children[0], "extra")).status, "allowed");
    const control = await (await request("/__test/pause", { method: "POST" })).json();
    const paused = await Promise.all(children.slice(0, 3).map(child => command(child, "continue")));
    assert(paused.every(r => r.status === "paused"));
    assert.equal(new Set(paused.map(r => r.guidance)).size, 1);
    const renewal = `/broker/coding/renew?authorization_ref=${control.reference}`;
    assert(paused[0].guidance.includes(`${origin}${renewal}`));
    const form = await request(renewal);
    const cookie = form.headers.get("set-cookie").split(";")[0];
    const nonce = (await form.text()).match(/name="request_id" value="([^"]+)"/)[1];
    const { totp } = await (await request("/__test/totp", { method: "POST" })).json();
    const renewed = await request("/broker/coding/renew", { method: "POST", headers: { cookie, origin, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ request_id: nonce, decision: "approve", window_seconds: "28800", totp }) });
    assert.equal(renewed.status, 200);
    const continued = await Promise.all(children.map(child => command(child, "continue")));
    assert(continued.slice(0, 3).every(r => r.status === "active"));
    assert.equal(continued[3].status, "denied");
    assert.equal(new Set(continued.slice(0, 3).map(r => r.access)).size, 3);
    assert.notEqual(continued[0].access, original[0].access); // idle expiry
    assert.notEqual(continued[1].access, original[1].access); // absolute expiry
    assert.equal((await command(children[0], "baseline")).status, "allowed");
    assert.equal((await command(children[0], "extra")).status, "denied");
    const counts = await (await request("/__test/counts", { method: "POST" })).json();
    assert.equal(counts.renewals, 1);
    console.log(JSON.stringify({ result: "passed", independentProcesses: 4, eligibleContinued: 3, revokedDenied: 1, humanRenewals: counts.renewals,
      expiredExtraGrant: "denied", oldIdleAndAbsoluteExpiry: "recovered", elapsedMs: Date.now() - started,
      brokerRevision: execFileSync("git", ["-C", infra, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
      adapterBase: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
      piRevision: JSON.parse(readFileSync(new URL("../node_modules/@earendil-works/pi-coding-agent/package.json", import.meta.url))).version }));
  } finally {
    for (const child of children) { if (child.connected) child.disconnect(); child.kill(); }
    if (server.exitCode === null) { server.kill("SIGTERM"); await once(server, "exit"); }
    rmSync(directory, { recursive: true, force: true });
  }
}
