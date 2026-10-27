import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CodingAuthClient } from "../mcp-coding-auth.ts";
import { captureOAuthAuthority, getAuthStorageOptions } from "../mcp-auth.ts";
import { createOAuthRuntime, shutdownOAuth } from "../mcp-auth-flow.ts";
import { getMcpOAuthTokensForUrl, replaceMcpCodingSession } from "../oauth.ts";

const infra = process.env.CODING_BROKER_INFRA;
assert(infra, "Set CODING_BROKER_INFRA to a trusted infra checkout with services/mcp-broker");
const directory = mkdtempSync(join(tmpdir(), "coding-reset-smoke-"));
process.env.PI_CODING_AGENT_DIR = directory;
process.env.PI_MCP_ADAPTER_OAUTH_FILE_KEY = randomBytes(32).toString("base64");
delete process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE;
delete process.env.MCP_OAUTH_DIR;
const runtime = createOAuthRuntime();
const server = spawn("uv", ["run", "--project", infra, "python", fileURLToPath(new URL("./fixtures/coding-broker-smoke.py", import.meta.url)), infra],
  { cwd: infra, stdio: ["ignore", "pipe", "pipe"] });
let diagnostic = "";
server.stderr.on("data", chunk => { diagnostic = (diagnostic + chunk).slice(-2000); });
const started = Date.now();
try {
  const origin = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Broker startup timed out: ${diagnostic}`)), 30_000);
    server.once("exit", code => { clearTimeout(timer); reject(new Error(`Broker fixture exit ${code}: ${diagnostic}`)); });
    server.stdout.once("data", chunk => { clearTimeout(timer); resolve(String(chunk).trim()); });
  });
  const request = (route, init = {}) => fetch(`${origin}${route}`, { ...init, signal: AbortSignal.timeout(30_000) });
  // Retry readiness only, never credential issuance or retirement.
  for (let attempt = 0; ; attempt++) {
    try { assert((await request("/__test/counts", { method: "POST" })).ok); break; }
    catch (error) { if (attempt >= 20) throw error; await new Promise(resolve => setTimeout(resolve, 50)); }
  }
  const url = `${origin}/broker/mcp`, codingEnrollment = { version: 1, cohort: "reset-smoke" };
  const storage = () => getAuthStorageOptions(undefined, process.cwd(), "session", "encrypted-file");
  const first = storage(), second = storage();
  const options = authStorageOptions => ({ runtime, authStorageOptions, definition: { oauth: { codingEnrollment } } });
  const client = new CodingAuthClient("broker", url, codingEnrollment, first);
  client.install(client.parseCredentials(await (await request("/__test/initial", { method: "POST" })).json()), captureOAuthAuthority("broker", true, first));
  const read = s => getMcpOAuthTokensForUrl("broker", url, options(s));
  const old = await read(first), peer = await read(second);
  assert(old && peer);
  const invoke = async (tokens, name = "nexus.get_task") => {
    const response = await request("/broker/mcp", { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens.accessToken}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name } }) });
    const result = await response.json();
    return response.ok && !result.error && !result.result?.isError;
  };
  const retire = async tokens => { assert((await request("/__test/revoke", { method: "POST", headers: { authorization: `Bearer ${tokens.accessToken}` } })).ok); };
  assert(await invoke(old, "nexus.extra"));
  await replaceMcpCodingSession("broker", url, { ...options(first), retire: () => retire(old) });
  assert.equal(await invoke(old), false);
  const replacement = await read(first);
  assert(replacement);
  assert.notEqual(replacement.accessToken, old.accessToken);
  assert.notEqual(replacement.refreshToken, old.refreshToken);
  assert.notEqual(replacement.accessToken, peer.accessToken);
  assert(await invoke(replacement));
  assert.equal(await invoke(replacement, "nexus.extra"), false);
  assert.equal((await read(second)).accessToken, peer.accessToken);
  assert(await invoke(peer));
  await retire(replacement);
  await assert.rejects(read(first), /revoked/);
  await assert.rejects(read(first), /revoked/);
  assert(await invoke(await read(second)));
  console.log(JSON.stringify({ result: "passed", oldEnrollment: "denied", replacement: "independent-authenticated", copiedGrant: "denied",
    unsolicitedReconnect: "denied", otherLaunch: "usable", elapsedMs: Date.now() - started,
    brokerRevision: execFileSync("git", ["-C", infra, "rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    adapterRevision: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim() }));
} finally {
  await shutdownOAuth(runtime);
  if (server.exitCode === null) { server.kill("SIGTERM"); await once(server, "exit"); }
  rmSync(directory, { recursive: true, force: true });
}
