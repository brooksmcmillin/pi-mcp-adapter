import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { CodingAuthClient } from "../mcp-coding-auth.ts";
import { getAuthStorageOptions } from "../mcp-auth.ts";

// Real timers and loopback HTTP, synthetic credentials only; no broker restart.
process.env.PI_MCP_ADAPTER_TEST_AUTH_STORE = "memory";
let start, statusRequests = 0, toolDispatches = 0;
const server = createServer((req, res) => {
  assert.equal(req.url, "/broker/coding/status");
  statusRequests++;
  req.resume();
  if (performance.now() - start < 13_000) {
    res.writeHead(502, { "content-type": "text/html" }).end("<h1>synthetic restart</h1>");
  } else {
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
      version: 1, status: "active", authorization_ref: "synthetic", credential_status: "active",
      renewal_route: "/broker/coding/renew?authorization_ref=synthetic",
    }));
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const url = `http://127.0.0.1:${server.address().port}/broker/mcp`;
  const coding = new CodingAuthClient("synthetic", url, { version: 1, cohort: "restart-smoke" }, getAuthStorageOptions(undefined, process.cwd(), "session"));
  coding.install({
    version: 1, token_type: "Bearer", scope: "profile:coding", authorization_ref: "synthetic",
    access_token: "synthetic-access", refresh_token: "synthetic-refresh", enrollment_token: "synthetic-enrollment",
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  }, () => {});
  start = performance.now();
  const result = await coding.runPending(async () => {
    assert.equal((await coding.tokens(fetch, () => {})).accessToken, "synthetic-access");
    toolDispatches++;
    return "accepted";
  }, fetch, { check: () => {} });
  const elapsedMs = Math.round(performance.now() - start);
  assert.equal(result, "accepted");
  assert.equal(statusRequests, 5);
  assert.equal(toolDispatches, 1);
  assert(elapsedMs >= 15_000 && elapsedMs < 30_000);
  console.log(JSON.stringify({ result: "passed", unavailableMs: 13000, statusRequests, toolDispatches, elapsedMs, credentialRotations: 0 }));
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}
