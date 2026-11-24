import assert from "node:assert/strict";
import { getValidToken } from "../../mcp-auth-flow.ts";
import { getAuthStorageOptions } from "../../mcp-auth.ts";

const url = "https://broker.example/broker/mcp";
const cohort = process.argv[2];
const authStorageOptions = getAuthStorageOptions(undefined, process.cwd(), "session", "encrypted-file");
let exchanges = 0;
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://broker.example/broker/token");
  assert.equal(init.method, "POST");
  assert.deepEqual([...init.body], [["grant_type", "urn:mcp-broker:grant-type:basic-enrollment:v1"], ["basic_enrollment_token", "synthetic-host-proof"]]);
  exchanges++;
  return Response.json({ version: 1, token_type: "Bearer", scope: "profile:default", access_token: "synthetic-child-session", expires_at: new Date(Date.now() + 60_000).toISOString() });
};
const tokens = await getValidToken("broker", url, { authStorageOptions, definition: { oauth: { basicEnrollment: { version: 1, cohort } } } });
assert.equal(exchanges, 1);
assert.equal(tokens.accessToken, "synthetic-child-session");
assert.equal(tokens.refreshToken, undefined);
