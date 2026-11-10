import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ElicitResultSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "mock-permission-broker", version: "1" }, { capabilities: { tools: {} } });
let status = "pending";
let creates = 0;
const state = () => ({ request_id: "bound-request", status, grant_id: status === "approved" ? 7 : null });
const result = () => ({ content: [{ type: "text", text: JSON.stringify({ ...state(), creates }) }], structuredContent: state() });
server.setRequestHandler(ListToolsRequestSchema, async request => request.params?.cursor === "second" ? { tools: [
  { name: "always_second_page", inputSchema: { type: "object" } },
  ...(status === "approved" ? [{ name: "privileged", inputSchema: { type: "object" } }] : []),
] } : { tools: [
  ...["permission_request.create", "permission_request.status", "permission_request.cancel"].map(name => ({ name, inputSchema: { type: "object" } })),
], nextCursor: "second" });
server.setRequestHandler(CallToolRequestSchema, async request => {
  if (request.params.name === "permission_request.status") {
    if (request.params.arguments?.request_id !== "bound-request") throw new Error("wrong request");
    // Simulated phone resolution, not a cryptographic verifier. Client acceptance
    // below never changes this state to approved.
    if (status === "pending" && process.argv[2] !== "pending") status = process.argv[2] ?? "approved";
    return result();
  }
  if (request.params.name === "permission_request.cancel") {
    if (request.params.arguments?.request_id !== "bound-request") throw new Error("wrong request");
    if (status === "pending") status = "cancelled";
    return result();
  }
  if (request.params.name !== "permission_request.create") throw new Error("privileged operation must never be replayed");
  creates++;
  const response = await server.request({ method: "elicitation/create", params: {
    mode: "form", message: "Trusted catalogue scope; agent rationale is untrusted",
    requestedSchema: { type: "object", properties: {} },
    _meta: {
      ...(request.params._meta?.["com.brooksmcmillin/approval-call-id"] ? {
        "com.brooksmcmillin/approval-call-id": request.params._meta["com.brooksmcmillin/approval-call-id"],
      } : {}),
      "com.brooksmcmillin/permission-request": {
      request_id: "bound-request", deadline: Date.now() / 1000 + 30,
      methods: ["passkey"], approval_url: "https://broker.example/phone/?request=bound-request",
    } },
  } }, ElicitResultSchema);
  if (status === "pending") status = response.action === "decline" ? "denied" : "cancelled";
  return { ...result(), isError: status !== "approved" };
});
await server.connect(new StdioServerTransport());
