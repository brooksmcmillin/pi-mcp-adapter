import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "structured-echo-server", version: "1.0.0" },
  { capabilities: { tools: {} } },
);
const valueSchema = { type: "object", properties: { value: { type: "string" } }, required: ["value"] };
// Over the adapter's 50 KB output guard limit.
const large = JSON.stringify(Array.from({ length: 2000 }, (_, id) => ({ id, title: `Item ${id}`, body: "x".repeat(30) })));
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "echo", description: "Echo a value", inputSchema: valueSchema, outputSchema: valueSchema },
    { name: "large", description: "Return a large JSON list", inputSchema: { type: "object", properties: {} } },
    { name: "get_task", description: "Return a sanitized task in a selected result format", inputSchema: {
      type: "object", properties: { task_id: { type: "string" }, format: { type: "string" } }, required: ["task_id", "format"],
    } },
  ],
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "large") return { content: [{ type: "text", text: large }] };
  if (request.params.name === "get_task") {
    const { task_id, format } = request.params.arguments;
    const task = { id: task_id, title: "Sanitized task", status: "pending", description: "not for model output" };
    const payload = { task, current_time: "2026-11-04T02:43:35Z" };
    const encoded = JSON.stringify(payload);
    const content = [{ type: "text", text: encoded }];
    switch (format) {
      case "structured": return { content, structuredContent: payload };
      // Historical gateway shape: duplicate JSON text plus an encoded structured result.
      case "envelope": return { content, structuredContent: { result: encoded } };
      case "text": return { content };
      case "split-text": return { content: [{ type: "text", text: '{"task":' }, { type: "text", text: JSON.stringify(task) + "}" }] };
      case "plain": return { content: [{ type: "text", text: "Service is healthy" }] };
      case "error": return { content, isError: true };
      case "omitted": return { content, structuredContent: { omitted: true, task } };
      case "truncated": return { content: [{ type: "text", text: encoded + "\n[MCP text output truncated]" }] };
      case "partial": return { content, structuredContent: { task: { id: task_id, title: task.title } } };
      case "malformed-envelope": return { content, structuredContent: { result: '{"task":' } };
      case "ambiguous-text": return { content: [...content, ...content] };
      default: throw new Error("Unknown result fixture format");
    }
  }
  const { value } = request.params.arguments;
  return { content: [{ type: "text", text: value }], structuredContent: { value } };
});
await server.connect(new StdioServerTransport());
