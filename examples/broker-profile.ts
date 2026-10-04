import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { truncateToWidth } from "@earendil-works/pi-tui";
import { basename } from "node:path";

const STATUS_EVENT = "pi-mcp-adapter/status/v1";

export default function (pi: ExtensionAPI) {
	const args = process.argv;
	const configArg = args.find((arg) => arg.startsWith("--mcp-config="));
	const configPath = configArg?.slice("--mcp-config=".length)
		?? args[args.indexOf("--mcp-config") + 1];
	if (!configPath || !/^mcp-broker-(?:slot-)?[^/]+\.json$/.test(basename(configPath))) return;

	let label = "connecting…";
	let requestRender: (() => void) | undefined;

	pi.events.on(STATUS_EVENT, (data: unknown) => {
		const snapshot = data as {
			version?: number;
			servers?: { name: string; status: string; brokerProfile?: string }[];
		} | undefined;
		if (snapshot?.version !== 1 || !Array.isArray(snapshot.servers)) return;
		const broker = snapshot.servers.find((server) => server.name.startsWith("broker-"));
		if (!broker) return;
		label = broker.status === "connected"
			? (broker.brokerProfile || "unavailable (broker update needed)")
			: broker.status;
		// Profile names are display data, never terminal control sequences.
		label = label.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
		requestRender?.();
	});

	pi.on("session_start", (_event, ctx) => {
		if (ctx.mode !== "tui") return;
		ctx.ui.setHeader((tui, theme) => {
			requestRender = () => tui.requestRender();
			return {
				render: (width: number) => [truncateToWidth(
					`${theme.fg("accent", "Pi")} · MCP broker profile: ${theme.fg("accent", label)}`,
					width,
				)],
				invalidate() {},
				dispose() { requestRender = undefined; },
			};
		});
	});
}
