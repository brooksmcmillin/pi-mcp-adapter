import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selectApprovalMethod, validateApprovalPreference } from "../permission-approval.ts";

function ui(choice?: string) {
  return { select: vi.fn().mockResolvedValue(choice), input: vi.fn(), notify: vi.fn() };
}

afterEach(() => vi.unstubAllEnvs());

describe("approval preference", () => {
  it.each(["totp", "push", "ask"])("loads persisted %s preference", async preference => {
    const root = mkdtempSync(join(tmpdir(), "approval-pref-"));
    try {
      vi.stubEnv("HOME", root);
      vi.stubEnv("PI_CODING_AGENT_DIR", join(root, "agent"));
      vi.resetModules();
      const file = join(root, "mcp-adapter.json");
      writeFileSync(file, JSON.stringify({ mcpServers: {}, settings: { approvalPreference: preference } }));
      const { loadMcpConfig } = await import("../config.ts");
      expect(loadMcpConfig(file, root).settings?.approvalPreference).toBe(preference);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("defaults to TOTP without prompting", async () => {
    const prompts = ui();
    expect(await selectApprovalMethod(prompts, ["totp", "passkey"])).toBe("totp");
    expect(prompts.select).not.toHaveBeenCalled();
  });

  it("uses push only when passkey is advertised", async () => {
    expect(await selectApprovalMethod(ui(), ["totp", "passkey"], "push")).toBe("passkey");
    expect(await selectApprovalMethod(ui(), ["totp"], "push")).toBe("totp");
    expect(await selectApprovalMethod(ui(), ["passkey"], "totp")).toBe("passkey");
    expect(await selectApprovalMethod(ui(), [], "push")).toBeUndefined();
  });

  it("asks using only permitted methods and allows cancellation", async () => {
    const prompts = ui("Use Push");
    expect(await selectApprovalMethod(prompts, ["totp", "passkey"], "ask")).toBe("passkey");
    expect(prompts.select.mock.calls[0][1]).toEqual(["Use TOTP", "Use Push", "Cancel"]);
    expect(await selectApprovalMethod(ui("Cancel"), ["totp", "passkey"], "ask")).toBeUndefined();
  });

  it("rejects unknown preferences", () => {
    expect(() => validateApprovalPreference("approve")).toThrow("totp, push, or ask");
  });
});
