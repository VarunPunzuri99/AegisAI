import { describe, expect, it } from "vitest";
import type { AuditListItem } from "@/types/audit";

describe("audit types", () => {
  it("models list items without raw prompts or secrets", () => {
    const row: AuditListItem = {
      event_id: "11111111-1111-1111-1111-111111111111",
      created_at: new Date().toISOString(),
      detection_label: "ATTACK",
      attack_types: ["credential_theft"],
      risk_score: 90,
      severity: "CRITICAL",
      policy_decision: "BLOCK",
      agent_state: "NO_ACTION",
      tool_name: "send_email",
      tool_decision: "DENY",
      conflict: false,
      uncertainty: false,
      simulated: true,
    };
    const json = JSON.stringify(row);
    expect(row.policy_decision).toBe("BLOCK");
    expect(json.toLowerCase()).not.toContain("api_key");
    expect(json.toLowerCase()).not.toContain("password");
    expect(json).not.toContain("Ignore previous");
  });

  it("supports REVIEW and UNCERTAIN labels", () => {
    const row: AuditListItem = {
      event_id: "22222222-2222-2222-2222-222222222222",
      created_at: new Date().toISOString(),
      detection_label: "UNCERTAIN",
      attack_types: [],
      risk_score: 0,
      severity: "LOW",
      policy_decision: "REVIEW",
      agent_state: "ACTION_REQUIRES_REVIEW",
      tool_decision: null,
      conflict: true,
      uncertainty: true,
      simulated: true,
    };
    expect(row.policy_decision).toBe("REVIEW");
    expect(row.detection_label).toBe("UNCERTAIN");
  });
});
