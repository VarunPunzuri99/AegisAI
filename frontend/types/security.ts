/** Security pipeline and inspect response types (backend is authoritative). */

export type PolicyDecision = "ALLOW" | "REVIEW" | "BLOCK" | "ERROR";
export type DetectionLabel = "ATTACK" | "BENIGN" | "UNCERTAIN" | "UNAVAILABLE";
export type ToolVerdict = "ALLOW" | "DENY" | "REQUIRES_APPROVAL";
export type Severity = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type PipelineStage = {
  id: string;
  label: string;
  status: "ok" | "skipped" | "unavailable" | "error" | string;
  summary: string;
  detail?: string | null;
  meta?: Record<string, unknown>;
};

export type EvidenceSource = {
  source: string;
  available: boolean;
  label: string;
  score?: number | null;
  confidence?: number | null;
  attack_types: string[];
  error_code?: string | null;
};

export type InspectResponse = {
  input_preview: string;
  input_length: number;
  source_type: string;
  normalized_preview: string;
  normalization_flags: Record<string, unknown>;
  rules_label: string;
  rules_is_attack: boolean;
  rules_confidence: number;
  rules_findings: Array<Record<string, unknown>>;
  attack_types: string[];
  prompt_guard_invoked: boolean;
  prompt_guard_available?: boolean | null;
  prompt_guard_label?: string | null;
  prompt_guard_score?: number | null;
  prompt_guard_error?: string | null;
  safeguard_invoked: boolean;
  safeguard_available?: boolean | null;
  safeguard_label?: string | null;
  safeguard_confidence?: number | null;
  safeguard_intent?: string | null;
  safeguard_target?: string | null;
  safeguard_impact?: string | null;
  safeguard_rationale: string[];
  safeguard_error?: string | null;
  fusion_label?: string | null;
  conflict: boolean;
  uncertainty: boolean;
  evidence_sources: EvidenceSource[];
  risk_score?: number | null;
  severity?: string | null;
  risk_factors: Array<{ factor: string; points: number; reason: string }>;
  policy_decision?: string | null;
  policy_id?: string | null;
  policy_version?: string | null;
  policy_reason_codes: string[];
  policy_explanation?: string | null;
  agent_status?: string | null;
  agent_reason_codes: string[];
  tool_firewall_ran: boolean;
  tool_name?: string | null;
  tool_decision?: string | null;
  tool_reason_codes: string[];
  tool_explanation?: string | null;
  stages: PipelineStage[];
  latency_ms: number;
  note: string;
  event_id?: string | null;
  scan_id?: string | null;
  content_hash?: string | null;
  persisted?: boolean;
};

export type PlaygroundScenario = {
  id: string;
  title: string;
  description: string;
  expected_category: string;
  payload: string;
};

export type SystemStatus = {
  api: string;
  groq_configured: boolean;
  prompt_guard_enabled: boolean;
  prompt_guard_mode: string;
  safeguard_enabled: boolean;
  safeguard_mode: string;
  note: string;
};

export type PolicyOverview = {
  policy_id: string;
  version: string;
  read_only: boolean;
  bands: Array<{ range: string; severity: string; decision: string }>;
  special_rules: string[];
  high_impact_categories: string[];
  note: string;
};

export type ToolsOverview = {
  tools: Array<{
    tool_name: string;
    description: string;
    risk_level: string;
    operation_type: string;
    requires_approval: boolean;
    enabled: boolean;
  }>;
  controls: string[];
  verdicts: string[];
  note: string;
};

export type RecentActivity = {
  available: boolean;
  items: Array<{
    time: string;
    scan_id: string;
    event_id?: string | null;
    detection?: string | null;
    risk?: string | null;
    policy?: string | null;
    tool_decision?: string | null;
    status: string;
    preview?: string | null;
  }>;
  note: string;
};

export const ATTACK_CATEGORY_LABELS: Record<string, string> = {
  instruction_override: "Instruction Override",
  role_change: "Role Change",
  secret_extraction: "Secret Extraction",
  tool_abuse: "Tool Abuse",
  credential_theft: "Credential Theft",
  context_poisoning: "Context Poisoning",
  multi_step_jailbreak: "Multi-Step Jailbreak",
  encoded_instruction: "Encoded Instruction",
  indirect_prompt_injection: "Indirect Prompt Injection",
  benign: "Benign",
};
