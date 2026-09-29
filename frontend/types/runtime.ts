/** Phase 14 agent runtime simulation types. */

export type AgentRuntimeState =
  | "IDLE"
  | "PLANNING"
  | "CONTEXT_INSPECTION"
  | "ACTION_PROPOSED"
  | "SECURITY_CHECK"
  | "TOOL_PENDING"
  | "TOOL_EXECUTED"
  | "COMPLETED"
  | "SECURITY_BLOCKED"
  | "ACTION_REQUIRES_APPROVAL"
  | "TOOL_DENIED"
  | "FAILED"
  | "SESSION_LIMIT_EXCEEDED";

export type RuntimeScenarioSummary = {
  scenario_id: string;
  title: string;
  description: string;
  user_task: string;
};

export type RuntimeStepEvent = {
  id: string;
  label: string;
  status: string;
  summary: string;
};

export type SimulationResult = {
  session_id: string;
  scenario_id: string;
  state: AgentRuntimeState | string;
  original_intent: string;
  untrusted_preview?: string | null;
  action?: {
    action_id?: string | null;
    action_type?: string | null;
    tool_name?: string | null;
    target?: string | null;
    risk?: string | null;
    intent_alignment?: boolean | null;
    reason?: string | null;
  } | null;
  security: {
    detection?: string | null;
    risk_score?: number | null;
    severity?: string | null;
    policy?: string | null;
    conflict: boolean;
    uncertainty: boolean;
    tool_decision?: string | null;
    reason_codes: string[];
    attack_types: string[];
  };
  execution: {
    executed: boolean;
    simulated: boolean;
    tool_result_summary?: string | null;
    trusted_output: boolean;
  };
  steps: RuntimeStepEvent[];
  event_id?: string | null;
  note: string;
};
