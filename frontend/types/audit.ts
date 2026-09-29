/** Audit / security event API types (Phase 13). */

export type AuditListItem = {
  event_id: string;
  created_at: string;
  scan_id?: string | null;
  detection_label?: string | null;
  attack_types: string[];
  risk_score?: number | null;
  severity?: string | null;
  policy_decision?: string | null;
  agent_state?: string | null;
  tool_name?: string | null;
  tool_decision?: string | null;
  conflict: boolean;
  uncertainty: boolean;
  simulated: boolean;
};

export type AuditListResponse = {
  items: AuditListItem[];
  page: number;
  page_size: number;
  total: number;
  summary: {
    total?: number;
    blocks?: number;
    reviews?: number;
    allows?: number;
    tool_denials?: number;
  };
  note: string;
};

export type AuditDetail = {
  event_id: string;
  created_at: string;
  scan_id?: string | null;
  source_type: string;
  content_hash: string;
  content_length: number;
  detection: {
    label?: string | null;
    attack_types: string[];
    conflict?: boolean;
    uncertainty?: boolean;
  };
  risk: {
    score?: number | null;
    severity?: string | null;
    factors?: Array<{ factor?: string; points?: number; reason?: string }>;
  };
  policy: {
    decision?: string | null;
    id?: string | null;
    version?: string | null;
  };
  agent: { state?: string | null };
  tool: {
    name?: string | null;
    decision?: string | null;
    approval_state?: string | null;
  };
  evidence: Record<string, unknown>;
  pipeline_stages: Array<{
    id: string;
    label: string;
    status: string;
    summary: string;
  }>;
  risk_factors: Array<{ factor?: string; points?: number; reason?: string }>;
  reason_codes: string[];
  conflict: boolean;
  uncertainty: boolean;
  simulated: boolean;
  latency_ms?: number | null;
  metadata: Record<string, unknown>;
  note?: string | null;
};

export type AuditQuery = {
  page?: number;
  page_size?: number;
  decision?: string;
  severity?: string;
  detection_label?: string;
  tool_decision?: string;
  tool_name?: string;
  attack_type?: string;
};
