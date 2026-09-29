import { apiRequest } from "@/lib/api/client";
import type { AuditDetail, AuditListResponse, AuditQuery } from "@/types/audit";
import type { EvaluationOverview } from "@/types/evaluation";
import type {
  RuntimeScenarioSummary,
  SimulationResult,
} from "@/types/runtime";
import type {
  InspectResponse,
  PlaygroundScenario,
  PolicyOverview,
  RecentActivity,
  SystemStatus,
  ToolsOverview,
} from "@/types/security";
import type { HealthResponse } from "@/types/index";
import { API_URL } from "@/lib/config";

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_URL}/health`, {
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`);
  }
  return response.json();
}

export async function inspectContent(
  content: string,
  options?: { sourceType?: string; demoTool?: boolean; signal?: AbortSignal },
): Promise<InspectResponse> {
  return apiRequest<InspectResponse>("/inspect", {
    method: "POST",
    body: {
      content,
      source_type: options?.sourceType ?? "USER_MESSAGE",
      demo_tool: options?.demoTool ?? true,
    },
    timeoutMs: 180_000,
    signal: options?.signal,
  });
}

export async function getEvaluation(): Promise<EvaluationOverview> {
  return apiRequest<EvaluationOverview>("/dashboard/evaluation");
}

export async function getPlayground(): Promise<PlaygroundScenario[]> {
  return apiRequest<PlaygroundScenario[]>("/dashboard/playground");
}

export async function getPolicy(): Promise<PolicyOverview> {
  return apiRequest<PolicyOverview>("/dashboard/policy");
}

export async function getTools(): Promise<ToolsOverview> {
  return apiRequest<ToolsOverview>("/dashboard/tools");
}

export async function getSystemStatus(): Promise<SystemStatus> {
  return apiRequest<SystemStatus>("/dashboard/status");
}

export async function getRecentActivity(limit = 10): Promise<RecentActivity> {
  return apiRequest<RecentActivity>(`/dashboard/activity?limit=${limit}`);
}

export async function createScan(content: string, sourceType = "USER_MESSAGE") {
  return apiRequest<{ id: string; status: string; content_hash: string }>(
    "/scans",
    {
      method: "POST",
      body: { content, source_type: sourceType },
    },
  );
}

export async function listAuditEvents(
  query: AuditQuery = {},
): Promise<AuditListResponse> {
  const params = new URLSearchParams();
  params.set("page", String(query.page ?? 1));
  params.set("page_size", String(query.page_size ?? 20));
  if (query.decision) params.set("decision", query.decision);
  if (query.severity) params.set("severity", query.severity);
  if (query.detection_label) params.set("detection_label", query.detection_label);
  if (query.tool_decision) params.set("tool_decision", query.tool_decision);
  if (query.tool_name) params.set("tool_name", query.tool_name);
  if (query.attack_type) params.set("attack_type", query.attack_type);
  return apiRequest<AuditListResponse>(`/audit?${params.toString()}`);
}

export async function getAuditEvent(eventId: string): Promise<AuditDetail> {
  return apiRequest<AuditDetail>(`/audit/${eventId}`);
}

export async function listAgentScenarios(): Promise<RuntimeScenarioSummary[]> {
  return apiRequest<RuntimeScenarioSummary[]>("/agent/scenarios");
}

export async function simulateAgent(
  scenarioId: string,
  options?: { signal?: AbortSignal },
): Promise<SimulationResult> {
  return apiRequest<SimulationResult>("/agent/simulate", {
    method: "POST",
    body: { scenario_id: scenarioId },
    timeoutMs: 180_000,
    signal: options?.signal,
  });
}

export async function getProviders(): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/dashboard/providers");
}

export async function getPerformance(): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/dashboard/performance");
}

export async function getReviewAnalysis(): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/dashboard/review-analysis");
}

export async function listAuthPrincipals(): Promise<Record<string, unknown>[]> {
  return apiRequest<Record<string, unknown>[]>("/auth/principals");
}

export async function listAuthCapabilities(): Promise<Record<string, unknown>[]> {
  return apiRequest<Record<string, unknown>[]>("/auth/capabilities");
}

export async function authorizeAction(
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/auth/authorize", {
    method: "POST",
    body,
  });
}

export async function listMcpServers(): Promise<Record<string, unknown>[]> {
  return apiRequest<Record<string, unknown>[]>("/mcp/servers");
}

export async function listMcpTools(): Promise<Record<string, unknown>[]> {
  return apiRequest<Record<string, unknown>[]>("/mcp/tools");
}

export async function simulateMcp(
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/mcp/simulate", {
    method: "POST",
    body,
  });
}

export async function getAuthSession(): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>("/auth/session");
}
