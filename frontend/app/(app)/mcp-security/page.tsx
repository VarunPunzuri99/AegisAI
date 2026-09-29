"use client";

import { useEffect, useState } from "react";
import { Section } from "@/components/MetricCard";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { ApiError } from "@/lib/api/client";
import { listMcpServers, listMcpTools, simulateMcp } from "@/lib/api";

type McpServer = {
  server_id: string;
  status: string;
  trust: string;
  tools: string[];
  description: string;
};

type McpTool = {
  server_id: string;
  tool_name: string;
  description: string;
  capability: string;
  risk: string;
  target_scope: string;
  fingerprint: string;
  maps_to_internal_tool: string;
};

type SimResult = {
  ok: boolean;
  decision: string;
  server_id: string;
  tool_name: string;
  reason_codes: string[];
  integrity_ok: boolean;
  output_validation_ok: boolean;
  source_type: string;
  trusted: boolean;
  output?: Record<string, unknown> | null;
  mcp_called: boolean;
  explanation?: string;
  principal_id?: string;
  tenant_id?: string;
};

const SCENARIOS = [
  {
    id: "approved",
    label: "Approved public search",
    body: {
      server_id: "aegis-demo-mcp",
      tool_name: "mcp_search_public_documents",
      parameters: { query: "PTO", limit: 3 },
      intent_alignment: true,
      declared_intent: "Find the PTO policy.",
    },
  },
  {
    id: "unknown-server",
    label: "Unknown MCP server",
    body: {
      server_id: "evil-mcp",
      tool_name: "mcp_search_public_documents",
      parameters: { query: "PTO", limit: 3 },
    },
  },
  {
    id: "tamper",
    label: "Tool definition tamper",
    body: {
      server_id: "aegis-demo-mcp",
      tool_name: "mcp_search_public_documents",
      parameters: { query: "PTO", limit: 3 },
      force_definition_tamper: true,
    },
  },
  {
    id: "poison",
    label: "Malicious MCP output",
    body: {
      server_id: "aegis-demo-mcp",
      tool_name: "mcp_search_public_documents",
      parameters: { query: "PTO", limit: 3 },
      force_malicious_output: true,
    },
  },
  {
    id: "timeout",
    label: "MCP timeout",
    body: {
      server_id: "aegis-demo-mcp",
      tool_name: "mcp_search_public_documents",
      parameters: { query: "PTO", limit: 3 },
      force_timeout: true,
    },
  },
] as const;

export default function McpSecurityPage() {
  const [servers, setServers] = useState<McpServer[]>([]);
  const [tools, setTools] = useState<McpTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scenario, setScenario] = useState("approved");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SimResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listMcpServers(), listMcpTools()])
      .then(([s, t]) => {
        if (cancelled) return;
        setServers(s as McpServer[]);
        setTools(t as McpTool[]);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load MCP data");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function runScenario() {
    const sc = SCENARIOS.find((s) => s.id === scenario) ?? SCENARIOS[0];
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const res = (await simulateMcp({ ...sc.body })) as SimResult;
      setResult(res);
    } catch (err: unknown) {
      setRunError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Simulate failed",
      );
    } finally {
      setRunning(false);
    }
  }

  if (loading) return <LoadingState label="Loading MCP registry…" />;
  if (error) return <ErrorState message={error} />;

  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="font-display text-3xl tracking-tight text-aegis-ink">
          MCP Security
        </h1>
        <p className="max-w-2xl text-sm text-aegis-mist">
          Local Mock MCP gateway only. Authn → Authz → Tool Firewall → integrity →
          MockMCPServer. Output is always TOOL_OUTPUT / untrusted. No real MCP
          networking.
        </p>
      </header>

      <Section title="Approved servers">
        {servers.length === 0 ? (
          <EmptyState message="No approved MCP servers." />
        ) : (
          <ul className="space-y-3 text-sm">
            {servers.map((s) => (
              <li
                key={s.server_id}
                className="border border-aegis-steel/20 bg-white/60 px-4 py-3"
              >
                <p className="font-medium">{s.server_id}</p>
                <p className="text-xs text-aegis-mist">
                  {s.status} · {s.trust} · {s.tools.length} tools
                </p>
                <p className="mt-1 text-xs text-aegis-slate">{s.description}</p>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Registered tools + fingerprints">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead className="border-b border-aegis-steel/20 text-aegis-mist">
              <tr>
                <th className="py-2 pr-3 font-medium">Tool</th>
                <th className="py-2 pr-3 font-medium">Capability</th>
                <th className="py-2 pr-3 font-medium">Risk</th>
                <th className="py-2 pr-3 font-medium">Fingerprint</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((t) => (
                <tr
                  key={`${t.server_id}:${t.tool_name}`}
                  className="border-b border-aegis-steel/10"
                >
                  <td className="py-2 pr-3 font-mono">{t.tool_name}</td>
                  <td className="py-2 pr-3">{t.capability}</td>
                  <td className="py-2 pr-3">{t.risk}</td>
                  <td className="py-2 pr-3 font-mono text-[10px]">
                    {t.fingerprint.slice(0, 16)}…
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section title="Run MCP Tool (simulator)">
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-xs text-aegis-mist">Scenario</span>
            <select
              className="rounded-sm border border-aegis-steel/30 bg-white px-3 py-2"
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
            >
              {SCENARIOS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={runScenario}
            disabled={running}
            className="rounded-sm bg-aegis-ink px-4 py-2 text-sm text-white disabled:opacity-50"
          >
            {running ? "Running…" : "Run MCP Tool"}
          </button>
        </div>
        {runError ? <ErrorState message={runError} /> : null}
        {result ? (
          <div className="mt-4 space-y-2 border border-aegis-steel/20 bg-white/70 p-4 text-sm">
            <p>
              Decision: <strong>{result.decision}</strong> · trusted=
              {String(result.trusted)} · source={result.source_type}
            </p>
            <p className="text-xs text-aegis-mist">
              integrity={String(result.integrity_ok)} · output_ok=
              {String(result.output_validation_ok)} · mcp_called=
              {String(result.mcp_called)}
            </p>
            <p className="text-xs">
              principal={result.principal_id} · tenant={result.tenant_id}
            </p>
            {result.reason_codes?.length ? (
              <p className="font-mono text-xs text-red-800">
                {result.reason_codes.join(", ")}
              </p>
            ) : null}
            {result.output ? (
              <pre className="overflow-x-auto bg-aegis-surface/80 p-2 text-[11px]">
                {JSON.stringify(result.output, null, 2)}
              </pre>
            ) : null}
            {result.explanation ? (
              <p className="text-xs text-aegis-mist">{result.explanation}</p>
            ) : null}
          </div>
        ) : null}
      </Section>
    </div>
  );
}
