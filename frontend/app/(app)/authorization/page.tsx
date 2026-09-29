"use client";

import { useEffect, useState } from "react";
import {
  PolicyDecisionBadge,
  ToolVerdictBadge,
} from "@/components/Badges";
import { Section } from "@/components/MetricCard";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/States";
import { ApiError } from "@/lib/api/client";
import {
  authorizeAction,
  listAuthCapabilities,
  listAuthPrincipals,
} from "@/lib/api";

type Principal = {
  principal_id: string;
  principal_type: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
  status: string;
};

type Capability = {
  tool_name: string;
  capability: string;
  target_scope: string;
  risk_level: string;
  requires_approval: boolean;
  allowed_targets: string[];
};

type AuthzResult = {
  decision: string;
  principal_id?: string | null;
  tenant_id?: string | null;
  tool_name?: string | null;
  capability?: string | null;
  target?: string | null;
  reason_codes: string[];
  authorization_version: string;
  explanation?: string;
};

export default function AuthorizationPage() {
  const [principals, setPrincipals] = useState<Principal[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [principalId, setPrincipalId] = useState("user:demo");
  const [toolName, setToolName] = useState("search_public_documents");
  const [target, setTarget] = useState("public_documents");
  const [resourceTenant, setResourceTenant] = useState("");
  const [intentOk, setIntentOk] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AuthzResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([listAuthPrincipals(), listAuthCapabilities()])
      .then(([p, c]) => {
        if (cancelled) return;
        setPrincipals(p as Principal[]);
        setCapabilities(c as Capability[]);
        if (c.length) {
          setToolName((c as Capability[])[0].tool_name);
          setTarget((c as Capability[])[0].allowed_targets[0] ?? "");
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const selected = principals.find((p) => p.principal_id === principalId);
  const cap = capabilities.find((c) => c.tool_name === toolName);

  async function onAuthorize() {
    if (!selected) return;
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const body: Record<string, unknown> = {
        principal_id: principalId,
        tenant_id: selected.tenant_id,
        tool_name: toolName,
        target: target || null,
        intent_alignment: intentOk,
      };
      if (resourceTenant.trim()) {
        body.resource_tenant_id = resourceTenant.trim();
      }
      const res = await authorizeAction(body);
      setResult(res as AuthzResult);
    } catch (err) {
      setRunError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Authorize failed",
      );
    } finally {
      setRunning(false);
    }
  }

  if (loading) return <LoadingState label="Loading authorization console…" />;
  if (error) return <ErrorState message={error} />;

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Authorization
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Identity & capability boundary
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Read-only simulator for Phase 16 principals, permissions, and tenant
          scope. No permission-grant UI. Not production-ready; no real MCP.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-2">
        <Section title="Principals" description="Application-controlled demo identities.">
          {!principals.length ? (
            <EmptyState message="No principals returned." />
          ) : (
            <ul className="space-y-2 text-sm">
              {principals.map((p) => (
                <li
                  key={p.principal_id}
                  className="border border-aegis-steel/20 bg-white/80 px-3 py-3"
                >
                  <p className="font-medium text-aegis-ink">{p.principal_id}</p>
                  <p className="text-xs text-aegis-mist">
                    {p.principal_type} · tenant {p.tenant_id} · {p.status}
                  </p>
                  <p className="mt-1 text-xs text-aegis-slate">
                    roles: {p.roles.join(", ") || "—"}
                  </p>
                  <p className="text-xs text-aegis-slate">
                    perms: {p.permissions.join(", ")}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Tool capabilities" description="Explicit capabilities — no wildcards.">
          <ul className="space-y-2 text-sm">
            {capabilities.map((c) => (
              <li
                key={c.tool_name}
                className="border border-aegis-steel/20 bg-white/80 px-3 py-3"
              >
                <p className="font-medium text-aegis-ink">{c.tool_name}</p>
                <p className="text-xs text-aegis-mist">
                  {c.capability} · scope {c.target_scope} · risk {c.risk_level}
                  {c.requires_approval ? " · approval required" : ""}
                </p>
              </li>
            ))}
          </ul>
        </Section>
      </div>

      <Section title="Authorize simulator" description="Calls POST /api/v1/auth/authorize.">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-sm">
            Principal
            <select
              className="mt-1 w-full border border-aegis-steel/30 bg-white px-2 py-2"
              value={principalId}
              onChange={(e) => setPrincipalId(e.target.value)}
            >
              {principals.map((p) => (
                <option key={p.principal_id} value={p.principal_id}>
                  {p.principal_id}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            Tool
            <select
              className="mt-1 w-full border border-aegis-steel/30 bg-white px-2 py-2"
              value={toolName}
              onChange={(e) => {
                setToolName(e.target.value);
                const next = capabilities.find((c) => c.tool_name === e.target.value);
                setTarget(next?.allowed_targets?.[0] ?? "");
              }}
            >
              {capabilities.map((c) => (
                <option key={c.tool_name} value={c.tool_name}>
                  {c.tool_name}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            Target
            <select
              className="mt-1 w-full border border-aegis-steel/30 bg-white px-2 py-2"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            >
              {(cap?.allowed_targets ?? []).map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            Resource tenant (optional cross-tenant probe)
            <input
              className="mt-1 w-full border border-aegis-steel/30 bg-white px-2 py-2"
              value={resourceTenant}
              onChange={(e) => setResourceTenant(e.target.value)}
              placeholder="e.g. tenant-b"
            />
          </label>
          <label className="flex items-center gap-2 text-sm sm:col-span-2">
            <input
              type="checkbox"
              checked={intentOk}
              onChange={(e) => setIntentOk(e.target.checked)}
            />
            Intent aligned with original user task
          </label>
        </div>
        <button
          type="button"
          className="mt-4 bg-aegis-ink px-3 py-2 text-sm font-medium text-white disabled:opacity-60"
          disabled={running}
          onClick={() => void onAuthorize()}
        >
          {running ? "Authorizing…" : "Authorize"}
        </button>
        {runError ? <ErrorState title="Authorize failed" message={runError} /> : null}
        {result ? (
          <div className="mt-4 space-y-2 border border-aegis-steel/20 bg-white/80 p-4 text-sm">
            <div className="flex flex-wrap gap-2">
              <ToolVerdictBadge value={result.decision} />
              <PolicyDecisionBadge value={result.decision === "DENY" ? "BLOCK" : "ALLOW"} />
            </div>
            <p>Capability: {result.capability ?? "—"}</p>
            <p>Tenant: {result.tenant_id ?? "—"}</p>
            <p>Version: {result.authorization_version}</p>
            <p>Reasons: {result.reason_codes.join(", ") || "—"}</p>
            <p className="text-aegis-mist">{result.explanation}</p>
          </div>
        ) : null}
      </Section>
    </div>
  );
}
