"use client";

import { useState } from "react";
import { EvidencePanel } from "@/components/EvidencePanel";
import { Section } from "@/components/MetricCard";
import { ErrorState, LoadingState } from "@/components/States";
import { ApiError } from "@/lib/api/client";
import { inspectContent } from "@/lib/api";
import type { InspectResponse } from "@/types/security";

export default function ScannerPage() {
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InspectResponse | null>(null);

  async function onScan() {
    const trimmed = content.trim();
    if (!trimmed) {
      setError("Enter untrusted content to scan.");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const inspect = await inspectContent(trimmed);
      setResult(inspect);
    } catch (err) {
      const message =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Scan failed";
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-aegis-mist">
          Scanner
        </p>
        <h1 className="mt-2 font-display text-3xl text-aegis-ink">
          Inspect untrusted input
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-aegis-slate/75">
          Content is submitted to the FastAPI inspect endpoint. Detection, risk,
          and policy are computed only on the backend. A security event is
          persisted (content hash + decision metadata).
        </p>
      </header>

      <Section title="Security input">
        <label className="block text-sm font-medium text-aegis-slate" htmlFor="scan-input">
          Text
        </label>
        <textarea
          id="scan-input"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={8}
          placeholder="Paste untrusted content here…"
          className="mt-2 w-full resize-y border border-aegis-steel/30 bg-white px-3 py-3 text-sm text-aegis-ink outline-none focus:border-aegis-accent focus-visible:ring-2 focus-visible:ring-aegis-accent/40"
        />
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onScan}
            disabled={loading}
            className="bg-aegis-ink px-4 py-2.5 text-sm font-medium text-white transition hover:bg-aegis-slate disabled:opacity-60"
          >
            {loading ? "Scanning…" : "Scan with AegisAI"}
          </button>
          {result?.event_id ? (
            <span className="font-mono text-xs text-aegis-mist">
              event {result.event_id.slice(0, 8)}…
              {result.persisted ? " · persisted" : ""}
            </span>
          ) : null}
        </div>
      </Section>

      {loading ? <LoadingState label="Running security pipeline…" /> : null}
      {error ? <ErrorState title="Scan failed" message={error} /> : null}
      {result ? (
        <Section title="Evidence chain">
          <EvidencePanel result={result} />
        </Section>
      ) : null}
    </div>
  );
}
