/** Evaluation overview types (dataset evaluation only). */

export type DetectionMetrics = {
  true_positives?: number;
  true_negatives?: number;
  false_positives?: number;
  false_negatives?: number;
  precision?: number;
  recall?: number;
  f1?: number;
  false_positive_rate?: number;
  false_negative_rate?: number;
  accuracy?: number;
  total?: number;
};

export type EvaluationOverview = {
  available: boolean;
  source: string;
  note: string;
  dataset_version?: string | null;
  mode?: string | null;
  total_cases?: number | null;
  detection: DetectionMetrics;
  fusion_label_counts: Record<string, number>;
  policy_confusion: {
    confusion?: Record<string, Record<string, number>>;
    actual_totals?: Record<string, number>;
  };
  tool_metrics: Record<string, number | string>;
  live_provider_stats: Record<string, unknown>;
  per_category: Record<string, DetectionMetrics>;
  offline_comparison: Record<string, number>;
  latency_ms: Record<string, number>;
  auth_matrix?: string | null;
  invariants?: string | null;
  false_positives: string[];
  false_negatives: string[];
  generated_at?: string | null;
};
