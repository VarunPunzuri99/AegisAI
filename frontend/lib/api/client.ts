import { API_PREFIX, API_URL } from "@/lib/config";
import { getAuthToken } from "@/lib/auth-token";

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(message: string, status: number, body: unknown = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

type RequestOptions = {
  method?: string;
  body?: unknown;
  timeoutMs?: number;
  signal?: AbortSignal;
};

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = "GET", body, timeoutMs = 120_000, signal } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort);

  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const token = getAuthToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_URL}${API_PREFIX}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      cache: "no-store",
    });

    const text = await response.text();
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
    }

    if (!response.ok) {
      const errObj =
        typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
      const nested =
        errObj && typeof errObj.error === "object" && errObj.error !== null
          ? (errObj.error as Record<string, unknown>)
          : null;
      const detail =
        (nested && typeof nested.message === "string" && nested.message) ||
        (errObj && typeof errObj.detail === "string" && errObj.detail) ||
        `Request failed (${response.status})`;
      throw new ApiError(detail, response.status, parsed);
    }

    return parsed as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError("Request timed out or was cancelled", 408);
    }
    throw new ApiError(
      err instanceof Error ? err.message : "Network request failed",
      0,
      err,
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}
