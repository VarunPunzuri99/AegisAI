/**
 * Public backend base URL. Never put API keys in frontend code.
 * Prefer NEXT_PUBLIC_API_URL (existing convention); NEXT_PUBLIC_API_BASE_URL accepted as alias.
 */
export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ??
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  "http://localhost:8000";

export const API_PREFIX = "/api/v1";
