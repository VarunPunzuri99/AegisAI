/** Shared TypeScript types (expand in later phases). */

export type HealthResponse = {
  status: string;
  service: string;
  version?: string;
};
