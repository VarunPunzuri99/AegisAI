export type HealthResponse = {
  status: string;
  service: string;
  version?: string;
};

export * from "./security";
export * from "./evaluation";
export * from "./audit";
