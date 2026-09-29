"use client";

/**
 * Development Authentication — tokens held in memory only.
 * Do NOT use localStorage / sessionStorage / URL query parameters.
 */

import {
  createContext,
  useContext,
  useState,
  type ReactNode,
} from "react";
import { registerAuthTokenGetter as registerGetter } from "@/lib/auth-token";

export type DemoIdentity = {
  id: string;
  label: string;
  principalId: string;
  envKey: string;
};

export const DEMO_IDENTITIES: DemoIdentity[] = [
  {
    id: "user",
    label: "user:demo (tenant-a)",
    principalId: "user:demo",
    envKey: "NEXT_PUBLIC_AEGIS_DEMO_TOKEN_USER",
  },
  {
    id: "readonly",
    label: "user:readonly (tenant-a)",
    principalId: "user:readonly",
    envKey: "NEXT_PUBLIC_AEGIS_DEMO_TOKEN_READONLY",
  },
  {
    id: "agent",
    label: "agent:aegis-demo (no audit)",
    principalId: "agent:aegis-demo",
    envKey: "NEXT_PUBLIC_AEGIS_DEMO_TOKEN_AGENT",
  },
  {
    id: "tenant-b",
    label: "user:tenant-b",
    principalId: "user:tenant-b",
    envKey: "NEXT_PUBLIC_AEGIS_DEMO_TOKEN_TENANT_B",
  },
];

function tokenFromEnv(envKey: string): string {
  if (typeof process === "undefined") return "";
  const map: Record<string, string | undefined> = {
    NEXT_PUBLIC_AEGIS_DEMO_TOKEN_USER:
      process.env.NEXT_PUBLIC_AEGIS_DEMO_TOKEN_USER,
    NEXT_PUBLIC_AEGIS_DEMO_TOKEN_READONLY:
      process.env.NEXT_PUBLIC_AEGIS_DEMO_TOKEN_READONLY,
    NEXT_PUBLIC_AEGIS_DEMO_TOKEN_AGENT:
      process.env.NEXT_PUBLIC_AEGIS_DEMO_TOKEN_AGENT,
    NEXT_PUBLIC_AEGIS_DEMO_TOKEN_TENANT_B:
      process.env.NEXT_PUBLIC_AEGIS_DEMO_TOKEN_TENANT_B,
  };
  return (map[envKey] || "").trim();
}

type AuthContextValue = {
  identityId: string;
  principalId: string;
  token: string | null;
  setIdentityId: (id: string) => void;
  clearAuth: () => void;
  isAuthenticated: boolean;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [identityId, setIdentityIdState] = useState("user");

  const identity =
    DEMO_IDENTITIES.find((i) => i.id === identityId) ?? DEMO_IDENTITIES[0];
  const token = tokenFromEnv(identity.envKey) || null;

  return (
    <AuthContext.Provider
      value={{
        identityId: identity.id,
        principalId: identity.principalId,
        token,
        setIdentityId: setIdentityIdState,
        clearAuth: () => setIdentityIdState("user"),
        isAuthenticated: Boolean(token),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}

export function registerAuthTokenGetter(getter: () => string | null) {
  registerGetter(getter);
}
