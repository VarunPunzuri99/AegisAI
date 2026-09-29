"use client";

import { useEffect, type ReactNode } from "react";
import {
  AuthProvider,
  DEMO_IDENTITIES,
  registerAuthTokenGetter,
  useAuth,
} from "@/lib/auth";
import { DashboardShellInner } from "@/components/DashboardShellInner";

function AuthTokenBridge({ children }: { children: ReactNode }) {
  const auth = useAuth();
  // Register synchronously so child effects see the token on first fetch.
  registerAuthTokenGetter(() => auth.token);
  useEffect(() => {
    registerAuthTokenGetter(() => auth.token);
    return () => registerAuthTokenGetter(() => null);
  }, [auth.token]);
  return <>{children}</>;
}

function DevAuthBanner() {
  const auth = useAuth();
  return (
    <div className="border-b border-amber-700/20 bg-amber-50 px-4 py-2 text-xs text-amber-950 sm:px-6 lg:px-8">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-3">
        <span className="font-semibold uppercase tracking-[0.12em]">
          Development Authentication
        </span>
        <label className="flex items-center gap-2">
          <span className="text-amber-900/70">Identity</span>
          <select
            className="rounded-sm border border-amber-800/30 bg-white px-2 py-1 text-xs"
            value={auth.identityId}
            onChange={(e) => auth.setIdentityId(e.target.value)}
          >
            {DEMO_IDENTITIES.map((i) => (
              <option key={i.id} value={i.id}>
                {i.label}
              </option>
            ))}
          </select>
        </label>
        <span className="text-amber-900/70">
          {auth.isAuthenticated
            ? `Token in memory · ${auth.principalId}`
            : "No demo token configured in frontend .env.local"}
        </span>
        <span className="text-amber-900/50">
          Not a production IdP · tokens never stored in localStorage
        </span>
      </div>
    </div>
  );
}

export function DashboardShell({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <AuthTokenBridge>
        <DevAuthBanner />
        <DashboardShellInner>{children}</DashboardShellInner>
      </AuthTokenBridge>
    </AuthProvider>
  );
}
