import { DashboardShell } from "@/components/DashboardShell";

export default function AppLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return <DashboardShell>{children}</DashboardShell>;
}
