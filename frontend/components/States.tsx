export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      className="border border-dashed border-aegis-steel/30 bg-white/50 px-4 py-10 text-center text-sm text-aegis-mist"
      role="status"
      aria-live="polite"
    >
      {label}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  message,
}: {
  title?: string;
  message: string;
}) {
  return (
    <div
      className="border border-rose-300/70 bg-rose-50 px-4 py-6 text-sm text-rose-950"
      role="alert"
    >
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-rose-900/80">{message}</p>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="border border-aegis-steel/20 bg-white/60 px-4 py-8 text-center text-sm text-aegis-mist">
      {message}
    </div>
  );
}

export function UnavailableState({ message }: { message: string }) {
  return (
    <div
      className="border border-amber-300/70 bg-amber-50 px-4 py-6 text-sm text-amber-950"
      role="status"
    >
      <p className="font-semibold">Unavailable</p>
      <p className="mt-1">{message}</p>
    </div>
  );
}
