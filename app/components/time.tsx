const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

// "14 Nov 2026, 20:00 UTC". Always UTC, so two people reading the same record
// see the same time, and independent of the browser's locale.
export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getUTCDate()} ${months[date.getUTCMonth()]} ${date.getUTCFullYear()}, ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}

// The readable time, with the exact recorded value on hover and for copying.
export function Time({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="muted">—</span>;
  return <time dateTime={value} title={value}>{formatTime(value)}</time>;
}
