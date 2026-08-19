export function safeReturnPath(value: string | null | undefined): string {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return "/";
  try {
    const origin = "https://same-origin.invalid";
    const parsed = new URL(value, origin);
    return parsed.origin === origin ? `${parsed.pathname}${parsed.search}` : "/";
  } catch {
    return "/";
  }
}

export function buildIdentityStartURL(returnTo: string): string {
  return `/api/v1/session/start?return_to=${encodeURIComponent(safeReturnPath(returnTo))}`;
}
