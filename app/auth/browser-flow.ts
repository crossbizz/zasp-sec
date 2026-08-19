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

export function buildIdentityStartURL(configured: string | undefined, returnTo: string): string | null {
  if (!configured) return null;
  try {
    const target = new URL(configured);
    if (target.protocol !== "https:" || target.username || target.password || target.hash) return null;
    target.searchParams.set("return_to", safeReturnPath(returnTo));
    return target.toString();
  } catch {
    return null;
  }
}
