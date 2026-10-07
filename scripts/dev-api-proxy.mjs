/** Explicit development-only API routing; no default backend authority. */
export function createDevAPIProxy(origin) {
  if (origin === undefined || origin === "") return undefined;
  let target;
  try {
    target = new URL(origin);
  } catch {
    throw new Error("Invalid ZASP_DEV_API_ORIGIN");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname);
  if (typeof origin !== "string" || target.username || target.password
      || (origin !== target.origin && origin !== `${target.origin}/`)
      || !(target.protocol === "https:" || target.protocol === "http:" && loopback)) {
    throw new Error("Invalid ZASP_DEV_API_ORIGIN");
  }
  return {
    "^/api(?:/|$)": {
      target: target.origin,
      secure: true,
      changeOrigin: false,
    },
  };
}
