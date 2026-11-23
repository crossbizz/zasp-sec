// Only operator-selected, exact provider upload endpoints may become rules.
// No request data is read. Session rules disappear when the browser exits.
const firstID = 8100;
const maximum = 8;
const uuid = "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}";
const claudePath = new RegExp("^/api/(?:organizations/)?"+uuid+"/upload$");

export function approvedUploadRoutes(raw, enabledOrigins) {
  if (raw.UploadBlockingEnabled !== true) return undefined;
  const urls = raw.UploadBlockingRoutes;
  if (!Array.isArray(urls) || urls.length < 1 || urls.length > maximum || new Set(urls).size !== urls.length) return [];
  for (const value of urls) {
    if (typeof value !== "string" || value.length > 220) return [];
    let url;
    try { url = new URL(value); } catch { return []; }
    if (!enabledOrigins.includes(url.origin) || value !== url.origin + url.pathname) return [];
    const approved = url.origin === "https://claude.ai" && claudePath.test(url.pathname) ||
      url.origin === "https://chatgpt.com" && ["/backend-api/files", "/backend-api/files/prepare"].includes(url.pathname);
    if (!approved) return [];
  }
  return [...urls].sort();
}

export async function reconcileUploadRules(dnr, routes) {
  let status = routes === undefined ? "disabled" : routes.length ? "active" : "invalid";
  if (!dnr) return { status: routes === undefined ? status : "unavailable", count: 0 };
  const owned = rule => Number.isInteger(rule.id) && rule.id >= firstID && rule.id < firstID + maximum;
  const wanted = (routes ?? []).map((route, i) => {
    const hostname = new URL(route).hostname;
    return {
      id: firstID + i, priority: 1, action: { type: "block" },
      condition: {
        urlFilter: "|" + route + "|", isUrlFilterCaseSensitive: true,
        requestMethods: ["post"], resourceTypes: ["xmlhttprequest"], initiatorDomains: [hostname],
      },
    };
  });
  const read = async () => (await dnr.getSessionRules()).filter(owned);
  try {
    const previous = await read();
    if (previous.length || wanted.length) {
      await dnr.updateSessionRules({ removeRuleIds: previous.map(rule => rule.id), addRules: wanted });
      const installed = await read();
      if (installed.length !== wanted.length || wanted.some(rule => !installed.some(applied =>
        applied.id === rule.id && applied.action.type === "block" && applied.condition.urlFilter === rule.condition.urlFilter &&
        applied.condition.isUrlFilterCaseSensitive === true &&
        ["requestMethods", "resourceTypes", "initiatorDomains"].every(key =>
          applied.condition[key]?.length === 1 && applied.condition[key][0] === rule.condition[key][0])))) {
        throw Error("Rule acknowledgment did not match the managed configuration");
      }
    }
    return { status, count: wanted.length };
  } catch {
    // An update failure can leave the previous session rules in place.
    // Remove them when possible and report that the browser needs attention.
    try { await dnr.updateSessionRules({ removeRuleIds: (await read()).map(rule => rule.id) }); } catch { /* status remains unavailable */ }
    return { status: "unavailable", count: 0 };
  }
}
