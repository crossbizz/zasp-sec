const origins = new Map([
  ["https://claude.ai", "claude"],
  ["https://chatgpt.com", "chatgpt"],
]);
const rulePrefix = "zasp-origin-";
const keyPrefix = "usage/";
const dayLength = 86_400_000;

export function parsePolicy(raw) {
  const inactive = (status) => ({ status, origins: [], retentionDays: 7 });
  if (!Object.hasOwn(raw, "Enabled")) return inactive("unconfigured");
  if (raw.Enabled === false) return inactive("disabled");
  if (raw.Enabled !== true || !Array.isArray(raw.AllowedOrigins) || !raw.AllowedOrigins.length) {
    return inactive("invalid");
  }
  const days = raw.RetentionDays === undefined ? 7 : raw.RetentionDays;
  if (!Number.isInteger(days) || days < 1 || days > 30 ||
      raw.AllowedOrigins.some((origin) => !origins.has(origin))) {
    return inactive("invalid");
  }
  return { status: "enabled", origins: [...new Set(raw.AllowedOrigins)].sort(), retentionDays: days, ...(raw.CentralReportingEnabled === true ? { remoteEnabled: true } : {}) };
}

function day(date) {
  return date.toISOString().slice(0, 10);
}

function usageKey(origin, date) {
  return keyPrefix + origins.get(origin) + "/" + day(date);
}

function decodeKey(key) {
  if (!key.startsWith(keyPrefix)) return;
  const [id, date, ...extra] = key.slice(keyPrefix.length).split("/");
  const origin = [...origins].find(([, slug]) => slug === id)?.[0];
  if (origin && !extra.length && /^\d{4}-\d{2}-\d{2}$/.test(date)) return { origin, day: date };
}

function registration(origin) {
  return {
    id: rulePrefix + origins.get(origin),
    matches: [origin + "/*"],
    js: ["observe.js"],
    allFrames: false,
    runAt: "document_start",
    world: "ISOLATED",
    persistAcrossSessions: true,
  };
}

export function createGuard(api, clock = () => new Date()) {
  async function currentPolicy() {
    try {
      return parsePolicy(await api.storage.managed.get(["Enabled", "AllowedOrigins", "RetentionDays", "CentralReportingEnabled"]));
    } catch {
      return { status: "unavailable", origins: [], retentionDays: 7 };
    }
  }

  async function refreshRegistrations(policy) {
    const wanted = policy.origins.map(registration);
    const installed = (await api.scripting.getRegisteredContentScripts()).map((rule) => rule.id);
    const remove = installed.filter((id) => id.startsWith(rulePrefix) && !wanted.some((rule) => rule.id === id));
    if (remove.length) await api.scripting.unregisterContentScripts({ ids: remove });
    const add = wanted.filter((item) => !installed.includes(item.id));
    if (add.length) await api.scripting.registerContentScripts(add);
  }

  async function retained(policy) {
    const now = clock();
    const earliest = day(new Date(now.getTime() - (policy.retentionDays - 1) * dayLength));
    const today = day(now);
    const stored = await api.storage.local.get(null);
    const observations = [], remove = [];
    for (const [key, value] of Object.entries(stored)) {
      if (!key.startsWith(keyPrefix)) continue;
      const seen = decodeKey(key);
      if (value !== true || !seen || !policy.origins.includes(seen.origin) || seen.day < earliest || seen.day > today) {
        remove.push(key);
      } else {
        observations.push(seen);
      }
    }
    if (remove.length) await api.storage.local.remove(remove);
    return observations.sort((a, b) => b.day.localeCompare(a.day) || a.origin.localeCompare(b.origin));
  }

  async function refresh() {
    const policy = await currentPolicy();
    const observations = await retained(policy);
    await refreshRegistrations(policy);
    return { policy, observations };
  }

  async function observe(sender) {
    // Ignore page-provided fields and browser URL, path, title and profile data.
    if (sender.id !== api.runtime.id || sender.frameId !== 0 || sender.tab?.incognito !== false ||
        !Number.isInteger(sender.tab.id) || !origins.has(sender.origin)) return;
    const policy = await currentPolicy();
    if (!policy.origins.includes(sender.origin)) return;
    // Repeated visits on the same UTC day overwrite the same boolean.
    const observed = clock();
    await api.storage.local.set({ [usageKey(sender.origin, observed)]: true });
    return { policy, observation: { origin: sender.origin, day: day(observed) } };
  }
  return { refresh, observe };
}
