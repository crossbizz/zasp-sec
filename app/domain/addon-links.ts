import { addonID } from "../../apps/web/api/addon-reviews";

export function scanReceiptLink(id: string, environment: string) {
  return "/inventory/tools?" + new URLSearchParams({ scan: id, environment_id: environment });
}

export function addonVersionLink(id: string, environment: string) {
  return "/inventory/tools?" + new URLSearchParams({ addon: id, environment_id: environment });
}

export type ScanTarget = { state: "selected"; id: string } | { state: "invalid" | "foreign" };
export type AddonTarget = ScanTarget | { state: "version"; id: string };

export function scopedAddonFromSearch(search: string, environment: string): AddonTarget | undefined {
  const query = new URLSearchParams(search);
  const key = query.has("scan") ? "scan" : "addon";
  // Existing version links select their version in the active session's scope.
  if (key === "addon" && !(query.has("addon") && query.has("environment_id"))) return;
  const id = query.get(key), linked = query.get("environment_id");
  if (query.size !== 2 || !id || !linked || !addonID.test(id) || !addonID.test(linked)) return {state: "invalid"};
  const canonical = `${key}=${id}&environment_id=${linked}`;
  if (search.replace(/^\?/, "") !== canonical) return {state: "invalid"};
  if (linked !== environment) return {state: "foreign"};
  return {state: key === "scan" ? "selected" : "version", id};
}
