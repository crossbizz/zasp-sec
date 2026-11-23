import type { ActivityScope } from "./activity-links";
export type RecoverySelection = { backup: string; restore?: string };
const pid = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const base = "/administration/recovery";
export function recoveryLink(ids: RecoverySelection, scope: ActivityScope) {
  if (![ids.backup, scope.organizationID, scope.workspaceID, scope.environmentID].every(v => pid.test(v)) || ids.restore !== undefined && (!pid.test(ids.restore) || ids.restore === ids.backup)) throw Error("Invalid recovery reference");
  return `${base}?${new URLSearchParams({ backup_id: ids.backup, ...(ids.restore ? {restore_id: ids.restore} : {}), organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID })}`;
}
export function parseRecoveryLink(location: string, current: ActivityScope) {
  if (!location.startsWith(`${base}?backup_id=`)) return { state: "none" as const };
  const q = new URLSearchParams(location.slice(base.length + 1));
  const ids: RecoverySelection = { backup: q.get("backup_id") ?? "", ...(q.has("restore_id") ? {restore: q.get("restore_id")!} : {}) };
  const scope = { organizationID: q.get("organization_id") ?? "", workspaceID: q.get("workspace_id") ?? "", environmentID: q.get("environment_id") ?? "" };
  try { if (recoveryLink(ids, scope) !== location) return { state: "invalid" as const }; } catch { return { state: "invalid" as const }; }
  if (scope.organizationID !== current.organizationID || scope.workspaceID !== current.workspaceID || scope.environmentID !== current.environmentID) return {state: "scope_mismatch" as const};
  return { state: "selected" as const, ids };
}
