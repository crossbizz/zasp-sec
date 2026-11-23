import {
  parseRedTeamStatusLink, redTeamStatusLink, redTeamPath, type RedTeamStatusReference,
} from "../../domain/red-team-status-link";
import type { RecoveryStorage, RedTeamIntent } from "./redTeamMutationRecovery";

// The live component owns the full request. Only a read-only record reference
// survives navigation, bounded by the active API session and authenticated scope.
const openRecords = new WeakMap<object, Map<string, RedTeamStatusReference>>();
const location = () => window.location.pathname + window.location.search + window.location.hash;

export function pendingRedTeamRecord(session: object, scope: string) {
  if (typeof window === "undefined") return null;
  const link = parseRedTeamStatusLink(location(), scope);
  return link.state === "selected" ? link.ref : openRecords.get(session)?.get(scope) ?? null;
}

export function clearRedTeamRecord(session: object, ref: RedTeamStatusReference, returnPath = redTeamPath) {
  const href = redTeamStatusLink(ref);
  if (location() === href) window.history.replaceState(window.history.state, "", returnPath);
  const records = openRecords.get(session);
  const current = records?.get(ref.scope);
  if (current && redTeamStatusLink(current) === href) records?.delete(ref.scope);
}

function reference(scope: string, intent: RedTeamIntent): RedTeamStatusReference {
  switch (intent.kind) {
    case "create": return { kind: "created", id: intent.input.id, version: 0, scope };
    case "run": return { kind: "submitted", id: intent.runID, version: 0, scope };
    case "update": return { kind: "updated", id: intent.id, version: intent.version, scope };
    case "cancel": return { kind: "cancellation", id: intent.id, version: intent.version, scope };
  }
}

export function liveRedTeamCheckpoint(session: object, scope: string): RecoveryStorage | undefined {
  if (typeof window === "undefined") return undefined;
  const original = window.location.pathname === redTeamPath ? location() : redTeamPath;
  let value: string | null = null;
  let selected: RedTeamStatusReference | null = null;
  return {
    getItem: () => value,
    setItem: (_key, data) => {
      if (pendingRedTeamRecord(session, scope)) throw Error("Another record needs review");
      const ref = reference(scope, (JSON.parse(data) as { intent: RedTeamIntent }).intent);
      const href = redTeamStatusLink(ref);
      window.history.replaceState(window.history.state, "", href);
      if (location() !== href) throw Error("Could not retain the record link");
      const records = openRecords.get(session) ?? new Map<string, RedTeamStatusReference>();
      records.set(scope, ref);
      openRecords.set(session, records);
      selected = ref;
      value = data;
    },
    removeItem: () => {
      if (selected) clearRedTeamRecord(session, selected, original);
      value = null;
      selected = null;
    },
  };
}
