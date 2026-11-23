import { APITransportError } from "./client";

export type AddonInstallation = Readonly<{
  device_id: string;
  cohort: string;
  device_state: "pending" | "active" | "retired";
  partition_id: string;
  installation_id: string;
  observation: "complete" | "partial" | "last_complete";
  generation: number;
  latest_generation: number;
  reported_at: string | null;
  latest_reported_at: string | null;
}>;
const id =
  /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ref = /^[a-f0-9]{64}$/;
const invalid = (): never => {
  throw new APITransportError(
    "invalid_response",
    "Invalid installation observation",
  );
};
function object(v: unknown): Record<string, unknown> {
  if (!v || Array.isArray(v) || typeof v !== "object") return invalid();
  return v as Record<string, unknown>;
}
function generation(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
}
function time(v: unknown): v is string | null {
  return (
    v === null || (typeof v === "string" && Number.isFinite(Date.parse(v)))
  );
}
export function decodeAddonInstallationPage(
  raw: unknown,
  cursor?: string,
  limit = 25,
) {
  const page = object(raw);
  if (!Array.isArray(page.items) || page.items.length > limit) return invalid();
  const items = page.items.map((value): AddonInstallation => {
    const r = object(value);
    if (
      typeof r.device_id !== "string" ||
      !id.test(r.device_id) ||
      typeof r.cohort !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(r.cohort) ||
      !["pending", "active", "retired"].includes(String(r.device_state)) ||
      typeof r.partition_id !== "string" ||
      !ref.test(r.partition_id) ||
      typeof r.installation_id !== "string" ||
      !ref.test(r.installation_id) ||
      !["complete", "partial", "last_complete"].includes(
        String(r.observation),
      ) ||
      !generation(r.generation) ||
      !generation(r.latest_generation) ||
      r.generation > r.latest_generation ||
      (r.observation === "last_complete") !==
        r.latest_generation > r.generation ||
      !time(r.reported_at) ||
      !time(r.latest_reported_at)
    )
      return invalid();
    return r as AddonInstallation;
  });
  const keys = items.map((r) =>
    [r.device_id, r.partition_id, r.installation_id].join("."),
  );
  if (
    keys.some((k, i) =>
      i === 0 ? cursor !== undefined && k <= cursor : k <= keys[i - 1],
    )
  )
    return invalid();
  if (
    page.next_cursor !== null &&
    (typeof page.next_cursor !== "string" ||
      !keys.length ||
      page.next_cursor !== keys.at(-1))
  )
    return invalid();
  return { items, next_cursor: page.next_cursor as string | null };
}
