"use client";

import { useCallback, useState } from "react";
import type {
  AddonReviewAPI,
  AddonVersion,
} from "../../../apps/web/api/addon-reviews";
import { useAPIQuery } from "../../api/query";
import { Button } from "../../components/ui";
import { Time } from "../../components/time";

export function AddonInstallations({
  api,
  version,
}: {
  api: AddonReviewAPI;
  version: AddonVersion;
}) {
  const [history, setHistory] = useState<string[]>([]);
  const cursor = history.at(-1);
  const load = useCallback(
    (signal?: AbortSignal) => api.installations(version.id, cursor, signal),
    [api, version.id, cursor],
  );
  const result = useAPIQuery(
    `addon-installations:${version.id}:${cursor ?? ""}`,
    load,
  );
  return (
    <section aria-label="Matching device installations">
      <h3>Matching device installations</h3>
      {version.review_state === "revoked" && (
        <p>
          This version’s review is revoked. Device inventory shows where to
          investigate. Removal and policy acknowledgment require separate
          evidence.
        </p>
      )}
      {result.status === "loading" && <p>Loading installation evidence…</p>}
      {(result.status === "error" || result.status === "stale") && (
        <p role="status">
          Could not refresh device inventory.{" "}
          <Button onClick={() => void result.retry()}>Retry</Button>
        </p>
      )}
      {result.data &&
        (result.data.items.length ? (
          <table>
            <thead>
              <tr>
                <th>Device and cohort</th>
                <th>Installation</th>
                <th>Inventory evidence</th>
                <th>Reported</th>
              </tr>
            </thead>
            <tbody>
              {result.data.items.map((row) => (
                <tr
                  key={[
                    row.device_id,
                    row.partition_id,
                    row.installation_id,
                  ].join(".")}
                >
                  <td>
                    <a
                      href={`/integrations/sensors?device=${encodeURIComponent(row.device_id)}`}
                    >
                      {row.device_id}
                    </a>
                    <br />
                    {row.cohort} · {row.device_state}
                  </td>
                  <td>
                    <code title={row.installation_id}>
                      {row.installation_id.slice(0, 12)}
                    </code>
                  </td>
                  <td>
                    {row.observation === "last_complete"
                      ? `Last complete snapshot ${row.generation}. Latest snapshot ${row.latest_generation} was partial`
                      : `${row.observation === "complete" ? "Complete" : "Partial"} snapshot ${row.generation}`}
                  </td>
                  <td>
                    {row.reported_at ? (
                      <Time value={row.reported_at} />
                    ) : (
                      "Unknown"
                    )}
                    {row.observation === "last_complete" &&
                      row.latest_reported_at && (
                        <>
                          <br />
                          Latest partial report{" "}
                          <Time value={row.latest_reported_at} />
                        </>
                      )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>
            No matching installation was reported in the available device
            inventory.
          </p>
        ))}
      {history.length > 0 && (
        <Button onClick={() => setHistory((v) => v.slice(0, -1))}>
          Previous installations
        </Button>
      )}
      {result.data?.next_cursor && (
        <Button
          onClick={() => {
            const next = result.data?.next_cursor;
            if (next) setHistory((v) => [...v, next]);
          }}
        >
          Next installations
        </Button>
      )}
    </section>
  );
}
