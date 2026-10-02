import { render, screen, within } from "@testing-library/react";
import { expect, it } from "vitest";
import type { SecurityAgentActionDetail } from "../../../apps/web/api/generated";
import { ActionDetails } from "./ActionDetails";

it("shows every frozen export source before an artifact result exists", () => {
  const value: SecurityAgentActionDetail = {
    step_id: "pid_78000001-0000-4000-8000-000000000001",
    action: "create_evidence_export",
    arguments: {
      target_id: "pid_78000002-0000-4000-8000-000000000002",
      evidence_ids: [
        { source_kind: "finding", source_id: "pid_78000003-0000-4000-8000-000000000003", source_version: 7, association_digest: `sha256:${"a".repeat(64)}` },
        { source_kind: "manual", source_id: "b".repeat(64), source_version: 2, association_digest: `sha256:${"c".repeat(64)}` },
      ],
    },
    result: null,
    ttl_seconds: null,
    control_expires_at: null,
    rollback: { support: "not_supported", state: "unavailable", verification: { state: "unavailable", source: "none" } },
    verification: { state: "unavailable", source: "none" },
  };
  render(<ActionDetails stepID={value.step_id} value={value} />);
  const selections = within(screen.getByRole("list", { name: "Selected export evidence" }));
  const items = selections.getAllByRole("listitem");
  expect(items).toHaveLength(2);
  expect(items[0]).toHaveTextContent("finding");
  expect(items[0]).toHaveTextContent("pid_78000003-0000-4000-8000-000000000003");
  expect(items[0]).toHaveTextContent("version 7");
  expect(items[1]).toHaveTextContent("manual");
  expect(items[1]).toHaveTextContent("b".repeat(64));
  expect(items[1]).toHaveTextContent("version 2");
  expect(screen.getByText("No effect result recorded.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument();
});
