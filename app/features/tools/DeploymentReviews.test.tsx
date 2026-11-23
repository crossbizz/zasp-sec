import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { APIProvider } from "../../api/APIProvider";
import type { DeploymentAPI } from "../../../apps/web/api/addon-deployments";
import { decodeDeploymentApproval } from "../../../apps/web/api/addon-deployments";
import type { DeploymentApproval } from "../../../apps/web/api/generated";
import { DeploymentReviews } from "./DeploymentReviews";

const agent = "pid_11111111-1111-4111-8111-111111111111";
const version = "pid_22222222-2222-4222-8222-222222222222";
const record: DeploymentApproval = {
  addon_version_id: version, agent_id: agent, revision: 1, state: "needs_re_review",
  access_revision: 2, purpose_revision: 1, identity_count: 1, version_approved: true,
  permission_context_digest: "sha256:"+"0".repeat(64), destinations:["internal"],classifications:["customer"],
};
it("selects a deployment, confirms its current context and reloads its receipt", async () => {
  const user = userEvent.setup();
  let current = record;
  const api: DeploymentAPI = {
    agents: async () => [{id:agent,name:"Help desk"}],
    get: async () => current,
    review: vi.fn(async ({receipt,decision}) => {
      expect(receipt.permission_context_digest).toEqual(record.permission_context_digest);
      current = {...record,state:decision,revision:2};
      return current;
    }),
  };
  render(<APIProvider><DeploymentReviews api={api} versionID={version} versionRevision={1} canReview /></APIProvider>);
  await user.click(screen.getByRole("button",{name:"Review a deployment"}));
  await user.selectOptions(await screen.findByRole("combobox",{name:"Deployment agent"}),agent);
  expect(await screen.findByText(/Permissions changed/)).toBeVisible();
  await user.click(screen.getByRole("button",{name:"Approve deployment"}));
  expect(api.review).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button",{name:"Confirm deployment decision"}));
  expect(await screen.findByText("Approved")).toBeVisible();
  expect(api.review).toHaveBeenCalledTimes(1);
});

it("rejects a receipt bound to a different deployment", () => {
  expect(() => decodeDeploymentApproval({...record,agent_id:version},version,agent)).toThrow();
});
