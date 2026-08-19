import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { APITransportError } from "../../../apps/web/api/client";
import { WorkflowMutationProvider, useRetainedWorkflowMutation } from "./useRetainedWorkflowMutation";

function ScopeProbe() {
  const mutation = useRetainedWorkflowMutation<{ name: string }>("policies");
  const start = () => void mutation.execute({ name: "Production policy" }, async () => {
    throw new APITransportError("timeout", "committed response lost");
  }).catch(() => undefined);
  return mutation.hasAmbiguousAttempt
    ? <button onClick={() => undefined}>Retry exact retained policy operation</button>
    : <button onClick={start}>Start policy operation</button>;
}

describe("scope-owned workflow mutation registry", () => {
  it("hides scope A's unresolved attempt in B and restores it when A returns", async () => {
    const user = userEvent.setup();
    const view = render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ScopeProbe /></WorkflowMutationProvider>);
    await user.click(screen.getByRole("button", { name: "Start policy operation" }));
    expect(await screen.findByRole("button", { name: "Retry exact retained policy operation" })).toBeVisible();

    view.rerender(<WorkflowMutationProvider scopeKey="organization/workspace-b/environment-b"><ScopeProbe /></WorkflowMutationProvider>);
    expect(screen.queryByRole("button", { name: "Retry exact retained policy operation" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start policy operation" })).toBeVisible();

    view.rerender(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ScopeProbe /></WorkflowMutationProvider>);
    expect(screen.getByRole("button", { name: "Retry exact retained policy operation" })).toBeVisible();
  });
});
