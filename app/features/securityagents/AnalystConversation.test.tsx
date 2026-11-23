import {render,screen,waitFor} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {expect,it,vi} from "vitest";
import type {APIClient} from "../../../apps/web/api/client";
import type {AnalystThread} from "../../../apps/web/api/generated";
import {APIProvider} from "../../api/APIProvider";
import AnalystConversation from "./AnalystConversation";

const id="pid_10000000-0000-4000-8000-000000000001";
vi.mock("../../auth/SessionProvider",() => ({
  useOptionalSession:() => ({status:"authenticated",isFreshAuthenticated:true}),
  useSession:() => ({status:"authenticated",organizationID:id,workspaceID:id,environmentID:id}),
}));
it("consumes a fresh session read approval on the first question",async () => {
  const user=userEvent.setup();
  const read=vi.fn(async () => {throw Error("unavailable");});
  const client={openAuthorizedEventStream:read} as unknown as APIClient;
  const thread:AnalystThread={id,session_id:id,created_at:"2026-08-10T20:00:00Z",messages:[],requires_session_read_approval:true,requires_external_inventory_approval:true};
  render(<APIProvider client={client}><AnalystConversation thread={thread}/></APIProvider>);
  await user.type(screen.getByRole("textbox",{name:"Question about this session"}),"What was blocked?");
  const send=screen.getByRole("button",{name:"Send question"});
  const grant=screen.getByRole("checkbox",{name:/Approve reading this session/});
  expect(send).toBeDisabled();
  await user.click(grant);
  expect(send).toBeDisabled();
  const external=screen.getByRole("checkbox",{name:/Approve a private connector/});
  await user.click(external);
  await user.click(send);
  await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
  expect(read.mock.calls[0]).toEqual([id,id,"What was blocked?",expect.any(String),expect.anything(),["external_inventory_status","inspect_session"]]);
  expect(grant).not.toBeChecked();
  expect(external).not.toBeChecked();
  expect(send).toBeDisabled();
});
