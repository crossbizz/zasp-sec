import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {expect,it,vi} from "vitest";
import {APIProvider} from "../../api/APIProvider";
import {WorkforceInventory} from "./WorkforceInventory";
import {decodeWorkforcePage} from "../../../apps/web/api/workforce-inventory";

const id="pid_11111111-1111-4111-8111-111111111111";
const row={id,name:"Receipt reviewer",source:"studio" as const,revision:2,mission:"Inspect recorded receipts",trigger:"finding_opened",read_tools:["inspect_session"],actions:["propose_policy"],trigger_receipts:3,updated_at:"2026-11-01T10:00:00Z"};
it("exposes locked native purposes and paginates through actual registration receipts",async()=>{
 const user=userEvent.setup();
 const list=vi.fn(async(cursor?:string)=>cursor?{items:[],next_cursor:null}:{items:[row],next_cursor:id+".studio"});
 render(<APIProvider><WorkforceInventory list={list}/></APIProvider>);
 expect(await screen.findByText(row.name)).toBeVisible();
 expect(screen.getByText("3 opening receipts")).toBeVisible();
 await user.click(screen.getByText(row.mission));
 expect(screen.getByText("propose policy")).toBeVisible();
 await user.click(screen.getByRole("button",{name:"Next agents"}));
 expect(await screen.findByText(/No registered security agents/)).toBeVisible();
 await user.click(screen.getByRole("button",{name:"Previous agents"}));
 expect(await screen.findByText(row.name)).toBeVisible();
});
it("rejects repeated or unbound cursor pages",()=>{
 expect(()=>decodeWorkforcePage({items:[row,row],next_cursor:null})).toThrow();
 expect(()=>decodeWorkforcePage({items:[row],next_cursor:id+".built_in"})).toThrow();
});
