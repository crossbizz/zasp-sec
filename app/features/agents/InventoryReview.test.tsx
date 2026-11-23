import {render,screen} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {expect,it,vi} from "vitest";
import {APIProvider} from "../../api/APIProvider";
import {InventoryReview} from "./InventoryReview";
import type {InventoryReviewReceipt} from "../../../apps/web/api/generated";

vi.mock("../../auth/SessionProvider",async(importOriginal)=>{
 const source=await importOriginal<typeof import("../../auth/SessionProvider")>();
 return {...source,useOptionalSession:()=>({status:"authenticated",isFreshAuthenticated:true,hasCapability:()=>true})};
});
const id="pid_11111111-1111-4111-8111-111111111111";
it("shows the explicit degraded state after an unqualified review",async()=>{
 const user=userEvent.setup();
 const receipt:InventoryReviewReceipt={target_id:id,purpose:"agent_discovery_verify",coverage_degraded:true,result:null};
 const review=vi.fn(async()=>receipt);
 render(<APIProvider><InventoryReview id={id} purposes={["agent_discovery_verify"]} review={review}/></APIProvider>);
 await user.click(screen.getByRole("button",{name:"Verify discovery"}));
 expect(await screen.findByText(/optional model review is unavailable/)).toBeVisible();
 expect(review).toHaveBeenCalledWith(id,"agent_discovery_verify",expect.any(String),expect.any(AbortSignal));
});
it("keeps static threat and impact scores separate with citations",async()=>{
 const user=userEvent.setup();
 const receipt:InventoryReviewReceipt={target_id:id,purpose:"addon_semantic_audit",coverage_degraded:false,result:{threat_score:0.1,risk_score:0.8,tags:[],citations:["script.network_access"]}};
 render(<APIProvider><InventoryReview id={id} purposes={["addon_semantic_audit"]} review={async()=>receipt}/></APIProvider>);
 await user.click(screen.getByRole("button",{name:"Review static findings"}));
 expect(await screen.findByText("10%")).toBeVisible();
 expect(screen.getByText("80%")).toBeVisible();
 expect(screen.getByText("script.network_access")).toBeVisible();
});
