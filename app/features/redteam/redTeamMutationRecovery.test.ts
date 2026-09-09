import { describe, expect, it, vi } from "vitest";
import { APIProductError } from "../../../apps/web/api/client";
import type { ProductionRedTeamAPI } from "./api";
import { createRedTeamMutationRecovery, type RecoveryStorage, type RedTeamIntent } from "./redTeamMutationRecovery";

const principal = "pid_92200001-0000-4000-8000-000000000001";
const scope = `${principal}/pid_92200002-0000-4000-8000-000000000002/pid_92200003-0000-4000-8000-000000000003/pid_92200004-0000-4000-8000-000000000004`;
const intent: RedTeamIntent = { kind:"run", id:"pid_92200005-0000-4000-8000-000000000005", version:7, runID:"pid_92200006-0000-4000-8000-000000000006" };
const run = { id:intent.runID, definition_id:intent.id, definition_version:7, version:1, status:"queued" as const, attempt:0, cancel_requested:false, queued_at:"2026-09-09T00:00:00Z" };
function fixture() {
  const values = new Map<string,string>();
  const storage: RecoveryStorage = { getItem:key=>values.get(key)??null, setItem:(key,value)=>{values.set(key,value);}, removeItem:key=>{values.delete(key);} };
  const send = vi.fn().mockResolvedValue(run);
  const api = { runDefinition:send } as unknown as ProductionRedTeamAPI;
  return {values,storage,send,api, make:(authorized=()=>true)=>createRedTeamMutationRecovery(scope,storage,api,authorized)};
}

describe("principal-scoped durable Red Team intent",()=>{
  it("does not clear replaced recovery ownership when a delayed rejection arrives",async()=>{
    const f=fixture(); let reject!:(error:unknown)=>void;
    f.send.mockImplementationOnce(()=>new Promise((_resolve,fail)=>{reject=fail;}));
    const controller=f.make(); const pending=controller.execute(intent);
    const storageKey=[...f.values.keys()][0]; const replacement=f.values.get(storageKey)! + " "; f.values.set(storageKey,replacement);
    reject(new APIProductError(409,{code:"version_conflict",message:"conflict",retryable:false,correlation_id:principal}));
    await expect(pending).rejects.toThrow(); expect(f.values.get(storageKey)).toBe(replacement); expect(controller.getSnapshot().unavailable).toBe(true);
  });
  it("releases a directly rejected version conflict but retains one after response loss",async()=>{
    const conflict = new APIProductError(409,{code:"version_conflict",message:"version conflict",retryable:false,correlation_id:principal});
    const direct=fixture();direct.send.mockRejectedValueOnce(conflict);const first=direct.make();await expect(first.execute(intent)).rejects.toThrow();expect(first.getSnapshot().pending).toBeNull();expect(direct.values.size).toBe(0);
    const ambiguous=fixture();ambiguous.send.mockRejectedValueOnce(new TypeError("lost")).mockRejectedValueOnce(conflict);const second=ambiguous.make();await expect(second.execute(intent)).rejects.toThrow();await expect(second.retry()).rejects.toThrow();expect(second.getSnapshot().pending).toEqual(intent);expect(ambiguous.values.size).toBe(1);
  });
  it("retains an idempotency conflict instead of allocating a replacement request",async()=>{
    const f=fixture();f.send.mockRejectedValueOnce(new APIProductError(409,{code:"idempotency_conflict",message:"conflicting intent",retryable:false,correlation_id:principal}));const controller=f.make();await expect(controller.execute(intent)).rejects.toThrow();expect(controller.getSnapshot().pending).toEqual(intent);
  });
  it("fails closed if storage becomes unreadable before retry",async()=>{
    const f=fixture();f.send.mockRejectedValueOnce(new TypeError("lost"));let failed=false;const storage={...f.storage,getItem:(key:string)=>{if(failed)throw new Error("denied");return f.storage.getItem(key);}};
    const controller=createRedTeamMutationRecovery(scope,storage,f.api,()=>true);await expect(controller.execute(intent)).rejects.toThrow();failed=true;await expect(controller.retry()).rejects.toThrow();expect(controller.getSnapshot().unavailable).toBe(true);expect(f.send).toHaveBeenCalledTimes(1);
  });
  it("retains before I/O and recovers exactly the same operation after remount",async()=>{
    const f=fixture(); f.send.mockImplementationOnce(()=>{expect(f.values.size).toBe(1);throw new TypeError("response lost");});
    const first=f.make(); await expect(first.execute(intent)).rejects.toThrow(); const args=f.send.mock.calls[0];first.dispose();
    const restored=f.make();expect(restored.getSnapshot().pending).toEqual(intent);expect(f.send).toHaveBeenCalledTimes(1);
    await restored.retry();expect(f.send.mock.calls[1].slice(0,4)).toEqual(args.slice(0,4));expect(f.values.size).toBe(0);
  });
  it("blocks duplicate and competing controllers synchronously",async()=>{
    const f=fixture();let finish!:(value:typeof run)=>void;f.send.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
    const first=f.make(), second=f.make();const pending=first.execute(intent);
    await expect(first.execute(intent)).rejects.toThrow();await expect(second.execute(intent)).rejects.toThrow();expect(f.send).toHaveBeenCalledTimes(1);
    finish(run);await pending;
  });
  it("leaves the original checkpoint after an aborted response arrives late",async()=>{
    const f=fixture();let finish!:(value:typeof run)=>void;f.send.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
    const first=f.make();const pending=first.execute(intent);first.dispose();finish(run);await expect(pending).rejects.toThrow();
    expect(f.make().getSnapshot().pending).toEqual(intent);expect(f.values.size).toBe(1);
  });
  it("does not expose one principal's intent to another principal or environment",async()=>{
    const f=fixture();f.send.mockRejectedValueOnce(new TypeError("lost"));await expect(f.make().execute(intent)).rejects.toThrow();
    for(const other of [scope.replace(principal,"pid_92300001-0000-4000-8000-000000000001"),scope.replace("pid_92200004","pid_92300004")]) {
      expect(createRedTeamMutationRecovery(other,f.storage,f.api,()=>true).getSnapshot().pending).toBeNull();
    }
    expect(f.send).toHaveBeenCalledTimes(1);
  });
  it("requires working retention before sending",async()=>{
    const f=fixture();const broken={...f.storage,setItem:()=>{throw new Error("quota");}};
    const controller=createRedTeamMutationRecovery(scope,broken,f.api,()=>true);await expect(controller.execute(intent)).rejects.toThrow();
    expect(controller.getSnapshot().unavailable).toBe(true);expect(f.send).not.toHaveBeenCalled();
    expect(createRedTeamMutationRecovery(scope,undefined,f.api,()=>true).getSnapshot().unavailable).toBe(true);
  });
  it("keeps a verified response retryable if checkpoint acknowledgement fails",async()=>{
    const f=fixture();const broken={...f.storage,removeItem:()=>{throw new Error("storage denied");}};
    await expect(createRedTeamMutationRecovery(scope,broken,f.api,()=>true).execute(intent)).rejects.toThrow();
    expect(f.make().getSnapshot().pending).toEqual(intent);await f.make().retry();expect(f.send.mock.calls[1].slice(0,4)).toEqual(f.send.mock.calls[0].slice(0,4));
  });
  it("rejects changed request ownership before retry without calling the API",async()=>{
    const f=fixture();f.send.mockRejectedValueOnce(new TypeError("lost"));const controller=f.make();await expect(controller.execute(intent)).rejects.toThrow();
    f.values.clear();await expect(controller.retry()).rejects.toThrow();expect(controller.getSnapshot().unavailable).toBe(true);expect(f.send).toHaveBeenCalledTimes(1);
  });
  it("rejects authorization drift before retry and after a delayed response",async()=>{
    const f=fixture();let authorized=true;let finish!:(value:typeof run)=>void;f.send.mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));
    const controller=f.make(()=>authorized);const pending=controller.execute(intent);authorized=false;finish(run);await expect(pending).rejects.toThrow();
    await expect(controller.retry()).rejects.toThrow();expect(f.send).toHaveBeenCalledTimes(1);expect(controller.getSnapshot().pending).toEqual(intent);
  });
  for(const name of ["invalid JSON","oversize","wrong scope","credential field","wrong run","wrong version","wrong operation"]) {
    it(`rejects ${name} in retained storage`,async()=>{
      const f=fixture();f.send.mockRejectedValueOnce(new TypeError("lost"));await expect(f.make().execute(intent)).rejects.toThrow();
      const [storageKey,saved]=[...f.values.entries()][0];const record=JSON.parse(saved);
      if(name==="wrong scope")record.scope=principal;
      if(name==="credential field")record.intent.credential="synthetic-secret-must-not-be-retained";
      if(name==="wrong run")record.intent.runID=record.intent.id;
      if(name==="wrong version")record.intent.version=0;
      if(name==="wrong operation")record.intent.kind="arbitrary";
      f.values.set(storageKey,name==="invalid JSON"?"{":name==="oversize"?" ".repeat(16385):JSON.stringify(record));
      const restored=f.make();expect(restored.getSnapshot().unavailable).toBe(true);await expect(restored.retry()).rejects.toThrow();expect(f.send).toHaveBeenCalledTimes(1);
    });
  }
});
