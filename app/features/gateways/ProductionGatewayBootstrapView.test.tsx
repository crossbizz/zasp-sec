import {render,screen,waitFor,cleanup} from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {describe,it,expect,vi} from 'vitest';
import {ProductionGatewayBootstrapView,type GatewayBootstrapAuthority} from './ProductionGatewayBootstrapView';
import type {GatewayBootstrapAPI} from './api';
import {APIProductError} from '../../../apps/web/api/client';
import {device,enrollment,bundle,status,issued,gatewayID} from './bootstrap-fixtures';
const authority:GatewayBootstrapAuthority={key:'principal/org/work/env/query1/session1',permitted:true,fresh:true,sessionValid:true,isCurrent:()=>true};
function api(overrides:Partial<GatewayBootstrapAPI>={}):GatewayBootstrapAPI{return {createGatewayDevice:vi.fn(async()=>({device,replayed:false})),getGatewayDevice:vi.fn(async()=>status),issueGatewayEnrollment:vi.fn(async()=>issued),revokeGatewayEnrollment:vi.fn(async()=>({device,enrollment:{...enrollment,revoked_at:'2026-10-17T12:02:00Z'},replayed:false})),...overrides};}
async function create(user:ReturnType<typeof userEvent.setup>){await user.type(screen.getByLabelText('Gateway name'),device.name);await user.click(screen.getByRole('button',{name:'Create gateway'}));await screen.findByText(gatewayID);}
async function issue(user:ReturnType<typeof userEvent.setup>){await user.click(screen.getByRole('button',{name:'Issue enrollment'}));await screen.findByText(/Copy this enrollment bundle now/);}
describe('production gateway bootstrap connected operator flow',()=>{
 it('creates then issues once clears on close and never uses browser storage or sensor credentials',async()=>{
  const user=userEvent.setup();const backend=api();render(<ProductionGatewayBootstrapView api={backend} authority={authority} onReauthenticate={()=>{}}/>);await create(user);await issue(user);
  expect(document.body.textContent).toContain(bundle.secret);expect(document.body.textContent).toContain('credentialSecretName');expect(document.body.textContent).not.toContain('sensorAgent.tokenSecretName');expect(localStorage.length).toBe(0);expect(sessionStorage.length).toBe(0);
  await user.click(screen.getByRole('button',{name:'Done'}));expect(document.body.textContent).not.toContain(bundle.secret);expect(backend.issueGatewayEnrollment).toHaveBeenCalledTimes(1);expect(backend.getGatewayDevice).toHaveBeenCalled();
 });
 it('clears secrets at principal scope query fresh and session authority boundaries and ignores late responses',async()=>{
  const user=userEvent.setup();const backend=api();const view=render(<ProductionGatewayBootstrapView api={backend} authority={authority} onReauthenticate={()=>{}}/>);await create(user);await issue(user);
  view.rerender(<ProductionGatewayBootstrapView api={backend} authority={{...authority,key:'other-principal/org/work/env/query2/session2',fresh:false,sessionValid:false}} onReauthenticate={()=>{}}/>);await waitFor(()=>expect(document.body.textContent).not.toContain(bundle.secret));
  let finish:((value:typeof issued)=>void)|undefined;const slow=api({issueGatewayEnrollment:()=>new Promise(resolve=>{finish=resolve;})});view.rerender(<ProductionGatewayBootstrapView api={slow} authority={{...authority,key:'second'}} onReauthenticate={()=>{}}/>);await create(user);await user.click(screen.getByRole('button',{name:'Issue enrollment'}));view.rerender(<ProductionGatewayBootstrapView api={slow} authority={{...authority,key:'new-scope-query',isCurrent:()=>false}} onReauthenticate={()=>{}}/>);finish?.(issued);await waitFor(()=>expect(document.body.textContent).not.toContain(bundle.secret));
 });
 it('handles unknown issue through exact metadata refetch deliberate revoke and a new issue attempt',async()=>{
  const user=userEvent.setup();const issueCall=vi.fn().mockRejectedValueOnce(new TypeError('response lost')).mockResolvedValue(issued);const get=vi.fn().mockResolvedValueOnce(status).mockResolvedValueOnce({...status,latest_enrollment:enrollment,issuance_state:'existing_enrollment'}).mockResolvedValue(status);const backend=api({issueGatewayEnrollment:issueCall,getGatewayDevice:get});render(<ProductionGatewayBootstrapView api={backend} authority={authority} onReauthenticate={()=>{}}/>);await create(user);await user.click(screen.getByRole('button',{name:'Issue enrollment'}));await screen.findByText(/may have committed/);expect(issueCall).toHaveBeenCalledTimes(1);expect(document.body.textContent).not.toContain(bundle.secret);await user.click(screen.getByRole('button',{name:'Revoke enrollment'}));await screen.findByRole('button',{name:'Issue enrollment'});await issue(user);expect(issueCall).toHaveBeenCalledTimes(2);expect(issueCall.mock.calls[0][2].idempotencyKey).not.toBe(issueCall.mock.calls[1][2].idempotencyKey);
  // Late independent-review regression controls, after the first 7-pass source.
  // A successful create followed by a failed GET is read recovery only.
  cleanup();
  const confirmedCreate=vi.fn(async()=>({device,replayed:false}));
  const statusRead=vi.fn().mockRejectedValueOnce(new TypeError('metadata response lost')).mockResolvedValue(status);
  render(<ProductionGatewayBootstrapView api={api({createGatewayDevice:confirmedCreate,getGatewayDevice:statusRead})} authority={authority} onReauthenticate={()=>{}}/>);
  await user.type(screen.getByLabelText('Gateway name'),device.name);await user.click(screen.getByRole('button',{name:'Create gateway'}));
  await screen.findByText(/Gateway creation is confirmed/);expect(screen.queryByRole('button',{name:'Create gateway'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Recover gateway creation'})).not.toBeInTheDocument();
  await user.click(screen.getByRole('button',{name:'Retry gateway status'}));await screen.findByRole('button',{name:'Issue enrollment'});
  expect(confirmedCreate).toHaveBeenCalledTimes(1);expect(statusRead.mock.calls.map(call=>call[0])).toEqual([gatewayID,gatewayID]);
  cleanup();
  const rejectedCreate=vi.fn().mockRejectedValueOnce(new APIProductError(400,{code:'invalid_request',message:'Gateway input rejected',correlation_id:'pid_91000006-0000-4000-8000-000000000006',retryable:false})).mockResolvedValue({device,replayed:false});
  render(<ProductionGatewayBootstrapView api={api({createGatewayDevice:rejectedCreate})} authority={authority} onReauthenticate={()=>{}}/>);
  await user.type(screen.getByLabelText('Gateway name'),'é'.repeat(65));expect(screen.getByRole('button',{name:'Create gateway'})).toBeDisabled();expect(rejectedCreate).not.toHaveBeenCalled();
  await user.clear(screen.getByLabelText('Gateway name'));await user.type(screen.getByLabelText('Gateway name'),'rejected-name');await user.click(screen.getByRole('button',{name:'Create gateway'}));await screen.findByText(/input was rejected/);expect(screen.getByLabelText('Gateway name')).toBeEnabled();
  await user.clear(screen.getByLabelText('Gateway name'));await user.type(screen.getByLabelText('Gateway name'),device.name);await user.click(screen.getByRole('button',{name:'Create gateway'}));await screen.findByRole('button',{name:'Issue enrollment'});
  expect(rejectedCreate).toHaveBeenCalledTimes(2);expect(rejectedCreate.mock.calls[0][1].idempotencyKey).not.toBe(rejectedCreate.mock.calls[1][1].idempotencyKey);

 });
 it('requires current environment capability and fresh authentication before mutation',async()=>{
  const backend=api();const reauthenticate=vi.fn();const view=render(<ProductionGatewayBootstrapView api={backend} authority={{...authority,permitted:false}} onReauthenticate={reauthenticate}/>);expect(screen.queryByRole('button',{name:'Create gateway'})).not.toBeInTheDocument();view.rerender(<ProductionGatewayBootstrapView api={backend} authority={{...authority,fresh:false}} onReauthenticate={reauthenticate}/>);await userEvent.click(screen.getByRole('button',{name:'Reauthenticate for gateway setup'}));expect(reauthenticate).toHaveBeenCalledOnce();expect(backend.createGatewayDevice).not.toHaveBeenCalled();
 });
 it('preserves original native issuance blockers without claiming enrollment revokes credentials',async()=>{
  const user=userEvent.setup();const backend=api({getGatewayDevice:async()=>({...status,issuance_state:'existing_credential' as const,latest_enrollment:{...enrollment,consumed_at:'2026-10-17T12:02:00Z'}})});render(<ProductionGatewayBootstrapView api={backend} authority={authority} onReauthenticate={()=>{}}/>);await create(user);expect(await screen.findByText(/existing credential/i)).toBeVisible();expect(screen.queryByRole('button',{name:'Issue enrollment'})).not.toBeInTheDocument();expect(document.body.textContent).not.toContain('healthy');expect(backend.issueGatewayEnrollment).not.toHaveBeenCalled();
 });
});
