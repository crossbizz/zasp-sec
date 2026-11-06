import type {APIClient} from '../../../apps/web/api/client';
import {APITransportError,requireAPIData} from '../../../apps/web/api/client';
import type {GatewayDeviceInput,GatewayEnrollmentIssueInput,GatewayEnrollmentRevokeInput} from '../../../apps/web/api/generated';
import {decodeGatewayCreate,decodeGatewayStatus,decodeGatewayIssue,decodeGatewayRevoke,type GatewayScope} from '../../../apps/web/api/gateway-bootstrap-decoders';
export type GatewayAttempt=Readonly<{idempotencyKey:string}>;
export function createGatewayAttempt():GatewayAttempt{return Object.freeze({idempotencyKey:`gateway_${globalThis.crypto.randomUUID()}`});}
function requireProtected(response:Response){if(response.headers.get('Cache-Control')!=='no-store'||response.headers.get('Pragma')!=='no-cache')throw new APITransportError('invalid_response','Gateway response was cacheable');}
export function createGatewayBootstrapAPI(client:APIClient,scope:GatewayScope){
 const mutationHeaders=(attempt:GatewayAttempt)=>({'Idempotency-Key':attempt.idempotencyKey,'X-Zasp-Fresh-Auth':'confirmed' as const});
 return {
  async createGatewayDevice(value:GatewayDeviceInput,attempt:GatewayAttempt=createGatewayAttempt()) {const result=await client.POST('/api/v1/gateways',{params:{header:mutationHeaders(attempt)},body:value,cache:'no-store'});const decoded=requireAPIData(result,v=>decodeGatewayCreate(v,result.response.status));requireProtected(result.response);return decoded;},
  async getGatewayDevice(id:string,signal?:AbortSignal) {const result=await client.GET('/api/v1/gateways/{id}',{params:{path:{id}},signal,cache:'no-store'});const decoded=requireAPIData(result,v=>decodeGatewayStatus(v,id));requireProtected(result.response);return decoded;},
  async issueGatewayEnrollment(id:string,value:GatewayEnrollmentIssueInput,attempt:GatewayAttempt=createGatewayAttempt()){const result=await client.POST('/api/v1/gateways/{id}/enrollments',{params:{path:{id},header:mutationHeaders(attempt)},body:value,cache:'no-store'});const decoded=requireAPIData(result,v=>decodeGatewayIssue(v,result.response.status,id,scope));requireProtected(result.response);return decoded;},
  async revokeGatewayEnrollment(id:string,enrollmentId:string,value:GatewayEnrollmentRevokeInput,attempt:GatewayAttempt=createGatewayAttempt()){const result=await client.POST('/api/v1/gateways/{id}/enrollments/{enrollmentId}/revoke',{params:{path:{id,enrollmentId},header:mutationHeaders(attempt)},body:value,cache:'no-store'});const decoded=requireAPIData(result,v=>decodeGatewayRevoke(v,result.response.status,id,enrollmentId));requireProtected(result.response);return decoded;},
 };
}
export type GatewayBootstrapAPI=ReturnType<typeof createGatewayBootstrapAPI>;
