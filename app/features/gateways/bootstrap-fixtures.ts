export const gatewayID="pid_91000001-0000-4000-8000-000000000001";
export const enrollmentID="pid_91000002-0000-4000-8000-000000000002";
export const scope={organization_id:"pid_91000003-0000-4000-8000-000000000003",workspace_id:"pid_91000004-0000-4000-8000-000000000004",environment_id:"pid_91000005-0000-4000-8000-000000000005"};
export const device={id:gatewayID,name:"production-gateway",state:"pending" as const,version:1,replay_floor:0,created_at:"2026-10-17T12:00:00Z"};
export const enrollment={id:enrollmentID,device_id:gatewayID,token_generation:1,device_version:1,audience:"runtime-gateway-enroll" as const,issued_at:"2026-10-17T12:01:00Z",expires_at:"2026-10-17T13:01:00Z",consumed_at:null,revoked_at:null};
export const bundle={schema:"gateway-enrollment-token-v1" as const,...scope,device_id:gatewayID,enrollment_id:enrollmentID,token_generation:1,credential_generation:1,enrollment_expires_at:enrollment.expires_at,locator:"EREREREREREREREREREREQ",secret:"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"};
export const status={device,latest_enrollment:null,next_credential_generation:1,issuance_state:"available" as const};
export const issued={device,enrollment,replayed:false as const,token_bundle:bundle};
