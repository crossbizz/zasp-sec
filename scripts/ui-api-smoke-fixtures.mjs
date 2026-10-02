// Local migration48 fixture identity/readiness only, not Stytch/search acceptance.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
export const smokeScope=Object.freeze({organization_id:"pid_10000001-0000-4000-8000-000000000001",workspace_id:"pid_10000002-0000-4000-8000-000000000002",environment_id:"pid_10000003-0000-4000-8000-000000000003"});
export const smokePrincipal="pid_10000004-0000-4000-8000-000000000004";
const roles=Object.freeze({DISCOVERY_API:"api",DISCOVERY_WORKER:"discovery",RUNTIME_INGEST:"ingest",RUNTIME_WORKER:"runtime",OUTBOX_WORKER:"outbox",RUNTIME_GATEWAY:"gateway",DISCOVERY_SCHEDULER:"scheduler",PROJECTION_RISK:"projection_risk",PROJECTION_GRAPH:"projection_graph",PROJECTION_SEARCH:"projection_search",RUNTIME_COORDINATOR:"coordinator",RUNTIME_ARCHIVE:"archive",RUNTIME_INDEX:"index",RUNTIME_CORRELATION:"correlation",RUNTIME_PROJECTION:"runtime_projection",GATEWAY_CONTROL:"gateway_control",SECURITY_AGENT_API:"security_agent_api",SECURITY_AGENT_WORKER:"security_agent_worker",SECURITY_AGENT_ACTION:"security_agent_action",POLICY_DEPLOYMENT:"policy_deployment",RED_TEAM_WORKER:"red_team_worker",RED_TEAM_OUTBOX:"red_team_outbox",RED_TEAM_ADAPTER:"red_team_adapter",ATTACK_LAB_CONTROLLER:"attack_lab_controller",ATTACK_LAB_OUTBOX:"attack_lab_outbox",ATTACK_LAB_PROXY:"attack_lab_proxy",RECOVERY_WORKER:"recovery",RECOVERY_OUTBOX:"recovery_outbox"});
export function principalSQL(){return Object.values(roles).map(role=>`CREATE ROLE zasp_e2e_${role} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`).join("\n");}
export function migrationEnvironment(dsn){
  assert.match(dsn,/^postgres:\/\/zasp_e2e@127\.0\.0\.1:[0-9]+\/postgres\?sslmode=disable$/);
  return {ZASP_POSTGRES_DSN:dsn,ZASP_MIGRATION_TIMEOUT:"20s",ZASP_MIGRATION_DB_PRINCIPAL:"zasp_e2e",...Object.fromEntries(Object.entries(roles).map(([n,r])=>[`ZASP_${n}_DB_PRINCIPAL`,`zasp_e2e_${r}`]))};
}
export function fixtureSeedSQL(){
  const {organization_id:o,workspace_id:w,environment_id:e}=smokeScope,p=smokePrincipal;
  const bootstrap={principal:{id:p,organization_id:o,organization_reference:"organization-test-local",member_reference:"member-test-local",role:"security_admin",active:true},...smokeScope,permissions:["view"],capabilities:["inventory.read","scope.switch"],csrf_token:"c".repeat(32),correlation_id:"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"};
  return `BEGIN;
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES('${p}','${o}','${w}','${e}','Local fixture','["view"]'::jsonb,true);
INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES('${p}','${o}','organization-test-local','member-test-local','security_admin');
INSERT INTO zasp_organizations(id,name,domain) VALUES('${o}','Local fixture organization','smoke.invalid');
INSERT INTO zasp_workspaces(id,organization_id,name) VALUES('${w}','${o}','Local fixture workspace');
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES('${e}','${o}','${w}','Local fixture environment','test');
INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES('${o}','${w}','${e}','test','metadata_only',30,true,false);
INSERT INTO zasp_core_payloads(organization_id,workspace_id,environment_id,operation,payload) VALUES('${o}','${w}','${e}','session_bootstrap:${p}','${JSON.stringify(bootstrap)}'::jsonb);
SELECT zasp_inventory_backfill_scope('${o}','${w}','${e}');
SELECT zasp_inventory_cutover_scope('${o}','${w}','${e}');
COMMIT;`;
}
export function identityReply({method,url,headers,body},publicOrigin){
  if(method==="GET"&&url.pathname==="/v1/b2b/public/oauth/google/start"){
    assert.equal(url.searchParams.get("public_token"),"public-token-test-local");assert.equal(url.searchParams.get("organization_id"),"organization-test-local");
    const cb=new URL(url.searchParams.get("login_redirect_url"));assert.equal(cb.origin,publicOrigin);assert.equal(cb.pathname,"/auth/callback");assert.equal(url.searchParams.get("signup_redirect_url"),cb.toString());assert.ok((cb.searchParams.get("state")??"").length>=32);
    cb.searchParams.set("token","local-oauth-token");return {status:302,headers:{location:cb.toString()}};
  }
  assert.equal(method,"POST");assert.equal(headers.authorization,"Basic "+Buffer.from("project-test-local:secret-test-local").toString("base64"));
  const input=JSON.parse(body),base={status_code:200,request_id:"local-smoke-identity",member_id:"member-test-local",organization_id:"organization-test-local",session_jwt:"header.payload.signature"};
  if(url.pathname==="/v1/b2b/oauth/authenticate"){assert.deepEqual(input,{oauth_token:"local-oauth-token",session_duration_minutes:60});return {status:200,body:base};}
  assert.equal(url.pathname,"/v1/b2b/sessions/authenticate");assert.deepEqual(input,{session_jwt:"header.payload.signature"});
  const now=Date.now();return {status:200,body:{...base,member_session:{member_session_id:"member-session-test-local",member_id:base.member_id,organization_id:base.organization_id,started_at:new Date(now).toISOString(),last_accessed_at:new Date(now).toISOString(),expires_at:new Date(now+3600000).toISOString()},member:{member_id:base.member_id,organization_id:base.organization_id,scim_registration:{scim_attributes:{groups:[]}}}}};
}
export function historyReply({method,url,headers},mapping,digest){
  assert.equal(method,"GET");assert.equal(url.search,"");assert.ok(String(headers.authorization??"").startsWith("AWS4-HMAC-SHA256 "));
  if(url.pathname==="/zasp-runtime-events-v1/_mapping")return {status:200,body:{"zasp-runtime-events-v1":mapping}};
  assert.equal(url.pathname,"/zasp-runtime-events-v1/_doc/_zasp_schema_v1");return {status:200,body:{_index:"zasp-runtime-events-v1",_id:"_zasp_schema_v1",_version:1,_seq_no:0,_primary_term:1,found:true,_source:{record_type:"schema_marker",schema_version:1,mapping_digest:`sha256:${digest}`}}};
}
export function smokeProxyHeaders(headers,publicOrigin){
  const origin=new URL(publicOrigin);
  assert.equal(origin.protocol,"https:");assert.equal(origin.hostname,"zasp.local-smoke.test");
  assert.equal(origin.origin,publicOrigin);assert.equal(origin.username,"");assert.equal(origin.password,"");
  assert.equal(headers.host,origin.host);
  const forwarded={};
  for(const [name,value] of Object.entries(headers)){
    const lower=name.toLowerCase();
    if(lower==="forwarded"||lower.startsWith("x-forwarded-"))continue;
    if(lower==="host")assert.equal(name,"host");
    forwarded[name]=value;
  }
  return {...forwarded,host:origin.host,"x-forwarded-for":"127.0.0.1","x-forwarded-host":origin.host,"x-forwarded-port":origin.port||"443","x-forwarded-proto":"https"};
}

export function proxyRoute(method,pathname){
  if(pathname.startsWith("/api/")){assert.ok(method==="GET"&&["/api/v1/session/start","/api/v1/session/bootstrap","/api/v1/session/scopes","/api/v1/agents","/api/v1/workflow-mutation-receipts"].includes(pathname)||method==="POST"&&pathname==="/api/v1/session/callback","unexpected product route");return "api";}
  assert.ok(method==="GET"||method==="HEAD","unexpected web mutation");return "web";
}
export function smokeAPIEnvironment({postgresPort,identityPort,historyPort,apiPort,healthPort,publicOrigin}){
  for(const port of [postgresPort,identityPort,historyPort,apiPort,healthPort])assert.ok(Number.isInteger(port)&&port>1024&&port<=65535);
  assert.match(publicOrigin,/^https:\/\/zasp\.local-smoke\.test:[0-9]+$/);
  return {HOSTNAME:"agentsec-api-local-fixture",ZASP_ENVIRONMENT:"test",ZASP_DEPLOYMENT_MODE:"saas",ZASP_ORGANIZATION_ID:"",ZASP_PRODUCT_LISTEN_ADDRESS:`127.0.0.1:${apiPort}`,ZASP_INTERNAL_LISTEN_ADDRESS:`127.0.0.1:${healthPort}`,ZASP_PUBLIC_ORIGIN:publicOrigin,ZASP_TRUSTED_PROXY_CIDRS:"127.0.0.0/8",ZASP_REQUEST_RATE_PER_SECOND:"1000",ZASP_REQUEST_BURST:"2000",ZASP_COOKIE_SECURE:"true",ZASP_PROVIDER_TIMEOUT:"5s",ZASP_REQUEST_TIMEOUT:"10s",ZASP_SHUTDOWN_TIMEOUT:"5s",ZASP_READINESS_INTERVAL:"100ms",ZASP_READINESS_MAX_INTERVAL:"1s",ZASP_DISCOVERY_PARSER_VERSION:"inventory-parser-2026.08.20",ZASP_DISCOVERY_TOOL_VERSION:"collector-tool-2026.08.20",ZASP_POSTGRES_DSN:`postgres://zasp_e2e_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,ZASP_SECURITY_AGENT_POSTGRES_DSN:`postgres://zasp_e2e_security_agent_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
    ZASP_STYTCH_BASE_URL:`http://127.0.0.1:${identityPort}`,ZASP_STYTCH_AUTHORIZE_URL:`http://127.0.0.1:${identityPort}/v1/b2b/public/oauth/google/start`,ZASP_STYTCH_PROJECT_ID:"project-test-local",ZASP_STYTCH_SECRET:"secret-test-local",ZASP_STYTCH_WEBHOOK_SECRET:`whsec_${randomBytes(32).toString("base64")}`,ZASP_STYTCH_PUBLIC_TOKEN:"public-token-test-local",ZASP_STYTCH_ORGANIZATION_ID:"organization-test-local",ZASP_WORKFLOW_SIGNING_KEY:randomBytes(32).toString("hex"),ZASP_TOKEN_REVEAL_KEY:randomBytes(32).toString("base64url"),
    ZASP_CONNECTOR_AWS_REGION:"us-east-1",ZASP_CONNECTOR_ROLE_ARN:"arn:aws:iam::000000000000:role/zasp-production-e2e-api-connectors",ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE:"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",ZASP_CONNECTOR_KMS_KEY_ARN:"arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111",ZASP_CONNECTOR_SECRET_PREFIX:"zasp-production-e2e/connectors/oauth",ZASP_POLICY_HISTORY_ENDPOINT:`http://127.0.0.1:${historyPort}`,ZASP_POLICY_HISTORY_INDEX:"zasp-runtime-events-v1",ZASP_AWS_CUSTOMER_ROLE_PREFIXES:'["arn:aws:iam::123456789012:role/zasp-reference/"]',ZASP_AWS_CUSTOMER_ROLE_ARNS:'["arn:aws:iam::123456789012:role/zasp-reference/production-e2e"]',ZASP_KUBERNETES_EGRESS_CIDRS:"203.0.113.0/24",ZASP_FINDING_TICKET_EGRESS_CIDRS:"192.0.2.64/28",ZASP_GITHUB_CLIENT_ID:"Iv1.1234567890abcdef",ZASP_GITHUB_CLIENT_SECRET_REFERENCE:"ref:github/client-secret",ZASP_GITHUB_APP_ID:"123456",ZASP_GITHUB_PRIVATE_KEY_REFERENCE:"ref:github/app-private-key",ZASP_OKTA_CLIENT_ID:"0oa1234567890abcdef",ZASP_OKTA_CLIENT_SECRET_REFERENCE:"ref:okta/client-secret"};
}
