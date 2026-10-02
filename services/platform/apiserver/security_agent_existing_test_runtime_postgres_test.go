package apiserver

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Real scoped gateway rows and immutable event identity. Rotation revokes the
// predecessor, as required by the unique live-current-format credential index.
func seedExistingTestRuntimeTrigger(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, run, session, mode string) {
	t.Helper()
	device := strings.Replace(run, "pid_890001", "pid_891001", 1)
	enrollment := strings.Replace(run, "pid_890001", "pid_892001", 1)
	credential := strings.Replace(run, "pid_890001", "pid_893001", 1)
	event := strings.Replace(run, "pid_890001", "pid_894001", 1)
	if _, err := owner.Exec(ctx, `
 INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Existing test runtime gateway','active');
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$5,$4,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),digest(convert_to($5,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,issued_at,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$6,$4,$5,digest(convert_to($6,'UTF8'),'sha256'),'runtime-gateway','ref:gateway/public/existing-test-runtime',decode(repeat('04',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',1,1,'existing-test-runtime','Ed25519',clock_timestamp()-interval '1 hour');
 INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,$4,$6,$7,1,decode(repeat('fa',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$8),clock_timestamp());
 UPDATE zasp_security_agent_definitions SET body=body||'{"trigger_kind":"runtime_decision","trigger_source":"gateway"}'::jsonb WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 UPDATE zasp_security_agent_definition_versions v SET definition=d.body,definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d WHERE (v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) AND (v.organization_id,v.workspace_id,v.environment_id)=($1,$2,$3);
 UPDATE zasp_security_agent_trigger_receipts SET trigger_kind='runtime_decision',trigger_digest=digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',$8,'device_id',$4,'event_id',$7,'sequence',1,'request_digest','sha256:'||repeat('fa',32))::text,'UTF8'),'sha256') WHERE run_id=$9;
 UPDATE zasp_security_agent_plans SET trigger_digest=(SELECT trigger_digest FROM zasp_security_agent_trigger_receipts WHERE run_id=$9) WHERE run_id=$9;
 `, pgx.QueryExecModeSimpleProtocol, org, ws, env, device, enrollment, credential, event, session, run); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "runtime_revoked":
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE id=$1`, credential); err != nil {
			t.Fatal(err)
		}
	case "runtime_expired":
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, credential); err != nil {
			t.Fatal(err)
		}
	case "runtime_rotated":
		rotated := strings.Replace(credential, "pid_893001", "pid_895001", 1)
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE id=$1`, credential); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,issued_at,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) SELECT organization_id,workspace_id,environment_id,$2,device_id,enrollment_token_id,digest(convert_to($2,'UTF8'),'sha256'),audience,key_reference,public_key,clock_timestamp(),clock_timestamp()+interval '1 hour',format_version,2,key_id,algorithm,clock_timestamp() FROM zasp_gateway_credentials WHERE id=$1`, credential, rotated); err != nil {
			t.Fatal(err)
		}
	case "runtime_digest_changed":
		if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_gateway_events SET request_digest=decode(repeat('fb',32),'hex') WHERE event_id=$1`, event); err != nil {
			t.Fatal(err)
		}
	}
}
