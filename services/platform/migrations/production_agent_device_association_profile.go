package migrations

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed sql/agent_device_association_profile.sql
var agentDeviceAssociationSQL string

const AgentDeviceAssociationProfileName = "canonical61-temporal78-authorization79-80-agent-device-association-v1"
const AgentDeviceAssociationAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-agent-device-association-v1"

func agentDeviceAssociationProfileSource(audit bool) (string, string) {
	am, im := "none", "none"
	_, worker := authorizationWorkerProfileSource()
	selected := "AND to_regnamespace('zasp_authorization80_audit') IS NULL AND to_regnamespace('zasp_authorization80_identity') IS NULL"
	if audit {
		am, im = AuthorizationAuditProfileName, AuthorizationIdentityProfileName
		_, worker = authorizationWorkerAuditProfileSource()
		selected = "AND EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE singleton AND checksum='" + AuthorizationAuditProfileChecksum() + "') AND zasp_authorization80_audit.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE singleton AND checksum='" + AuthorizationIdentityProfileChecksum() + "') AND zasp_authorization80_identity.structural_ready('" + AuthorizationIdentityProfileChecksum() + "')"
	}
	runtime, runtimePin := authorizationRuntimeProfileSource()
	parent80 := ProductionAuthorizationEnforcement().UpSQL()
	source := strings.NewReplacer("-- agent device association selected parent predicate", selected, "-- agent device association parent79", ProductionAuthorizationProjection().Checksum(), "-- agent device association parent80", ProductionAuthorizationEnforcement().Checksum(), "-- agent device association worker", worker, "-- agent device association runtime", runtimePin, "-- agent device association audit mode", am, "-- agent device association identity mode", im, "-- association typed14 fingerprint", ProductionTypedInventoryCutoverSemanticFingerprint(), "-- association typed14", ProductionTypedInventoryCutover().Checksum()).Replace(agentDeviceAssociationSQL)
	type fact struct {
		Signature  string   `json:"signature"`
		Source     string   `json:"source"`
		ArgNames   []string `json:"argnames"`
		Language   string   `json:"language,omitempty"`
		Volatility string   `json:"volatility,omitempty"`
		Returns    string   `json:"returns,omitempty"`
		Roles      []string `json:"roles"`
		Secdef     bool     `json:"secdef"`
	}
	manifest := struct {
		Own     []fact          `json:"own"`
		Parents []fact          `json:"parents"`
		Tables  json.RawMessage `json:"tables"`
	}{Own: []fact{}, Parents: []fact{}, Tables: json.RawMessage(`[{"name":"registration","columns":[{"name":"singleton","type":"boolean","default":true},{"name":"checksum","type":"text","default":false},{"name":"rawseal","type":"text","default":false}],"pk":"1","checks":[{"name":"registration_singleton_ck","expression":"singleton"},{"name":"registration_checksum_ck","expression":"checksum ~ '^[a-f0-9]{64}$'"},{"name":"registration_rawseal_ck","expression":"rawseal ~ '^[a-f0-9]{64}$'"}],"uniques":[],"foreign":[],"indexes":[{"name":"registration_pkey","key":"1","unique":true,"primary":true,"predicate":null}]},{"name":"pairs","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"agent_id","type":"text","default":false},{"name":"device_id","type":"text","default":false},{"name":"association_id","type":"text","default":false},{"name":"version","type":"bigint","default":false},{"name":"state","type":"text","default":false},{"name":"active","type":"jsonb","default":false,"nullable":true},{"name":"created_by","type":"text","default":false},{"name":"created_at","type":"timestamp with time zone","default":false},{"name":"activated_by","type":"text","default":false,"nullable":true},{"name":"activated_at","type":"timestamp with time zone","default":false,"nullable":true},{"name":"revoked_at","type":"timestamp with time zone","default":false,"nullable":true}],"pk":"1,2,3,4,5","checks":[{"name":"pairs_version_ck","expression":"version>=0"},{"name":"pairs_state_ck","expression":"state ~ '^(none|admitted|revoked)$'"},{"name":"pairs_active_ck","expression":"jsonb_typeof(active)='object'"}],"uniques":[{"name":"pairs_association_key","key":"1,2,3,6"}],"foreign":[],"indexes":[{"name":"pairs_pkey","key":"1,2,3,4,5","unique":true,"primary":true,"predicate":null},{"name":"pairs_association_key","key":"1,2,3,6","unique":true,"primary":false,"predicate":null},{"name":"pairs_page","key":"1,2,3,4,6","unique":false,"primary":false,"predicate":null}]},{"name":"challenges","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"challenge_id","type":"text","default":false},{"name":"association_id","type":"text","default":false},{"name":"actor","type":"text","default":false},{"name":"expected_version","type":"bigint","default":false},{"name":"source_identity","type":"jsonb","default":false},{"name":"source_digest","type":"bytea","default":false},{"name":"snapshot","type":"jsonb","default":false},{"name":"wire","type":"bytea","default":false},{"name":"nonce_digest","type":"bytea","default":false},{"name":"expires_at","type":"timestamp with time zone","default":false},{"name":"created_at","type":"timestamp with time zone","default":false},{"name":"state","type":"text","default":false}],"pk":"1,2,3,4","checks":[{"name":"challenges_version_ck","expression":"expected_version>=0"},{"name":"challenges_source_ck","expression":"jsonb_typeof(source_identity)='object'"},{"name":"challenges_snapshot_ck","expression":"jsonb_typeof(snapshot)='object'"},{"name":"challenges_digest_ck","expression":"octet_length(source_digest)=32"},{"name":"challenges_nonce_ck","expression":"octet_length(nonce_digest)=32"},{"name":"challenges_wire_min_ck","expression":"octet_length(wire)>0"},{"name":"challenges_wire_max_ck","expression":"octet_length(wire)<=4096"},{"name":"challenges_time_ck","expression":"expires_at>created_at"},{"name":"challenges_state_ck","expression":"state ~ '^(pending_device|pending_human|expired|superseded|activated|revoked)$'"}],"uniques":[],"foreign":[{"name":"challenges_pair_fk","key":"1,2,3,5","ref":"pairs","refkey":"1,2,3,6"}],"indexes":[{"name":"challenges_pkey","key":"1,2,3,4","unique":true,"primary":true,"predicate":null},{"name":"challenges_one_pending","key":"1,2,3,5","unique":true,"primary":false,"predicate":"(state ~ '^pending_(device|human)$'::text)"},{"name":"challenges_pair","key":"1,2,3,5,14,4","unique":false,"primary":false,"predicate":null}]},{"name":"acceptances","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"challenge_id","type":"text","default":false},{"name":"credential_id","type":"text","default":false},{"name":"credential_generation","type":"bigint","default":false},{"name":"request_digest","type":"bytea","default":false},{"name":"response","type":"jsonb","default":false},{"name":"accepted_at","type":"timestamp with time zone","default":false},{"name":"expires_at","type":"timestamp with time zone","default":false},{"name":"accepted_tx","type":"xid8","default":false,"default_expression":"pg_current_xact_id()"}],"pk":"1,2,3,4","checks":[{"name":"acceptances_generation_ck","expression":"credential_generation>0"},{"name":"acceptances_digest_ck","expression":"octet_length(request_digest)=32"},{"name":"acceptances_response_ck","expression":"jsonb_typeof(response)='object'"},{"name":"acceptances_time_ck","expression":"expires_at>accepted_at"}],"uniques":[],"foreign":[{"name":"acceptances_challenge_fk","key":"1,2,3,4","ref":"challenges","refkey":"1,2,3,4"}],"indexes":[{"name":"acceptances_pkey","key":"1,2,3,4","unique":true,"primary":true,"predicate":null}]},{"name":"human_receipts","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"actor","type":"text","default":false},{"name":"operation","type":"text","default":false},{"name":"idempotency_key","type":"text","default":false},{"name":"request_digest","type":"bytea","default":false},{"name":"association_id","type":"text","default":false},{"name":"challenge_id","type":"text","default":false,"nullable":true},{"name":"result","type":"jsonb","default":false},{"name":"material","type":"jsonb","default":false},{"name":"recorded_at","type":"timestamp with time zone","default":false},{"name":"created_tx","type":"xid8","default":false,"default_expression":"pg_current_xact_id()"}],"pk":"1,2,3,4,5,6","checks":[{"name":"human_receipts_digest_ck","expression":"octet_length(request_digest)=32"},{"name":"human_receipts_result_ck","expression":"jsonb_typeof(result)='object'"},{"name":"human_receipts_material_ck","expression":"jsonb_typeof(material)='object'"},{"name":"human_receipts_operation_ck","expression":"operation ~ '^(createAgentDeviceIntent|activateAgentDeviceAssociation|revokeAgentDeviceAssociation)$'"}],"uniques":[],"foreign":[],"indexes":[{"name":"human_receipts_pkey","key":"1,2,3,4,5,6","unique":true,"primary":true,"predicate":null}]}]`)}
	for _, v := range []struct{ name, args, names, language, volatility, returns, roles string }{
		{"stamp", "timestamp with time zone", "t", "sql", "i", "text", ""},
		{"fingerprint", "", "", "sql", "s", "text", ""},
		{"immutable_registration", "", "", "plpgsql", "v", "trigger", ""},
		{"raw_seal_ready", "", "", "plpgsql", "s", "boolean", ""},
		{"effective_ready", "", "", "plpgsql", "s", "boolean", ""},
		{"caller_ready", "text,text", "purpose,pin", "sql", "s", "boolean", "zasp_discovery_api,zasp_gateway_control"},
		{"require_human", "text,text,text,text,text,text,text", "o,w,e,actor,agent_id,operation,pin", "plpgsql", "v", "jsonb", ""},
		{"source_facts", "text,text,text,text", "o,w,e,agent_id", "plpgsql", "v", "jsonb", ""},
		{"device_facts", "text,text,text,text,text,bigint", "o,w,e,device_id,credential_id,credential_generation", "plpgsql", "v", "jsonb", ""},
		{"source_digest", "jsonb", "facts", "sql", "i", "text", ""},
		{"build_challenge", "text,text,text,text,text,text,text,text,bigint,bytea,timestamp with time zone", "o,w,e,agent_id,device_id,association_id,challenge_id,source_digest,expected_version,nonce,expires_at", "sql", "i", "bytea", ""},
		{"pair_id", "text,text,text,text,text", "o,w,e,agent_id,device_id", "sql", "i", "text", ""},
		{"pair_value", "text,text,text,text", "o,w,e,association_id", "plpgsql", "v", "jsonb", ""},
		{"create_intent", "text,text,text,text,text,text,text,bytea,bigint,text,bytea,integer,text", "o,w,e,actor,agent_id,device_id,idempotency_key,request_digest,expected_version,challenge_id,nonce,ttl_seconds,pin", "plpgsql", "v", "jsonb", "zasp_discovery_api"},
		{"activate", "text,text,text,text,text,text,text,bytea,bigint,text,bytea,text", "o,w,e,actor,agent_id,association_id,challenge_id,challenge_sha256,expected_version,idempotency_key,request_digest,pin", "plpgsql", "v", "jsonb", "zasp_discovery_api"},
		{"revoke", "text,text,text,text,text,text,bigint,text,bytea,text", "o,w,e,actor,agent_id,association_id,expected_version,idempotency_key,request_digest,pin", "plpgsql", "v", "jsonb", "zasp_discovery_api"},
		{"page", "text,text,text,text,text,integer,text", "o,w,e,agent_id,after_association_id,page_limit,pin", "plpgsql", "v", "jsonb", "zasp_discovery_api"},
		{"confirm_human", "text,text,text,text,text,text,text,bytea,jsonb,text", "o,w,e,actor,agent_id,operation,idempotency_key,request_digest,expected_receipt,pin", "plpgsql", "v", "boolean", "zasp_discovery_api"},
		{"accept_intent", "text,bytea,text", "credential_id,body,pin", "plpgsql", "v", "jsonb", "zasp_gateway_control"},
		{"confirm_device", "text,bytea,jsonb,text", "credential_id,body,expected_receipt,pin", "plpgsql", "v", "boolean", "zasp_gateway_control"},
		{"store_human_receipt", "text,text,text,text,text,text,text,bytea,text,text,jsonb,jsonb", "o,w,e,actor,agent_id,operation,idempotency_key,request_digest,association_id,challenge_id,result,material", "plpgsql", "v", "jsonb", ""},
		{"human_replay", "text,text,text,text,text,text,bytea", "o,w,e,actor,operation,idempotency_key,request_digest", "plpgsql", "v", "jsonb", ""},
		{"parse_accept", "bytea", "body", "plpgsql", "v", "jsonb", ""},
	} {
		names, roles := []string{}, []string{}
		if v.names != "" {
			names = strings.Split(v.names, ",")
		}
		if v.roles != "" {
			roles = strings.Split(v.roles, ",")
		}
		manifest.Own = append(manifest.Own, fact{Signature: "zasp_agent_device_association_v1." + v.name + "(" + v.args + ")", Source: ownerSourceHash(agentReadFunctionBody(source, "zasp_agent_device_association_v1."+v.name)), ArgNames: names, Language: v.language, Volatility: v.volatility, Returns: v.returns, Roles: roles, Secdef: true})
	}
	workerSource, _ := authorizationWorkerProfileSource()
	if audit {
		workerSource, _ = authorizationWorkerAuditProfileSource()
	}
	for _, v := range []struct {
		source, name, args, roles string
		secdef                    bool
	}{
		{runtime, "zasp_authorization80_runtime.catalog_ready", "", "", true},
		{runtime, "zasp_authorization80_runtime.current_ready", "", "", true},
		{parent80, "zasp_authorization80.context", "", "", true},
		{workerSource, "zasp_authorization80_worker.gateway_api_organization_lock", "text", "", true},
		{parent80, "zasp_authorization80.require_read", "text,text,text,text[],text,boolean,text", "", true},
		{parent80, "zasp_authorization80.identity_fence", "jsonb", "", true},
		{parent80, "zasp_authorization80.allowed", "text,text,text,text,text", "", true},
		{ProductionRuntimeDataPlane().UpSQL(), "public.zasp_runtime_gateway_credential_authority", "text,text", "zasp_gateway_control", true},
		{parent80, "zasp_authorization80.unique_json", "json,integer", "", false},
	} {
		roles := []string{}
		if v.roles != "" {
			roles = strings.Split(v.roles, ",")
		}
		manifest.Parents = append(manifest.Parents, fact{Signature: v.name + "(" + v.args + ")", Source: ownerSourceHash(agentReadFunctionBody(v.source, v.name)), Roles: roles, Secdef: v.secdef})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic("agent device association manifest encoding")
	}
	source = strings.ReplaceAll(source, "-- agent device association manifest", string(raw))
	pin := ownerSourceHash(source)
	return strings.ReplaceAll(source, "-- agent device association checksum", pin), pin
}

// Only immutable compiler output is cached. No live authorization, device,
// credential, installation, receipt or readiness fact is retained by this cache.
type agentDeviceAssociationCompiled struct{ normal, normalPin, audit, auditPin string }

var compiledAgentDeviceAssociation = sync.OnceValue(func() agentDeviceAssociationCompiled {
	n, np := agentDeviceAssociationProfileSource(false)
	a, ap := agentDeviceAssociationProfileSource(true)
	return agentDeviceAssociationCompiled{n, np, a, ap}
})

func AgentDeviceAssociationProfileChecksum() string {
	return compiledAgentDeviceAssociation().normalPin
}
func AgentDeviceAssociationAuditProfileChecksum() string {
	return compiledAgentDeviceAssociation().auditPin
}
func IsAgentDeviceAssociationProfileChecksum(p string) bool {
	return len(p) == 64 && (p == AgentDeviceAssociationProfileChecksum() || p == AgentDeviceAssociationAuditProfileChecksum())
}
func compiledAgentDeviceAssociationSource(audit bool) (string, string) {
	p := compiledAgentDeviceAssociation()
	if audit {
		return p.audit, p.auditPin
	}
	return p.normal, p.normalPin
}
func (r *Runner) UpProductionAgentDeviceAssociationProfile(c context.Context) error {
	return r.upProductionAgentDeviceAssociationProfile(c, false)
}
func (r *Runner) UpProductionAgentDeviceAssociationAuditProfile(c context.Context) error {
	return r.upProductionAgentDeviceAssociationProfile(c, true)
}
func (r *Runner) upProductionAgentDeviceAssociationProfile(c context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || c == nil || c.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := compiledAgentDeviceAssociationSource(audit)
	const boundary = "-- agent device association authority definitions"
	if strings.Count(source, boundary) != 1 {
		return ErrInvalidState
	}
	parts := strings.SplitN(source, boundary, 2)
	return r.withTransaction(c, func(c context.Context, tx Transaction) error {
		if e := tx.Exec(c, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); e != nil {
			return fixedDatabaseError(c, e)
		}
		if e := requireMaintenanceAuthorizationReady(c, tx); e != nil {
			return e
		}
		var user, role string
		if e := scanRow(c, tx, `SELECT current_user::text,current_setting('role')`, nil, &user, &role); e != nil {
			return fixedDatabaseError(c, e)
		}
		if e := tx.Exec(c, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
			return fixedDatabaseError(c, e)
		}
		check := func(q string, a ...any) error {
			var ok bool
			if e := scanRow(c, tx, q, a, &ok); e != nil {
				return fixedDatabaseError(c, e)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if e := check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_authorization80_temporal.ready()`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum()); e != nil {
			return e
		}
		_, worker := authorizationWorkerProfileSource()
		am, im := "none", "none"
		if audit {
			_, worker = authorizationWorkerAuditProfileSource()
			am, im = AuthorizationAuditProfileName, AuthorizationIdentityProfileName
		}
		if e := check(`SELECT zasp_authorization80_runtime.catalog_ready() AND zasp_authorization80_runtime.current_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_runtime.registration WHERE singleton AND checksum=$1) AND zasp_authorization80_worker.catalog_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE singleton AND checksum=$2)`, AuthorizationRuntimeProfileChecksum(), worker); e != nil {
			return e
		}
		if e := check(`SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode=$1 AND identity_mode=$2) FROM zasp_authorization80.runtime_profile`, am, im); e != nil {
			return e
		}
		var present bool
		if e := scanRow(c, tx, `SELECT to_regnamespace('zasp_agent_device_association_v1') IS NOT NULL`, nil, &present); e != nil {
			return fixedDatabaseError(c, e)
		}
		if !present {
			if e := tx.Exec(c, `SET LOCAL ROLE NONE`); e != nil {
				return fixedDatabaseError(c, e)
			}
			if e := check(`SELECT current_user=session_user AND has_database_privilege(session_user,current_database(),'CREATE') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`); e != nil {
				return e
			}
			if e := tx.Exec(c, parts[0]); e != nil {
				return fixedDatabaseError(c, e)
			}
			if e := tx.Exec(c, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
				return fixedDatabaseError(c, e)
			}
			if e := tx.Exec(c, parts[1]); e != nil {
				return fixedDatabaseError(c, e)
			}
			// Never bless unexpected default privileges by capturing them in rawseal.
			if e := check(`SELECT NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_agent_device_association_v1'::regnamespace AND(p.proowner<>'zasp_discovery_authority'::regrole OR a.grantor<>p.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>p.proowner AND NOT(((p.proname IN('create_intent','activate','revoke','page','confirm_human','caller_ready') AND a.grantee='zasp_discovery_api'::regrole) OR(p.proname IN('caller_ready','accept_intent','confirm_device') AND a.grantee='zasp_gateway_control'::regrole))))) AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.relnamespace='zasp_agent_device_association_v1'::regnamespace AND(t.relowner<>'zasp_discovery_authority'::regrole OR a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid WHERE t.relnamespace='zasp_agent_device_association_v1'::regnamespace AND a.attacl IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_device_association_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee IN('zasp_discovery_api'::regrole,'zasp_gateway_control'::regrole) AND a.privilege_type='USAGE'))))`); e != nil {
				return e
			}

			if e := tx.Exec(c, `INSERT INTO zasp_agent_device_association_v1.registration(singleton,checksum,rawseal) VALUES(true,$1,zasp_agent_device_association_v1.fingerprint())`, pin); e != nil {
				return fixedDatabaseError(c, e)
			}
		}
		if e := check(`SELECT zasp_agent_device_association_v1.raw_seal_ready() AND zasp_agent_device_association_v1.effective_ready()`); e != nil {
			return e
		}
		var restored string
		if e := scanRow(c, tx, `SELECT set_config('role',$1,true)`, []any{role}, &restored); e != nil {
			return fixedDatabaseError(c, e)
		}
		var finalUser, finalRole string
		if e := scanRow(c, tx, `SELECT current_user::text,current_setting('role')`, nil, &finalUser, &finalRole); e != nil {
			return fixedDatabaseError(c, e)
		}
		if restored != role || finalUser != user || finalRole != role {
			return ErrInvalidState
		}
		return nil
	})
}
