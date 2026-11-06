package migrations

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed sql/sensor_node_coverage_profile.sql
var sensorNodeCoverageSQL string

const SensorNodeCoverageProfileName = "canonical61-temporal78-authorization79-80-sensor-node-coverage-v1"
const SensorNodeCoverageAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-sensor-node-coverage-v1"

func sensorNodeCoverageProfileSource(audit bool) (string, string) {
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
	source := strings.NewReplacer("-- node coverage selected parent predicate", selected, "-- node coverage parent79", ProductionAuthorizationProjection().Checksum(), "-- node coverage parent80", ProductionAuthorizationEnforcement().Checksum(), "-- node coverage worker", worker, "-- node coverage runtime", runtimePin, "-- node coverage audit mode", am, "-- node coverage identity mode", im).Replace(sensorNodeCoverageSQL)
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
	}{Own: []fact{}, Parents: []fact{}, Tables: json.RawMessage(`[{"name":"registration","columns":[{"name":"singleton","type":"boolean","default":true},{"name":"checksum","type":"text","default":false},{"name":"rawseal","type":"text","default":false}],"pk":"1","checks":[{"name":"registration_singleton_ck","expression":"singleton"},{"name":"registration_checksum_ck","expression":"checksum ~ '^[a-f0-9]{64}$'"},{"name":"registration_rawseal_ck","expression":"rawseal ~ '^[a-f0-9]{64}$'"}]},{"name":"accepted_observations","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"sensor_id","type":"text","default":false},{"name":"sequence","type":"bigint","default":false},{"name":"state_uid","type":"text","default":false},{"name":"storage_epoch","type":"bigint","default":false},{"name":"request_digest","type":"bytea","default":false},{"name":"source_observed_at","type":"text","default":false},{"name":"expires_at","type":"text","default":false},{"name":"source_epoch","type":"numeric","default":false},{"name":"expires_epoch","type":"numeric","default":false},{"name":"resolved_at","type":"timestamp with time zone","default":false},{"name":"sensor_version","type":"bigint","default":false},{"name":"token_id","type":"text","default":false},{"name":"token_generation","type":"bigint","default":false},{"name":"wire","type":"bytea","default":false},{"name":"observation","type":"jsonb","default":false},{"name":"recorded_tx","type":"xid8","default":false,"default_expression":"pg_current_xact_id()"}],"pk":"1,2,3,4","checks":[{"name":"accepted_observations_sequence_ck","expression":"sequence>0"},{"name":"accepted_observations_epoch_ck","expression":"storage_epoch>0"},{"name":"accepted_observations_digest_ck","expression":"octet_length(request_digest)=32"},{"name":"accepted_observations_expires_ck","expression":"expires_epoch>source_epoch"},{"name":"accepted_observations_version_ck","expression":"sensor_version>0"},{"name":"accepted_observations_generation_ck","expression":"token_generation>0"},{"name":"accepted_observations_wire_min_ck","expression":"octet_length(wire)>0"},{"name":"accepted_observations_wire_max_ck","expression":"octet_length(wire)<=16777216"},{"name":"accepted_observations_observation_ck","expression":"jsonb_typeof(observation)='object'"}]},{"name":"resolved_attempts","columns":[{"name":"organization_id","type":"text","default":false},{"name":"workspace_id","type":"text","default":false},{"name":"environment_id","type":"text","default":false},{"name":"sensor_id","type":"text","default":false},{"name":"sequence","type":"bigint","default":false},{"name":"state_uid","type":"text","default":false},{"name":"storage_epoch","type":"bigint","default":false},{"name":"request_digest","type":"bytea","default":false},{"name":"source_observed_at","type":"text","default":false},{"name":"expires_at","type":"text","default":false},{"name":"source_epoch","type":"numeric","default":false},{"name":"expires_epoch","type":"numeric","default":false},{"name":"resolved_at","type":"timestamp with time zone","default":false},{"name":"sensor_version","type":"bigint","default":false},{"name":"token_id","type":"text","default":false},{"name":"token_generation","type":"bigint","default":false},{"name":"disposition","type":"text","default":false}],"pk":"1,2,3,4","checks":[{"name":"resolved_attempts_sequence_ck","expression":"sequence>0"},{"name":"resolved_attempts_epoch_ck","expression":"storage_epoch>0"},{"name":"resolved_attempts_digest_ck","expression":"octet_length(request_digest)=32"},{"name":"resolved_attempts_expires_ck","expression":"expires_epoch>source_epoch"},{"name":"resolved_attempts_version_ck","expression":"sensor_version>0"},{"name":"resolved_attempts_generation_ck","expression":"token_generation>0"},{"name":"resolved_attempts_disposition_ck","expression":"disposition IN ('accepted','expired_not_committed')"}]}]`)}
	for _, v := range []struct{ name, args, names, language, volatility, returns, roles string }{
		{"fingerprint", "", "", "sql", "s", "text", ""},
		{"raw_seal_ready", "", "", "plpgsql", "s", "boolean", ""},
		{"effective_ready", "", "", "plpgsql", "s", "boolean", ""},
		{"caller_ready", "text,text", "purpose,pin", "sql", "s", "boolean", "zasp_discovery_api,zasp_runtime_ingest"},
		{"require_live_token", "bytea,bytea,text", "locator,secret,audience", "plpgsql", "v", "jsonb", ""},
		{"validate_wire", "bytea", "wire", "plpgsql", "v", "jsonb", ""},
		{"record_heartbeat", "bytea,bytea,text,bytea", "locator,secret,audience,wire", "plpgsql", "v", "jsonb", "zasp_runtime_ingest"},
		{"confirm_receipt", "bytea,bytea,text,bigint,bytea", "locator,secret,audience,attempt_sequence,request_digest", "plpgsql", "v", "jsonb", "zasp_runtime_ingest"},
		{"sensor_coverage", "text,text,text,text", "o,w,e,sensor_id", "plpgsql", "v", "jsonb", "zasp_discovery_api"},
		{"immutable_registration", "", "", "plpgsql", "v", "trigger", ""},
	} {
		names, roles := []string{}, []string{}
		if v.names != "" {
			names = strings.Split(v.names, ",")
		}
		if v.roles != "" {
			roles = strings.Split(v.roles, ",")
		}
		manifest.Own = append(manifest.Own, fact{Signature: "zasp_sensor_coverage_v1." + v.name + "(" + v.args + ")", Source: ownerSourceHash(agentReadFunctionBody(source, "zasp_sensor_coverage_v1."+v.name)), ArgNames: names, Language: v.language, Volatility: v.volatility, Returns: v.returns, Roles: roles, Secdef: true})
	}
	for _, v := range []struct {
		source, name, args, roles string
		secdef                    bool
	}{
		{runtime, "zasp_authorization80_runtime.catalog_ready", "", "", true},
		{runtime, "zasp_authorization80_runtime.current_ready", "", "", true},
		{parent80, "zasp_authorization80.context", "", "", true},
		{parent80, "zasp_authorization80.identity_fence", "jsonb", "", true},
		{parent80, "zasp_authorization80.require_read", "text,text,text,text[],text,boolean,text", "", true},
		{parent80, "zasp_authorization80.sensor_source_ready", "", "", true},
		{parent80, "zasp_authorization80.sensor_authorized", "text,text,text,text,text,text", "", true},
		{parent80, "zasp_authorization80.unique_json", "json,integer", "", false},
		{ProductionAuthorizationProjection().UpSQL(), "zasp_authorization79.revalidate", "text,bigint,bigint,text,text", "zasp_outbox_worker,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker", true},
	} {
		roles := []string{}
		if v.roles != "" {
			roles = strings.Split(v.roles, ",")
		}
		manifest.Parents = append(manifest.Parents, fact{Signature: v.name + "(" + v.args + ")", Source: ownerSourceHash(agentReadFunctionBody(v.source, v.name)), Roles: roles, Secdef: v.secdef})
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic("sensor node coverage manifest encoding")
	}
	source = strings.ReplaceAll(source, "-- node coverage manifest", string(raw))
	pin := ownerSourceHash(source)
	return strings.ReplaceAll(source, "-- node coverage checksum", pin), pin
}

// Only immutable compiler output is cached. No live authorization, sensor,
// credential, token, receipt or readiness fact is retained by this cache.
type sensorNodeCoverageCompiled struct{ normal, normalPin, audit, auditPin string }

var compiledSensorNodeCoverage = sync.OnceValue(func() sensorNodeCoverageCompiled {
	n, np := sensorNodeCoverageProfileSource(false)
	a, ap := sensorNodeCoverageProfileSource(true)
	return sensorNodeCoverageCompiled{n, np, a, ap}
})

func SensorNodeCoverageProfileChecksum() string      { return compiledSensorNodeCoverage().normalPin }
func SensorNodeCoverageAuditProfileChecksum() string { return compiledSensorNodeCoverage().auditPin }
func IsSensorNodeCoverageProfileChecksum(p string) bool {
	return len(p) == 64 && (p == SensorNodeCoverageProfileChecksum() || p == SensorNodeCoverageAuditProfileChecksum())
}
func compiledSensorNodeCoverageSource(audit bool) (string, string) {
	p := compiledSensorNodeCoverage()
	if audit {
		return p.audit, p.auditPin
	}
	return p.normal, p.normalPin
}
func (r *Runner) UpProductionSensorNodeCoverageProfile(c context.Context) error {
	return r.upProductionSensorNodeCoverageProfile(c, false)
}
func (r *Runner) UpProductionSensorNodeCoverageAuditProfile(c context.Context) error {
	return r.upProductionSensorNodeCoverageProfile(c, true)
}
func (r *Runner) upProductionSensorNodeCoverageProfile(c context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || c == nil || c.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := compiledSensorNodeCoverageSource(audit)
	const boundary = "-- node coverage authority definitions"
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
		if e := check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_authorization80_temporal.ready() AND zasp_authorization80.sensor_source_ready()`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum()); e != nil {
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
		if e := scanRow(c, tx, `SELECT to_regnamespace('zasp_sensor_coverage_v1') IS NOT NULL`, nil, &present); e != nil {
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
			if e := check(`SELECT NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_sensor_coverage_v1'::regnamespace AND(p.proowner<>'zasp_discovery_authority'::regrole OR a.grantor<>p.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee<>p.proowner AND NOT((p.proname IN('record_heartbeat','confirm_receipt','caller_ready') AND a.grantee='zasp_runtime_ingest'::regrole) OR(p.proname IN('sensor_coverage','caller_ready') AND a.grantee='zasp_discovery_api'::regrole)))) AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.relnamespace='zasp_sensor_coverage_v1'::regnamespace AND(t.relowner<>'zasp_discovery_authority'::regrole OR a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid WHERE t.relnamespace='zasp_sensor_coverage_v1'::regnamespace AND a.attacl IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_sensor_coverage_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT(a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE') OR a.grantee IN('zasp_discovery_api'::regrole,'zasp_runtime_ingest'::regrole) AND a.privilege_type='USAGE'))))`); e != nil {
				return e
			}
			if e := tx.Exec(c, `INSERT INTO zasp_sensor_coverage_v1.registration(singleton,checksum,rawseal) VALUES(true,$1,zasp_sensor_coverage_v1.fingerprint())`, pin); e != nil {
				return fixedDatabaseError(c, e)
			}
		}
		if e := check(`SELECT zasp_sensor_coverage_v1.raw_seal_ready() AND zasp_sensor_coverage_v1.effective_ready()`); e != nil {
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
