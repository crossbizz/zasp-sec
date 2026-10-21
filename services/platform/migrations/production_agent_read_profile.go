package migrations

import (
	"context"
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

//go:embed sql/agent_read_profile.sql
var agentReadSQL string

const AgentReadProfileName = "canonical61-temporal78-authorization79-80-agent-read-v1"
const AgentReadAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-agent-read-v1"

// Extract only a fixed, trusted compiled CREATE FUNCTION body, retaining exact bytes.
func agentReadFunctionBody(source, identity string) string {
	start := strings.Index(source, "CREATE FUNCTION "+identity+"(")
	if start < 0 {
		panic("agent read fixed parent function absent")
	}
	rest := source[start:]
	marker := regexp.MustCompile(` AS (\$[a-zA-Z0-9_]*\$)`).FindStringSubmatchIndex(rest)
	if marker == nil {
		panic("agent read fixed parent body absent")
	}
	delimiter := rest[marker[2]:marker[3]]
	body := rest[marker[1]:]
	end := strings.Index(body, delimiter+";")
	if end < 0 {
		panic("agent read fixed parent body end absent")
	}
	return body[:end]
}
func agentReadProfileSource(audit bool) (string, string) {
	_, temporal := authorizationTemporalProfileSource()
	am, im, name, ap, ip := "none", "none", AgentReadProfileName, "", ""
	selected := "IF to_regnamespace('zasp_authorization80_audit') IS NOT NULL OR to_regnamespace('zasp_authorization80_identity') IS NOT NULL THEN RETURN false;END IF;"
	if audit {
		am, im, name, ap, ip = AuthorizationAuditProfileName, AuthorizationIdentityProfileName, AgentReadAuditProfileName, AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
		selected = "IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE singleton AND checksum=r.audit) OR NOT zasp_authorization80_audit.catalog_ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE singleton AND checksum=r.identity) OR NOT zasp_authorization80_identity.structural_ready(r.identity) THEN RETURN false;END IF;"
	}
	source := strings.NewReplacer("-- agent read selected parent predicate", selected, "-- agent read filter name", name, "-- agent read parent79", ProductionAuthorizationProjection().Checksum(), "-- agent read parent80", ProductionAuthorizationEnforcement().Checksum(), "-- agent read temporal", temporal, "-- agent read audit mode", am, "-- agent read identity mode", im, "-- agent read audit", ap, "-- agent read identity", ip, "-- agent read typed14 fingerprint", ProductionTypedInventoryCutoverSemanticFingerprint(), "-- agent read typed14", ProductionTypedInventoryCutover().Checksum()).Replace(agentReadSQL)
	source = strings.NewReplacer("-- agent read session40 fingerprint", ProductionRuntimeSessionsSemanticFingerprint(), "-- agent read session40", ProductionRuntimeSessions().Checksum(), "-- agent read session41 fingerprint", ProductionRuntimeSessionReadsSemanticFingerprint(), "-- agent read session41", ProductionRuntimeSessionReads().Checksum()).Replace(source)
	type fact struct {
		Signature string `json:"signature"`
		Source    string `json:"source"`
		Owner     string `json:"owner,omitempty"`
		API       bool   `json:"api"`
	}
	type column struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		NotNull bool   `json:"notnull"`
	}
	type relation struct {
		Relation string   `json:"relation"`
		Policy   string   `json:"policy"`
		Columns  []column `json:"columns"`
	}
	manifest := struct {
		Parents   []fact     `json:"parents"`
		Own       []fact     `json:"own"`
		Relations []relation `json:"relations"`
	}{}
	typed14 := ProductionTypedInventoryCutover().UpSQL()
	for _, v := range []struct {
		name, args, owner string
		api               bool
	}{
		{"zasp_inventory_scope_state", "text,text,text", "zasp_inventory_authority", false},
		{"zasp_inventory_annotation_value", "text,text,text,text", "zasp_inventory_authority", false},
		{"zasp_inventory_detail", "text,text,text,text,text", "zasp_discovery_authority", true},
		{"zasp_inventory_agent_capability_edges", "text,text,text,text", "zasp_discovery_authority", false},
		{"zasp_inventory_agent_capabilities_page", "text,text,text,text,text,integer", "zasp_discovery_authority", true},
		{"zasp_inventory_agent_relationships_page", "text,text,text,text,text,integer", "zasp_discovery_authority", true},
	} {
		manifest.Parents = append(manifest.Parents, fact{"public." + v.name + "(" + v.args + ")", ownerSourceHash(ownerFunctionBody(typed14, "public."+v.name)), v.owner, v.api})
	}
	manifest.Parents = append(manifest.Parents, fact{"public.zasp_runtime_session_maintain_summary()", ownerSourceHash(agentReadFunctionBody(ProductionRuntimeSessionReads().UpSQL(), "public.zasp_runtime_session_maintain_summary")), "zasp_discovery_authority", false})
	manifest.Parents = append(manifest.Parents, fact{"zasp_authorization80.session_source_readiness(integer,text,text)", ownerSourceHash(agentReadFunctionBody(ProductionAuthorizationEnforcement().UpSQL(), "zasp_authorization80.session_source_readiness")), "zasp_discovery_authority", true})
	for _, v := range []struct{ name, args string }{{"fingerprint", ""}, {"catalog_ready", "text"}, {"caller_ready", "text"}, {"detail", "text,text,text,text,text"}, {"capabilities", "text,text,text,text,text,integer,text"}, {"relationships", "text,text,text,text,text,integer,text"}, {"sessions", "text,text,text,text,text,integer,text"}} {
		manifest.Own = append(manifest.Own, fact{Signature: "zasp_agent_read_v1." + v.name + "(" + v.args + ")", Source: ownerSourceHash(ownerFunctionBody(source, "zasp_agent_read_v1."+v.name))})
	}
	manifest.Relations = []relation{
		{"public.zasp_runtime_session_events", "zasp_runtime_session_events_authority", []column{
			{"organization_id", "text", true}, {"workspace_id", "text", true}, {"environment_id", "text", true}, {"event_id", "text", true}, {"session_id", "text", false}, {"agent_id", "text", false}, {"confidence", "text", true}, {"source", "text", true}, {"event_class", "text", true}, {"action", "text", true}, {"title", "text", true}, {"evidence_id", "text", true}, {"event_time", "timestamp with time zone", true}, {"projected_at", "timestamp with time zone", true}, {"sandbox_id", "text", false}, {"sandbox_source_sensor_id", "text", false},
		}},
		{"public.zasp_runtime_session_summaries", "zasp_runtime_session_summaries_authority", []column{
			{"organization_id", "text", true}, {"workspace_id", "text", true}, {"environment_id", "text", true}, {"id", "text", true}, {"first_event_at", "timestamp with time zone", true}, {"last_event_at", "timestamp with time zone", true}, {"projected_at", "timestamp with time zone", true}, {"event_count", "bigint", true}, {"exact_count", "bigint", true}, {"strong_count", "bigint", true}, {"probable_count", "bigint", true}, {"unattributed_count", "bigint", true}, {"minimum_agent_id", "text", false}, {"maximum_agent_id", "text", false},
		}},
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		panic("agent read manifest encoding")
	}
	source = strings.ReplaceAll(source, "-- agent read function manifest", string(raw))
	pin := ownerSourceHash(source)
	return strings.ReplaceAll(source, "-- agent read filter checksum", pin), pin
}

// Only immutable, trusted compiler output is retained. No database state,
// authorization decisions, credentials, scope or readiness is cached.
type agentReadCompiledProfiles struct{ normalSource, normalPin, auditSource, auditPin string }

var compiledAgentReadProfiles = sync.OnceValue(func() agentReadCompiledProfiles {
	normal, np := agentReadProfileSource(false)
	audit, ap := agentReadProfileSource(true)
	return agentReadCompiledProfiles{normal, np, audit, ap}
})

func AgentReadProfileChecksum() string      { return compiledAgentReadProfiles().normalPin }
func AgentReadAuditProfileChecksum() string { return compiledAgentReadProfiles().auditPin }
func compiledAgentReadProfileSource(audit bool) (string, string) {
	p := compiledAgentReadProfiles()
	if audit {
		return p.auditSource, p.auditPin
	}
	return p.normalSource, p.normalPin
}
func IsAgentReadProfileChecksum(p string) bool {
	return len(p) == 64 && (p == AgentReadProfileChecksum() || p == AgentReadAuditProfileChecksum())
}
func (r *Runner) UpProductionAgentReadProfile(c context.Context) error {
	return r.upProductionAgentReadProfile(c, false)
}
func (r *Runner) UpProductionAgentReadAuditProfile(c context.Context) error {
	return r.upProductionAgentReadProfile(c, true)
}
func (r *Runner) upProductionAgentReadProfile(ctx context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := compiledAgentReadProfileSource(audit)
	const boundary = "-- agent read authority definitions"
	if strings.Count(source, boundary) != 1 {
		return ErrInvalidState
	}
	parts := strings.SplitN(source, boundary, 2)
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if e := tx.Exec(ctx, `SET LOCAL lock_timeout='3s';SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		if e := requireMaintenanceAuthorizationReady(ctx, tx); e != nil {
			return e
		}
		var user, role string
		if e := scanRow(ctx, tx, `SELECT current_user::text,current_setting('role')`, nil, &user, &role); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		if e := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		check := func(q string, args ...any) error {
			var ok bool
			if e := scanRow(ctx, tx, q, args, &ok); e != nil {
				return fixedDatabaseError(ctx, e)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if e := check(`SELECT zasp_authorization79.ready($1) AND zasp_authorization80.ready($2) AND zasp_authorization80_temporal.ready() AND public.zasp_inventory_security_ready()`, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum()); e != nil {
			return e
		}
		am, im := "none", "none"
		if audit {
			am, im = AuthorizationAuditProfileName, AuthorizationIdentityProfileName
		}
		if e := check(`SELECT count(*)=1 AND bool_and(singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode=$1 AND identity_mode=$2) FROM zasp_authorization80.runtime_profile`, am, im); e != nil {
			return e
		}
		var present bool
		if e := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_agent_read_v1') IS NOT NULL`, nil, &present); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		if !present {
			if e := tx.Exec(ctx, `SET LOCAL ROLE NONE`); e != nil {
				return fixedDatabaseError(ctx, e)
			}
			if e := check(`SELECT current_user=session_user AND has_database_privilege(session_user,current_database(),'CREATE') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`); e != nil {
				return e
			}
			if e := tx.Exec(ctx, parts[0]); e != nil {
				return fixedDatabaseError(ctx, e)
			}
			if e := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); e != nil {
				return fixedDatabaseError(ctx, e)
			}
			if e := tx.Exec(ctx, parts[1]); e != nil {
				return fixedDatabaseError(ctx, e)
			}

			if e := check(`SELECT NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_agent_read_v1'::regnamespace AND(p.proowner<>'zasp_discovery_authority'::regrole OR a.grantor<>p.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(p.proowner,CASE WHEN p.proname IN('detail','capabilities','relationships','sessions','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE p.proowner END))) AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.oid='zasp_agent_read_v1.registration'::regclass AND(a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_read_v1.registration'::regclass AND attacl IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_read_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE'))))`); e != nil {
				return e
			}
			name := AgentReadProfileName
			ap, ip := "", ""
			if audit {
				name = AgentReadAuditProfileName
				ap, ip = AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
			}
			_, temporal := authorizationTemporalProfileSource()
			if e := tx.Exec(ctx, `INSERT INTO zasp_agent_read_v1.registration(singleton,name,checksum,parent79,parent80,temporal,audit,identity,fingerprint) VALUES(true,$1,$2,$3,$4,$5,$6,$7,zasp_agent_read_v1.fingerprint())`, name, pin, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), temporal, ap, ip); e != nil {
				return fixedDatabaseError(ctx, e)
			}
		}
		if e := check(`SELECT zasp_agent_read_v1.catalog_ready($1)`, pin); e != nil {
			return e
		}
		var restored string
		if e := scanRow(ctx, tx, `SELECT set_config('role',$1,true)`, []any{role}, &restored); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		var actualUser, actualRole string
		if e := scanRow(ctx, tx, `SELECT current_user::text,current_setting('role')`, nil, &actualUser, &actualRole); e != nil {
			return fixedDatabaseError(ctx, e)
		}
		if restored != role || actualRole != role || actualUser != user {
			return ErrInvalidState
		}
		return nil
	})
}
