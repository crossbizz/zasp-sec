package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed sql/agent_owner_filter_profile.sql
var agentOwnerFilterSQL string

const AgentOwnerFilterProfileName = "canonical61-temporal78-authorization79-80-agent-owner-filter-v1"
const AgentOwnerFilterAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-agent-owner-filter-v1"

func ownerSourceHash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func ownerFunctionBody(source, identity string) string {
	start := strings.Index(source, "CREATE FUNCTION "+identity+"(")
	if start < 0 {
		panic("owner fixed function absent")
	}
	rest := source[start:]
	first := strings.Index(rest, "AS $$")
	if first < 0 {
		panic("owner function body absent")
	}
	rest = rest[first+5:]
	end := strings.Index(rest, "$$;")
	if end < 0 {
		panic("owner function end absent")
	}
	return rest[:end]
}
func agentOwnerFilterProfileSource(audit bool) (string, string) {
	_, temporal := authorizationTemporalProfileSource()
	am, im, name, ap, ip := "none", "none", AgentOwnerFilterProfileName, "", ""
	selected := "IF to_regnamespace('zasp_authorization80_audit') IS NOT NULL OR to_regnamespace('zasp_authorization80_identity') IS NOT NULL THEN RETURN false;END IF;"
	if audit {
		am, im, name, ap, ip = AuthorizationAuditProfileName, AuthorizationIdentityProfileName, AgentOwnerFilterAuditProfileName, AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
		selected = "IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE singleton AND checksum=r.audit) OR NOT zasp_authorization80_audit.catalog_ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE singleton AND checksum=r.identity) OR NOT zasp_authorization80_identity.structural_ready(r.identity) THEN RETURN false;END IF;"
	}
	source := strings.NewReplacer("-- owner selected parent predicate", selected, "-- owner filter name", name, "-- owner parent79", ProductionAuthorizationProjection().Checksum(), "-- owner parent80", ProductionAuthorizationEnforcement().Checksum(), "-- owner temporal", temporal, "-- owner audit mode", am, "-- owner identity mode", im, "-- owner audit", ap, "-- owner identity", ip, "-- owner typed14 fingerprint", ProductionTypedInventoryCutoverSemanticFingerprint(), "-- owner typed14", ProductionTypedInventoryCutover().Checksum()).Replace(agentOwnerFilterSQL)
	type fact struct {
		Signature string `json:"signature"`
		Source    string `json:"source"`
		Owner     string `json:"owner,omitempty"`
		ACL       string `json:"acl,omitempty"`
	}
	typed14Source := ProductionTypedInventoryCutover().UpSQL()
	manifest := struct {
		Parents []fact `json:"parents"`
		Own     []fact `json:"own"`
	}{Parents: []fact{}, Own: []fact{}}
	for _, name := range []string{"zasp_inventory_annotation_value", "zasp_inventory_scope_state"} {
		manifest.Parents = append(manifest.Parents, fact{"public." + name + "(text,text,text" + map[string]string{"zasp_inventory_annotation_value": ",text"}[name] + ")", ownerSourceHash(ownerFunctionBody(typed14Source, "public."+name)), "zasp_inventory_authority", "{zasp_inventory_authority=X/zasp_inventory_authority,zasp_discovery_authority=X/zasp_inventory_authority}"})
	}
	// Public detail has its original API entry-point ACL and authority ownership.
	manifest.Parents = append(manifest.Parents, fact{"public.zasp_inventory_detail(text,text,text,text,text)", ownerSourceHash(ownerFunctionBody(typed14Source, "public.zasp_inventory_detail")), "zasp_discovery_authority", "{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}"})
	for _, v := range []struct{ name, args string }{{"fingerprint", ""}, {"catalog_ready", "text"}, {"caller_ready", "text"}, {"page", "text,text,text,text,integer,text,text"}} {
		manifest.Own = append(manifest.Own, fact{Signature: "zasp_agent_owner_filter_v1." + v.name + "(" + v.args + ")", Source: ownerSourceHash(ownerFunctionBody(source, "zasp_agent_owner_filter_v1."+v.name))})
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		panic("owner manifest encoding")
	}
	source = strings.ReplaceAll(source, "-- owner function manifest", string(raw))
	pin := ownerSourceHash(source)
	return strings.ReplaceAll(source, "-- owner filter checksum", pin), pin
}

// Only immutable, trusted compiler output is retained. No database state,
// authorization decisions, credentials, scope or readiness is cached.
type agentOwnerCompiledProfiles struct{ normalSource, normalPin, auditSource, auditPin string }

var compiledAgentOwnerProfiles = sync.OnceValue(func() agentOwnerCompiledProfiles {
	normal, np := agentOwnerFilterProfileSource(false)
	audit, ap := agentOwnerFilterProfileSource(true)
	return agentOwnerCompiledProfiles{normal, np, audit, ap}
})

func AgentOwnerFilterProfileChecksum() string      { return compiledAgentOwnerProfiles().normalPin }
func AgentOwnerFilterAuditProfileChecksum() string { return compiledAgentOwnerProfiles().auditPin }
func compiledAgentOwnerProfileSource(audit bool) (string, string) {
	p := compiledAgentOwnerProfiles()
	if audit {
		return p.auditSource, p.auditPin
	}
	return p.normalSource, p.normalPin
}
func IsAgentOwnerFilterProfileChecksum(p string) bool {
	return len(p) == 64 && (p == AgentOwnerFilterProfileChecksum() || p == AgentOwnerFilterAuditProfileChecksum())
}
func (r *Runner) UpProductionAgentOwnerFilterProfile(c context.Context) error {
	return r.upProductionAgentOwnerFilterProfile(c, false)
}
func (r *Runner) UpProductionAgentOwnerFilterAuditProfile(c context.Context) error {
	return r.upProductionAgentOwnerFilterProfile(c, true)
}
func (r *Runner) upProductionAgentOwnerFilterProfile(ctx context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := compiledAgentOwnerProfileSource(audit)
	const boundary = "-- owner authority definitions"
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
		if e := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_agent_owner_filter_v1') IS NOT NULL`, nil, &present); e != nil {
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

			if e := check(`SELECT NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_agent_owner_filter_v1'::regnamespace AND(p.proowner<>'zasp_discovery_authority'::regrole OR a.grantor<>p.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(p.proowner,CASE WHEN p.proname IN('page','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE p.proowner END))) AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.oid='zasp_agent_owner_filter_v1.registration'::regclass AND(a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_owner_filter_v1.registration'::regclass AND attacl IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_owner_filter_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE'))))`); e != nil {
				return e
			}
			name := AgentOwnerFilterProfileName
			ap, ip := "", ""
			if audit {
				name = AgentOwnerFilterAuditProfileName
				ap, ip = AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
			}
			_, temporal := authorizationTemporalProfileSource()
			if e := tx.Exec(ctx, `INSERT INTO zasp_agent_owner_filter_v1.registration(singleton,name,checksum,parent79,parent80,temporal,audit,identity,fingerprint) VALUES(true,$1,$2,$3,$4,$5,$6,$7,zasp_agent_owner_filter_v1.fingerprint())`, name, pin, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), temporal, ap, ip); e != nil {
				return fixedDatabaseError(ctx, e)
			}
		}
		if e := check(`SELECT zasp_agent_owner_filter_v1.catalog_ready($1)`, pin); e != nil {
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
