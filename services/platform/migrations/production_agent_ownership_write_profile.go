package migrations

import (
	"context"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed sql/agent_ownership_write_profile.sql
var agentOwnershipWriteSQL string

const AgentOwnershipWriteProfileName = "canonical61-temporal78-authorization79-80-agent-ownership-write-v1"
const AgentOwnershipWriteAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-agent-ownership-write-v1"

func agentOwnershipWriteProfileSource(audit bool) (string, string) {
	_, temporal := authorizationTemporalProfileSource()
	am, im, name, ap, ip := "none", "none", AgentOwnershipWriteProfileName, "", ""
	selected := "IF to_regnamespace('zasp_authorization80_audit') IS NOT NULL OR to_regnamespace('zasp_authorization80_identity') IS NOT NULL THEN RETURN false;END IF;"
	if audit {
		am, im, name, ap, ip = AuthorizationAuditProfileName, AuthorizationIdentityProfileName, AgentOwnershipWriteAuditProfileName, AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
		selected = "IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.registration WHERE singleton AND checksum=r.audit) OR NOT zasp_authorization80_audit.catalog_ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_identity.registration WHERE singleton AND checksum=r.identity) OR NOT zasp_authorization80_identity.structural_ready(r.identity) THEN RETURN false;END IF;"
	}
	source := strings.NewReplacer("-- ownership write selected parent predicate", selected, "-- ownership write filter name", name, "-- ownership write parent79", ProductionAuthorizationProjection().Checksum(), "-- ownership write parent80", ProductionAuthorizationEnforcement().Checksum(), "-- ownership write temporal", temporal, "-- ownership write audit mode", am, "-- ownership write identity mode", im, "-- ownership write audit", ap, "-- ownership write identity", ip, "-- ownership write typed14 fingerprint", ProductionTypedInventoryCutoverSemanticFingerprint(), "-- ownership write typed14", ProductionTypedInventoryCutover().Checksum()).Replace(agentOwnershipWriteSQL)
	type fact struct {
		Signature  string  `json:"signature"`
		Source     string  `json:"source"`
		Owner      string  `json:"owner,omitempty"`
		ACL        *string `json:"acl"`
		Secdef     bool    `json:"secdef"`
		Path       bool    `json:"path"`
		Volatility string  `json:"volatility,omitempty"`
		Strict     bool    `json:"strict"`
	}
	manifest := struct {
		Parents []fact `json:"parents"`
		Own     []fact `json:"own"`
	}{Parents: []fact{}, Own: []fact{}}
	acl := func(value string) *string { return &value }
	typed14 := ProductionTypedInventoryCutover().UpSQL()
	for _, v := range []struct{ name, args, owner, access string }{
		{"zasp_inventory_security_ready", "", "zasp_inventory_authority", "{zasp_inventory_authority=X/zasp_inventory_authority,zasp_discovery_authority=X/zasp_inventory_authority}"},
		{"zasp_inventory_scope_state", "text,text,text", "zasp_inventory_authority", "{zasp_inventory_authority=X/zasp_inventory_authority,zasp_discovery_authority=X/zasp_inventory_authority}"},
		{"zasp_inventory_annotation_value", "text,text,text,text", "zasp_inventory_authority", "{zasp_inventory_authority=X/zasp_inventory_authority,zasp_discovery_authority=X/zasp_inventory_authority}"},
		{"zasp_inventory_detail", "text,text,text,text,text", "zasp_discovery_authority", "{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}"},
		{"zasp_inventory_update_agent", "text,text,text,text,text,text,bigint,text,text,jsonb,text,text", "zasp_discovery_authority", "{zasp_discovery_authority=X/zasp_discovery_authority,zasp_discovery_api=X/zasp_discovery_authority}"},
		{"zasp_inventory_refresh_posture_findings", "text,text,text", "zasp_discovery_authority", "{zasp_discovery_authority=X/zasp_discovery_authority}"},
	} {
		manifest.Parents = append(manifest.Parents, fact{Signature: "public." + v.name + "(" + v.args + ")", Source: ownerSourceHash(ownerFunctionBody(typed14, "public."+v.name)), Owner: v.owner, ACL: acl(v.access), Secdef: true, Path: true})
	}
	manifest.Parents = append(manifest.Parents,
		fact{Signature: "public.zasp_discovery_canonical_id(text,text,text,text,text)", Source: ownerSourceHash(agentReadFunctionBody(ProductionDiscovery().UpSQL(), `"public"."zasp_discovery_canonical_id"`)), Owner: "zasp_discovery_authority", ACL: acl("{zasp_discovery_authority=X/zasp_discovery_authority}"), Secdef: true, Path: true, Volatility: "i", Strict: true},
		fact{Signature: "public.zasp_valid_product_id(text)", Source: ownerSourceHash(agentReadFunctionBody(ProductionDiscovery().UpSQL(), `"public"."zasp_valid_product_id"`)), Owner: "@registered-source", ACL: nil, Secdef: false, Path: false, Volatility: "i", Strict: true},
		fact{Signature: "zasp_temporal67.immutable()", Source: ownerSourceHash(agentReadFunctionBody(ProductionTemporalDomain().UpSQL(), "zasp_temporal67.immutable")), Owner: "zasp_discovery_authority", ACL: acl("{zasp_discovery_authority=X/zasp_discovery_authority}"), Secdef: false, Path: true, Volatility: "v"},
	)
	for _, v := range []struct{ name, args string }{{"fingerprint", ""}, {"catalog_ready", "text"}, {"caller_ready", "text"}, {"require_api", "text,text,text,text,text,text"}, {"update_agent", "text,text,text,text,text,text,bigint,text,text,jsonb,text,text,text"}} {
		manifest.Own = append(manifest.Own, fact{Signature: "zasp_agent_ownership_write_v1." + v.name + "(" + v.args + ")", Source: ownerSourceHash(ownerFunctionBody(source, "zasp_agent_ownership_write_v1."+v.name))})
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		panic("ownership write manifest encoding")
	}
	source = strings.ReplaceAll(source, "-- ownership write function manifest", string(raw))
	pin := ownerSourceHash(source)
	return strings.ReplaceAll(source, "-- ownership write filter checksum", pin), pin
}

// Only immutable, trusted compiler output is retained. No database state,
// authorization decisions, credentials, scope or readiness is cached.
type agentOwnershipWriteCompiledProfiles struct{ normalSource, normalPin, auditSource, auditPin string }

var compiledAgentOwnershipWriteProfiles = sync.OnceValue(func() agentOwnershipWriteCompiledProfiles {
	normal, np := agentOwnershipWriteProfileSource(false)
	audit, ap := agentOwnershipWriteProfileSource(true)
	return agentOwnershipWriteCompiledProfiles{normal, np, audit, ap}
})

func AgentOwnershipWriteProfileChecksum() string {
	return compiledAgentOwnershipWriteProfiles().normalPin
}
func AgentOwnershipWriteAuditProfileChecksum() string {
	return compiledAgentOwnershipWriteProfiles().auditPin
}
func compiledAgentOwnershipWriteProfileSource(audit bool) (string, string) {
	p := compiledAgentOwnershipWriteProfiles()
	if audit {
		return p.auditSource, p.auditPin
	}
	return p.normalSource, p.normalPin
}
func IsAgentOwnershipWriteProfileChecksum(p string) bool {
	return len(p) == 64 && (p == AgentOwnershipWriteProfileChecksum() || p == AgentOwnershipWriteAuditProfileChecksum())
}
func (r *Runner) UpProductionAgentOwnershipWriteProfile(c context.Context) error {
	return r.upProductionAgentOwnershipWriteProfile(c, false)
}
func (r *Runner) UpProductionAgentOwnershipWriteAuditProfile(c context.Context) error {
	return r.upProductionAgentOwnershipWriteProfile(c, true)
}
func (r *Runner) upProductionAgentOwnershipWriteProfile(ctx context.Context, audit bool) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRunner
	}
	source, pin := compiledAgentOwnershipWriteProfileSource(audit)
	const boundary = "-- ownership write authority definitions"
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
		if e := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_agent_ownership_write_v1') IS NOT NULL`, nil, &present); e != nil {
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

			if e := check(`SELECT NOT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.pronamespace='zasp_agent_ownership_write_v1'::regnamespace AND(p.proowner<>'zasp_discovery_authority'::regrole OR a.grantor<>p.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(p.proowner,CASE WHEN p.proname IN('update_agent','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE p.proowner END))) AND NOT EXISTS(SELECT 1 FROM pg_class t CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE t.oid='zasp_agent_ownership_write_v1.registration'::regclass AND(a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_ownership_write_v1.registration'::regclass AND attacl IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_ownership_write_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE'))))`); e != nil {
				return e
			}
			name := AgentOwnershipWriteProfileName
			ap, ip := "", ""
			if audit {
				name = AgentOwnershipWriteAuditProfileName
				ap, ip = AuthorizationAuditProfileChecksum(), AuthorizationIdentityProfileChecksum()
			}
			_, temporal := authorizationTemporalProfileSource()
			if e := tx.Exec(ctx, `INSERT INTO zasp_agent_ownership_write_v1.registration(singleton,name,checksum,parent79,parent80,temporal,audit,identity,fingerprint) VALUES(true,$1,$2,$3,$4,$5,$6,$7,zasp_agent_ownership_write_v1.fingerprint())`, name, pin, ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), temporal, ap, ip); e != nil {
				return fixedDatabaseError(ctx, e)
			}
		}
		if e := check(`SELECT zasp_agent_ownership_write_v1.catalog_ready($1)`, pin); e != nil {
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
