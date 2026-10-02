package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

//go:embed sql/0080_authorization_inventory_profile.sql
var authorizationInventoryProfileSQL string

//go:embed sql/0080_authorization_inventory_catalog.sql
var authorizationInventoryCatalogSQL string

// Optional consumers do not alter any registered canonical predecessor.
const AuthorizationInventoryProfileName = "source14-canonical61-inventory-v1"

func inventoryRetainedFunction(name, replacement string) string {
	start := "CREATE FUNCTION public." + name + "("
	_, tail, ok := strings.Cut(typedInventoryUpSQL, start)
	body, _, end := strings.Cut(tail, "END $$;")
	if !ok || !end {
		panic("compiled inventory source function unavailable")
	}
	return "CREATE FUNCTION zasp_authorization80_inventory." + replacement + "(" + body + "END $$;"
}
func inventoryReplace(source, old, replacement string) string {
	if strings.Count(source, old) != 1 {
		panic("compiled inventory source boundary changed")
	}
	return strings.Replace(source, old, replacement, 1)
}

type inventoryCompiledSource struct{ source, checksum string }

var inventoryCompiled = sync.OnceValue(func() inventoryCompiledSource {
	source, checksum := buildAuthorizationInventoryProfileSource()
	return inventoryCompiledSource{source, checksum}
})

func authorizationInventoryProfileSource() (string, string) {
	result := inventoryCompiled()
	return result.source, result.checksum
}
func buildAuthorizationInventoryProfileSource() (string, string) {
	caps := inventoryRetainedFunction("zasp_inventory_agent_capabilities_page", "_capabilities_page")
	caps = inventoryReplace(caps, "SELECT * FROM enriched WHERE after_value IS NULL OR key_value>after_value ORDER BY key_value LIMIT limit_value+1", `SELECT * FROM enriched WHERE EXISTS(SELECT 1 FROM public.zasp_inventory_entities target WHERE(target.organization_id,target.workspace_id,target.environment_id,target.id,target.state)=(organization_value,workspace_value,environment_value,enriched.target_id,'active') AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,target.product_kind,target.id)) AND(after_value IS NULL OR key_value>after_value) ORDER BY key_value LIMIT limit_value+1`)
	rels := inventoryRetainedFunction("zasp_inventory_agent_relationships_page", "_relationships_page")
	rels = inventoryReplace(rels, "AND (after_value IS NULL OR relationship_value.id>after_value)", `AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,source_entity.product_kind,source_entity.id) AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,target_entity.product_kind,target_entity.id) AND (after_value IS NULL OR relationship_value.id>after_value)`)
	s := strings.NewReplacer("-- inventory catalog query", strings.TrimSpace(authorizationInventoryCatalogSQL), "-- inventory retained capability page", caps, "-- inventory retained relationship page", rels, "-- inventory80 checksum", ProductionAuthorizationEnforcement().Checksum(), "-- inventory61 checksum", ProductionSecurityAgentMultistep().Checksum(), "-- inventory61 fingerprint", SecurityAgentMultistepRegisteredFingerprint()).Replace(authorizationInventoryProfileSQL)
	s = "-- inventory predecessors " + ProductionTypedInventoryCutover().Checksum() + " " + ProductionRuntimeSessions().Checksum() + " " + ProductionRuntimeSessionReads().Checksum() + " " + ProductionAuthorizationProjection().Checksum() + "\n" + s
	h := sha256.Sum256([]byte(s))
	c := hex.EncodeToString(h[:])
	return strings.ReplaceAll(s, "-- inventory profile checksum", c), c
}
func AuthorizationInventoryProfileChecksum() string {
	_, c := authorizationInventoryProfileSource()
	return c
}

func inventoryPinnedReadinessSQL(api bool) string {
	source, c := authorizationInventoryProfileSource()
	pins := []string{}
	for _, name := range []string{"catalog", "ready", "api_ready"} {
		marker := "AS $" + name + "$"
		_, tail, ok := strings.Cut(source, "CREATE FUNCTION zasp_authorization80_inventory."+name+"(")
		_, body, found := strings.Cut(tail, marker)
		body, _, end := strings.Cut(body, "$"+name+"$;")
		if !ok || !found || !end {
			panic("compiled inventory readiness boundary unavailable")
		}
		signature := name + "()"
		if name == "ready" {
			signature = "ready(text)"
		}
		pins = append(pins, fmt.Sprintf(`EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('zasp_authorization80_inventory.%s') AND p.prosrc='%s' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='sql') AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.privilege_type<>'EXECUTE' OR a.is_grantable OR a.grantee NOT IN('zasp_discovery_authority'::regrole%s)))`, signature, strings.ReplaceAll(body, "'", "''"), map[bool]string{true: ",'zasp_security_agent_api'::regrole", false: ""}[name != "catalog"]))
	}
	q := "SELECT " + strings.Join(pins, " AND ") + " AND zasp_authorization80_inventory.ready('" + c + "')"
	if api {
		q += " AND zasp_authorization80_inventory.api_ready()"
	}
	return q
}

// The API verifies compiled gate sources before trusting a callable readiness
// result. An allow-valued replacement cannot bless its own changed catalog.
var inventoryAPIReadyQuery = sync.OnceValue(func() string { return inventoryPinnedReadinessSQL(true) })
var inventoryInstallerReadyQuery = sync.OnceValue(func() string { return inventoryPinnedReadinessSQL(false) })

func AuthorizationInventoryReadySourceSQL() string { return inventoryAPIReadyQuery() }

// The migration operator verifies structural admission without impersonating an API login.
func AuthorizationInventoryInstallerReadySourceSQL() string {
	return inventoryInstallerReadyQuery()
}

func (r *Runner) UpProductionAuthorizationInventoryProfile(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(q string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, q, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if err := check(`SELECT (SELECT count(*)=61 FROM public.zasp_schema_versions) AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND checksum=$1) AND zasp_authorization79.operator() AND zasp_authorization79.ready($2) AND zasp_authorization80.ready($3) AND public.zasp_sa_multistep_readiness($1,$4)`, ProductionSecurityAgentMultistep().Checksum(), ProductionAuthorizationProjection().Checksum(), ProductionAuthorizationEnforcement().Checksum(), SecurityAgentMultistepRegisteredFingerprint()); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_authorization80_inventory') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if present {
			return check(AuthorizationInventoryInstallerReadySourceSQL())
		}
		const ancestry = `SELECT jsonb_build_array(public.zasp_sa_multistep_registered_live_fingerprint(),zasp_authorization79.fingerprint(),zasp_authorization80.fingerprint())::text`
		var before, after string
		if err := scanRow(ctx, tx, ancestry, nil, &before); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		source, c := authorizationInventoryProfileSource()
		if err := tx.Exec(ctx, source); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := scanRow(ctx, tx, ancestry, nil, &after); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if before != after {
			return ErrInvalidState
		}
		if err := tx.Exec(ctx, `INSERT INTO zasp_authorization80_inventory.registration(checksum,catalog) VALUES($1,zasp_authorization80_inventory.catalog())`, c); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return check(AuthorizationInventoryInstallerReadySourceSQL())
	})
}
