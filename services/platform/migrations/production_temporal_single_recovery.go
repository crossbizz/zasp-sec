package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed sql/0080_temporal_single_recovery.up.sql
var singleRecoveryUpSQL string

//go:embed sql/0080_temporal_single_recovery.admission.sql
var singleRecoveryAdmissionSQL string

//go:embed sql/0080_temporal_single_recovery.delivery.sql
var singleRecoveryDeliverySQL string

//go:embed sql/0080_temporal_single_recovery.settlement.sql
var singleRecoverySettlementSQL string

//go:embed production_temporal_single_recovery.go
var singleRecoveryAssemblySource string

const TemporalSingleRecoveryProfileName = "production_temporal_single_test_cleanup_recovery"

// Validate the compiled readiness body before calling it. Its digest is outside
// its own source, so there is no self-authorizing catalog hash cycle.
const TemporalSingleRecoveryReadySourceSQL = `SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure('zasp_temporal_single_recovery.ready(text)') AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')=$1 AND p.proowner='zasp_discovery_authority'::regrole AND l.lanname='sql' AND p.provolatile='s' AND p.prosecdef AND NOT p.proleakproof AND NOT p.proretset AND p.prokind='f' AND p.proconfig=ARRAY['search_path=pg_catalog, public'])`

func recoverySHA(s string) string   { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func recoveryQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func recoveryReplace(s, old, new string, n int) string {
	if strings.Count(s, old) != n {
		panic("single recovery fixed source changed")
	}
	return strings.ReplaceAll(s, old, new)
}

type recoveryFunctionSource struct {
	signature, body, language, volatility string
	definer                               bool
}

var recoveryFunctionHeader = regexp.MustCompile(`(?m)^CREATE FUNCTION ([a-z0-9_.]+)\(([^\n]*)\) RETURNS [^\n]*? LANGUAGE (sql|plpgsql)([^\n]*?) AS (\$[a-zA-Z0-9_]*\$)`)

// This extractor accepts only our fixed single-line declarations and dollar
// bodies. It is not a general PostgreSQL compiler or caller-provided parser.
func recoveryFunctionSources(s string) []recoveryFunctionSource {
	var result []recoveryFunctionSource
	for _, m := range recoveryFunctionHeader.FindAllStringSubmatchIndex(s, -1) {
		name, args, language, attributes, tag := s[m[2]:m[3]], s[m[4]:m[5]], s[m[6]:m[7]], s[m[8]:m[9]], s[m[10]:m[11]]
		end := strings.Index(s[m[1]:], tag)
		if end < 0 {
			panic("unterminated recovery source")
		}
		types := []string{}
		if args != "" {
			for _, arg := range strings.Split(args, ",") {
				p := strings.Fields(arg)
				if len(p) < 2 {
					panic("unsupported recovery argument")
				}
				types = append(types, strings.Join(p[1:], " "))
			}
		}
		volatility := "v"
		if strings.Contains(attributes, " IMMUTABLE") {
			volatility = "i"
		} else if strings.Contains(attributes, " STABLE") {
			volatility = "s"
		}
		result = append(result, recoveryFunctionSource{name + "(" + strings.Join(types, ",") + ")", s[m[1] : m[1]+end], language, volatility, strings.Contains(attributes, " SECURITY DEFINER")})
	}
	return result
}
func recoveryFindBody(source, signature string) recoveryFunctionSource {
	var found []recoveryFunctionSource
	for _, f := range recoveryFunctionSources(source) {
		if f.signature == signature {
			found = append(found, f)
		}
	}
	if len(found) != 1 {
		panic("recovery predecessor declaration changed: " + signature)
	}
	return found[0]
}
func recoveryWorkerPortablePlanningTerminal(source recoveryFunctionSource) recoveryFunctionSource {
	source.body = recoveryReplace(source.body, "to_jsonb(j)", "zasp_authorization80_worker.planner_receipt_row(a.body->'job',to_jsonb(j),'job')", 1)
	source.body = recoveryReplace(source.body, "to_jsonb(p)", "zasp_authorization80_worker.planner_receipt_row(a.body->'reservation',to_jsonb(p),'reservation')", 1)
	source.body = recoveryReplace(source.body, " AND a.body=jsonb_build_object(", ` AND zasp_authorization80_worker.planner_receipt_row(a.body->'job',to_jsonb(j),'job') IS NOT NULL
  AND (p.run_id IS NULL OR zasp_authorization80_worker.planner_receipt_row(a.body->'reservation',to_jsonb(p),'reservation') IS NOT NULL)
  AND a.body=jsonb_build_object(`, 1)
	return source
}
func recoveryNativeSources() []recoveryFunctionSource {
	current := ProductionTemporalTestExecutor().UpSQL()
	var sources []recoveryFunctionSource
	sources = append(sources, recoveryFindBody(authorizationWorkerStopSuccessor(current), "zasp_authorization80_worker.test74_stop_evidence(text,text,text,text)"))
	for _, signature := range []string{"zasp_temporal74.record_control(text,text,text,text,text,text,text)", "zasp_temporal74.decision_owner(zasp_temporal74.control_intents)", "zasp_temporal74.start_identity(jsonb)", "zasp_temporal74.parent_evidence(text,text,text,text,text)", "zasp_temporal74.stop_evidence(text,text,text,text)", "zasp_temporal74.unresolved(text,text,text,text)"} {
		sources = append(sources, recoveryFindBody(current, signature))
	}
	// Exact source18 -> export58 -> manual63 -> private74 copy recipe.
	cancel := recoveryFindBody(ProductionSecurityAgentExecution().UpSQL(), "public.zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)")
	originalGuard := "EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value))"
	exportGuard := "EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value) AND NOT (effect.action_key='create_evidence_export' AND EXISTS(SELECT 1 FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.input_digest,l.export_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.input_digest,effect.outcome_id))))"
	cancel.body = recoveryReplace(cancel.body, originalGuard, exportGuard, 1)
	cancel.body = recoveryReplace(cancel.body, "  UPDATE zasp_security_agent_approvals approval SET state='cancelled'", "  PERFORM public.zasp_sa_export_cancel_child(organization_value,workspace_value,environment_value,run_value);\n  UPDATE zasp_security_agent_approvals approval SET state='cancelled'", 1)
	cancel.body = recoveryReplace(cancel.body, "jsonb_build_array(run_row.trigger_id)", "public.zasp_sa_manual_evidence(organization_value,workspace_value,environment_value,run_value,run_row.trigger_id)", 1)
	cancel.body = recoveryReplace(cancel.body, "'receipt_id',receipt_value,'replayed',false);", "'receipt_id',receipt_value,'replayed',false)||public.zasp_sa_manual_fields(organization_value,workspace_value,environment_value,run_value);", 1)
	cancel.body = recoveryReplace(cancel.body, "IF NOT FOUND OR "+exportGuard+" THEN", "IF NOT FOUND THEN", 1)
	cancel.body = recoveryReplace(cancel.body, "PERFORM public.zasp_sa_export_cancel_child(organization_value,workspace_value,environment_value,run_value);", "", 1)
	cancel.signature = "zasp_temporal74.cancel_core(text,text,text,text,text,text,bigint,text,text,text)"
	sources = append(sources, cancel)
	terminal := recoveryFindBody(ProductionTemporalExecutor().UpSQL(), "zasp_temporal68.planning_terminal_valid(text,text,text,text)")
	terminal.body = strings.NewReplacer("zasp_temporal68.", "zasp_temporal74.", "zasp_temporal66.is_temporal(", "zasp_temporal74.is_owned(", "zasp_sa_multistep_prior.context(", "zasp_temporal74.context(", "zasp_sa_multistep_prior.planning_body(", "zasp_temporal74.planning_body(", "zasp_sa_multistep_prior.planning_result(", "zasp_temporal74.planning_result(").Replace(terminal.body)
	terminal.body = strings.NewReplacer("zasp_temporal74.principal_ready(", "zasp_temporal68.principal_ready(", "zasp_temporal74.active_count(", "zasp_temporal68.active_count(").Replace(terminal.body)
	terminal.signature = "zasp_temporal74.planning_terminal_valid(text,text,text,text)"
	terminal = recoveryWorkerPortablePlanningTerminal(terminal)
	sources = append(sources, terminal)
	return sources
}
func recoveryFunctionChecks(sources []recoveryFunctionSource) string {
	clauses := []string{}
	for _, f := range sources {
		clauses = append(clauses, fmt.Sprintf(`EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid=to_regprocedure(%s) AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')=%s AND p.proowner='zasp_discovery_authority'::regrole AND l.lanname=%s AND p.provolatile=%s AND p.prosecdef=%t AND NOT p.proleakproof AND NOT p.proretset AND p.prokind='f' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0))`, recoveryQuote(f.signature), recoveryQuote(recoverySHA(f.body)), recoveryQuote(f.language), recoveryQuote(f.volatility), f.definer))
		roles := []string{"zasp_discovery_authority"}
		switch f.signature {
		case "zasp_temporal_single_recovery.preflight(jsonb)", "zasp_temporal_single_recovery.admit(jsonb)", "zasp_temporal_single_recovery.get(text,text,text,text,text)":
			roles = append(roles, "zasp_security_agent_api")
		case "zasp_temporal_single_recovery.pending()", "zasp_temporal_single_recovery.attempt(jsonb)", "zasp_temporal_single_recovery.ack(jsonb)":
			roles = append(roles, "zasp_temporal_executor")
		case "zasp_temporal_single_recovery.load(jsonb)", "zasp_temporal_single_recovery.observe(jsonb,text)", "zasp_temporal_single_recovery.finish(jsonb)":
			roles = append(roles, "zasp_temporal_compensation")
		case "zasp_temporal74.unresolved(text,text,text,text)":
			roles = append(roles, "zasp_temporal_accounting")
		}
		quoted := []string{}
		for _, role := range roles {
			quoted = append(quoted, recoveryQuote(role))
		}
		sort.Strings(quoted)
		clauses = append(clauses, fmt.Sprintf(`(SELECT array_agg(a.grantee::regrole::text ORDER BY a.grantee::regrole::text COLLATE "C")=ARRAY[%s] AND bool_and(a.grantor=p.proowner AND a.privilege_type='EXECUTE' AND NOT a.is_grantable) FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=to_regprocedure(%s))`, strings.Join(quoted, ","), recoveryQuote(f.signature)))
	}
	return strings.Join(clauses, "\n AND ")
}

// Source-derived columns close extra/missing/reordered/type/nullability drift.
// The narrow grammar accepts only this file's fixed table declarations.
func recoveryTableChecks() string {
	tableRE := regexp.MustCompile(`(?m)^CREATE TABLE zasp_temporal_single_recovery\.([a-z_]+)\(`)
	var checks []string
	names := []string{}
	for _, m := range tableRE.FindAllStringSubmatchIndex(singleRecoveryUpSQL, -1) {
		name := singleRecoveryUpSQL[m[2]:m[3]]
		names = append(names, name)
		start := m[1]
		depth := 1
		end := start
		for ; end < len(singleRecoveryUpSQL) && depth > 0; end++ {
			switch singleRecoveryUpSQL[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		if depth != 0 {
			panic("recovery table declaration changed")
		}
		body := singleRecoveryUpSQL[start : end-1]
		parts := []string{}
		depth = 0
		last := 0
		for i, c := range body {
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
			}
			if c == ',' && depth == 0 {
				parts = append(parts, body[last:i])
				last = i + 1
			}
		}
		parts = append(parts, body[last:])
		columns := []string{}
		pk, unique, fk, check := 0, 0, 0, 0
		for _, part := range parts {
			part = strings.TrimSpace(part)
			fields := strings.Fields(part)
			switch {
			case strings.HasPrefix(part, "PRIMARY KEY"):
				pk++
				continue
			case strings.HasPrefix(part, "UNIQUE("):
				unique++
				continue
			case strings.HasPrefix(part, "FOREIGN KEY"):
				fk++
				continue
			}
			if len(fields) < 2 {
				panic("recovery column declaration changed")
			}
			typ := map[string]string{"text": "text", "bytea": "bytea", "jsonb": "jsonb", "timestamptz": "timestamp with time zone", "bigint": "bigint", "boolean": "boolean"}[fields[1]]
			if typ == "" {
				panic("unsupported recovery column type")
			}
			isPK := strings.Contains(part, "PRIMARY KEY")
			if isPK {
				pk++
			}
			check += strings.Count(part, "CHECK(")
			columns = append(columns, fmt.Sprintf("(%d,%s,%s,%t)", len(columns)+1, recoveryQuote(fields[0]), recoveryQuote(typ), strings.Contains(part, "NOT NULL") || isPK))
		}
		relation := recoveryQuote("zasp_temporal_single_recovery." + name)
		checks = append(checks, fmt.Sprintf(`EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=to_regclass(%s) AND c.relkind='r' AND c.relowner='zasp_discovery_authority'::regrole AND c.relrowsecurity AND c.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)) AND NOT EXISTS((SELECT attnum::integer,attname::text,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid=to_regclass(%s) AND attnum>0) EXCEPT (VALUES %s)) AND NOT EXISTS((VALUES %s) EXCEPT (SELECT attnum::integer,attname::text,format_type(atttypid,atttypmod),attnotnull FROM pg_attribute WHERE attrelid=to_regclass(%s) AND attnum>0)) AND(SELECT count(*) FILTER(WHERE contype='p')=%d AND count(*) FILTER(WHERE contype='u')=%d AND count(*) FILTER(WHERE contype='f')=%d AND count(*) FILTER(WHERE contype='c')=%d AND bool_and(convalidated) FROM pg_constraint WHERE conrelid=to_regclass(%s))`, relation, relation, strings.Join(columns, ","), strings.Join(columns, ","), relation, pk, unique, fk, check, relation))
	}
	sort.Strings(names)
	quoted := []string{}
	for _, n := range names {
		quoted = append(quoted, recoveryQuote(n))
	}
	checks = append(checks, "(SELECT array_agg(relname::text ORDER BY relname COLLATE \"C\")=ARRAY["+strings.Join(quoted, ",")+"] FROM pg_class WHERE relnamespace='zasp_temporal_single_recovery'::regnamespace AND relkind IN('r','v','m','f','p'))")
	return strings.Join(checks, "\n AND ")
}
func recoveryConstraintChecks() string {
	scope := "organization_id, workspace_id, environment_id"
	parent := scope + ", run_id"
	specs := map[string][]string{
		"registration":        {"PRIMARY KEY (singleton)", "CHECK (singleton)"},
		"commands":            {"PRIMARY KEY (" + parent + ")", "UNIQUE (" + scope + ", command_id)", "FOREIGN KEY (" + parent + ") REFERENCES zasp_temporal74.run_owners(" + parent + ")", "CHECK ((octet_length(command_digest) = 32))", "CHECK ((octet_length((command)::text) <= 65536))"},
		"request_receipts":    {"PRIMARY KEY (" + scope + ", actor_id, idempotency_key)", "UNIQUE (" + scope + ", receipt_id)", "FOREIGN KEY (" + parent + ") REFERENCES zasp_temporal74.run_owners(" + parent + ")", "CHECK ((octet_length(intent_digest) = 32))"},
		"audit":               {"PRIMARY KEY (" + scope + ", audit_id)", "CHECK ((event_kind = ANY (ARRAY['cleanup_recovery_requested'::text, 'cleanup_recovery_completed'::text])))", "CHECK ((octet_length(body_digest) = 32))"},
		"deliveries":          {"PRIMARY KEY (" + parent + ")", "FOREIGN KEY (" + scope + ", command_id) REFERENCES zasp_temporal_single_recovery.commands(" + scope + ", command_id)"},
		"progress":            {"PRIMARY KEY (" + parent + ")", "FOREIGN KEY (" + scope + ", command_id) REFERENCES zasp_temporal_single_recovery.commands(" + scope + ", command_id)", "CHECK ((status = ANY (ARRAY['queued'::text, 'pending'::text, 'repair_required'::text])))", "CHECK ((reason = ANY (ARRAY['queued'::text, 'cleanup_pending'::text, 'dependency_unavailable'::text, 'evidence_conflict'::text])))", "CHECK ((version > 0))"},
		"completion_receipts": {"PRIMARY KEY (" + parent + ")", "UNIQUE (" + scope + ", receipt_id)", "FOREIGN KEY (" + scope + ", command_id) REFERENCES zasp_temporal_single_recovery.commands(" + scope + ", command_id)", "CHECK ((octet_length(command_digest) = 32))", "CHECK ((octet_length(evidence_digest) = 32))", "CHECK ((octet_length(body_digest) = 32))"},
	}
	names := []string{}
	for name := range specs {
		names = append(names, name)
	}
	sort.Strings(names)
	clauses := []string{}
	for _, name := range names {
		defs := specs[name]
		sort.Strings(defs)
		quoted := []string{}
		for _, d := range defs {
			quoted = append(quoted, recoveryQuote(d))
		}
		rel := recoveryQuote("zasp_temporal_single_recovery." + name)
		clauses = append(clauses, fmt.Sprintf(`(SELECT array_agg(pg_get_constraintdef(oid) ORDER BY pg_get_constraintdef(oid) COLLATE "C")=ARRAY[%s] AND bool_and(convalidated AND NOT condeferrable AND NOT condeferred) FROM pg_constraint WHERE conrelid=to_regclass(%s) AND contype<>'n')`, strings.Join(quoted, ","), rel))
		clauses = append(clauses, fmt.Sprintf(`(SELECT count(*)=1 AND bool_and(polname='authority' AND polcmd='*' AND polpermissive AND polroles=ARRAY[0::oid] AND pg_get_expr(polqual,polrelid)='(CURRENT_USER = ''zasp_discovery_authority''::name)' AND pg_get_expr(polwithcheck,polrelid)='(CURRENT_USER = ''zasp_discovery_authority''::name)') FROM pg_policy WHERE polrelid=to_regclass(%s))`, rel))
		if name == "deliveries" || name == "progress" {
			clauses = append(clauses, fmt.Sprintf(`NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(%s) AND NOT tgisinternal)`, rel))
		} else {
			clauses = append(clauses, fmt.Sprintf(`(SELECT count(*)=1 AND bool_and(tgname='immutable' AND tgfoid='zasp_temporal67.immutable()'::regprocedure AND tgtype=58 AND tgenabled='O' AND tgqual IS NULL AND tgargs=''::bytea AND tgnargs=0) FROM pg_trigger WHERE tgrelid=to_regclass(%s) AND NOT tgisinternal)`, rel))
		}
		clauses = append(clauses, fmt.Sprintf(`NOT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass(%s) AND(NOT i.indisvalid OR NOT i.indisready OR NOT i.indisunique OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conindid=i.indexrelid AND c.contype IN('p','u'))))`, rel))
		clauses = append(clauses, fmt.Sprintf(`NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass(%s) AND attnum>0 AND(attisdropped OR attidentity<>'' OR attgenerated<>'' OR attacl IS NOT NULL)) AND NOT EXISTS(SELECT 1 FROM pg_class i JOIN pg_index x ON x.indexrelid=i.oid WHERE x.indrelid=to_regclass(%s) AND(i.relowner<>'zasp_discovery_authority'::regrole OR i.relkind<>'i'))`, rel, rel))
		defaultColumn := ""
		switch name {
		case "commands", "request_receipts", "audit":
			defaultColumn = "created_at"
		case "progress":
			defaultColumn = "updated_at"
		case "completion_receipts":
			defaultColumn = "completed_at"
		}
		if defaultColumn == "" {
			clauses = append(clauses, fmt.Sprintf(`NOT EXISTS(SELECT 1 FROM pg_attrdef WHERE adrelid=to_regclass(%s))`, rel))
		} else {
			clauses = append(clauses, fmt.Sprintf(`(SELECT count(*)=1 AND bool_and(a.attname=%s AND pg_get_expr(d.adbin,d.adrelid)='clock_timestamp()') FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE d.adrelid=to_regclass(%s))`, recoveryQuote(defaultColumn), rel))
		}
	}
	clauses = append(clauses, `NOT EXISTS(SELECT 1 FROM pg_default_acl WHERE defaclnamespace='zasp_temporal_single_recovery'::regnamespace)`)
	clauses = append(clauses, `EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='zasp_temporal_single_recovery' AND n.nspowner='zasp_discovery_authority'::regrole AND(SELECT array_agg(a.grantee::regrole::text||':'||a.privilege_type ORDER BY a.grantee::regrole::text COLLATE "C",a.privilege_type COLLATE "C")=ARRAY['zasp_discovery_authority:CREATE','zasp_discovery_authority:USAGE','zasp_security_agent_api:USAGE','zasp_temporal_compensation:USAGE','zasp_temporal_executor:USAGE'] AND bool_and(a.grantor=n.nspowner AND NOT a.is_grantable) FROM aclexplode(n.nspacl) a))`)
	return strings.Join(clauses, "\n AND ")
}
func TemporalSingleRecoveryReadyBodyDigest() string {
	source, _ := ProductionTemporalSingleRecoverySource()
	return recoverySHA(recoveryFindBody(source, "zasp_temporal_single_recovery.ready(text)").body)
}
func ProductionTemporalSingleRecoverySource() (string, string) {
	source := strings.NewReplacer("-- recovery admission", singleRecoveryAdmissionSQL, "-- recovery delivery", singleRecoveryDeliverySQL, "-- recovery settlement", singleRecoverySettlementSQL).Replace(singleRecoveryUpSQL)
	// Hash before checksum/body-digest expansion prevents a self-hash cycle.
	checksum := recoverySHA(source + singleRecoveryAssemblySource + authorizationWorkerStopSuccessor(ProductionTemporalTestExecutor().UpSQL()) + securityAgentExportLinksSQL + securityAgentManualSQL + ProductionTemporalTestExecutor().Checksum() + ProductionTemporalExecutor().Checksum() + ProductionSecurityAgentExecution().Checksum())
	source = strings.ReplaceAll(source, "-- recovery checksum", checksum)
	own := recoveryFunctionSources(source)
	if len(own) != 23 {
		panic(fmt.Sprintf("recovery function inventory changed: %d", len(own)))
	}
	checks := recoveryFunctionChecks(append(own, recoveryNativeSources()...)) + "\n AND " + recoveryTableChecks() + "\n AND " + recoveryConstraintChecks()
	ready := fmt.Sprintf(`CREATE FUNCTION zasp_temporal_single_recovery.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(c=%s AND zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready() AND zasp_temporal74.current_ready()
 AND(SELECT count(*)=1 FROM zasp_temporal_single_recovery.registration) AND EXISTS(SELECT 1 FROM zasp_temporal_single_recovery.registration WHERE singleton AND profile='production_temporal_single_test_cleanup_recovery' AND checksum=c)
 AND(SELECT count(*)=%d FROM pg_proc WHERE pronamespace='zasp_temporal_single_recovery'::regnamespace)
 AND %s,false)
$ready$;`, recoveryQuote(checksum), len(own)+1, checks)
	return strings.Replace(source, "-- recovery catalog source", ready, 1), checksum
}
func (r *Runner) UpProductionTemporalSingleRecovery(ctx context.Context) error {
	if r == nil || nilInterface(r.database) {
		return ErrInvalidRunner
	}
	source, checksum := ProductionTemporalSingleRecoverySource()
	return r.withTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Exec(ctx, `SET LOCAL lock_timeout='3s'; SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		check := func(sql string, args ...any) error {
			var ok bool
			if err := scanRow(ctx, tx, sql, args, &ok); err != nil {
				return fixedDatabaseError(ctx, err)
			}
			if !ok {
				return ErrInvalidState
			}
			return nil
		}
		if err := check(`SELECT zasp_authorization80_worker.catalog_ready() AND zasp_authorization80_temporal.ready() AND zasp_temporal74.current_ready() AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')`); err != nil {
			return err
		}
		var present bool
		if err := scanRow(ctx, tx, `SELECT to_regnamespace('zasp_temporal_single_recovery') IS NOT NULL`, nil, &present); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if !present {
			if err := tx.Exec(ctx, source); err != nil {
				return fixedDatabaseError(ctx, err)
			}
		}
		if err := check(TemporalSingleRecoveryReadySourceSQL, TemporalSingleRecoveryReadyBodyDigest()); err != nil {
			return err
		}
		return check(`SELECT zasp_temporal_single_recovery.ready($1)`, checksum)
	})
}
