package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	remainingFrameCatalogSHA   = "b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077"
	remainingFrameContractSHA  = "be343a262db904e6694cf79f582ba4ea57d777886bfa27d83165d3fcd18238c6"
	remainingFrameDirectSHA    = "c936c721c58de952ccd1d55baa89d3381a841ec82a4e7f62b1aadb26d72af4ab"
	remainingFrameMissingSHA   = "76e42de4fc2f53938704942e632549797fa1b885461ca30109fb45b37b28fe39"
	remainingFrameReferenceSHA = "cf98a5d2a8ddeaa84d08b67d35e5760fcc2a237906807c65a6fbabb26d43e797"
)

// The five independent sources above are read before the fixture starts. The
// expected texts below are literal source observations, never native output.
var remainingFrameHelpers = []struct {
	identity, sourceSHA, definitionSHA string
	definer                            bool
}{
	{"zasp_authorization80_worker.gateway_projected27()", "9cb5fa4453d0a725d6fde54e7744c884e031bc325d8c96463be67315344a3c4e", "fe8d3216de591bdb1264a9da97f982eb6cb2ac45115a3484c0fc544d2a76019c", false},
	{"zasp_authorization80_worker.ordered_projected28()", "9a0ec7f8b07dacc0e1d254ae127ad259652984824f6a5c621233b14a49c6fbba", "ac79cf296f7e2e7add00e130e18eb30940672680aaf7941ae6d6a05bf4a02876", false},
	{"zasp_temporal72.retained_execution_fingerprint()", "5717960835e5732473eac93e43866ad6eced608a63ac393aa8c6752fb9089e64", "2b9420f94abc111f2751e6fd4ff1dcb2501a1cc26657ba70d32f0e3e1908931b", true},
}

var remainingFramePretty = []struct {
	rule, relation, name, sourceText string
}{
	{"worker-edge:gateway_projected27:7", "public.zasp_recovery_audit", "zasp_recovery_audit_check", "CHECK (zasp_valid_product_id(audit_id) AND zasp_valid_product_id(correlation_id) AND zasp_valid_product_id(receipt_id) AND zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id))"},
	{"worker-edge:gateway_projected27:7", "public.zasp_recovery_backups", "zasp_recovery_backups_check", "CHECK (zasp_valid_product_id(backup_id) AND zasp_valid_product_id(actor_id))"},
	{"worker-edge:gateway_projected27:7", "public.zasp_recovery_fairness", "zasp_recovery_fairness_last_organization_id_check", "CHECK (last_organization_id IS NULL OR zasp_valid_product_id(last_organization_id))"},
	{"worker-edge:gateway_projected27:7", "public.zasp_recovery_request_receipts", "zasp_recovery_request_receipts_check", "CHECK (zasp_valid_product_id(actor_id) AND zasp_valid_product_id(resource_id))"},
	{"worker-edge:gateway_projected27:7", "public.zasp_recovery_restores", "zasp_recovery_restores_check", "CHECK (zasp_valid_product_id(restore_id) AND zasp_valid_product_id(actor_id))"},
	{"worker-edge:ordered_projected28:9", "public.zasp_security_agent_temporary_policy_targets", "zasp_security_agent_targets_policy_sequence", "CREATE TRIGGER zasp_security_agent_targets_policy_sequence BEFORE INSERT OR UPDATE OF credential_id ON zasp_security_agent_temporary_policy_targets FOR EACH ROW WHEN (new.state = 'planned'::text) EXECUTE FUNCTION zasp_policy_deployment_target_sequence_guard()"},
}

type remainingFrameTriggerFact struct {
	RelationName        string `json:"relation_name"`
	Name                string `json:"name"`
	Enabled             string `json:"enabled"`
	Function            string `json:"function"`
	ExecutionDefinition string `json:"execution_definition"`
}

var remainingFrameTemporal = []struct {
	relation, name, capturedKey string
	source, pristine            remainingFrameTriggerFact
}{
	{
		"public.zasp_connector_credentials", "zasp_execution_bind_oauth_subject", `["zasp_connector_credentials", "zasp_execution_bind_oauth_subject"]`,
		remainingFrameTriggerFact{"zasp_connector_credentials", "zasp_execution_bind_oauth_subject", "O", "zasp_execution_bind_oauth_subject_trigger()", "CREATE TRIGGER za p_execution_bind_oauth_ ubject AFTER INSERT OR UPDATE OF  tatu , metadata, credential_reference ON za p_connector_credential  FOR EACH ROW EXECUTE FUNCTION za p_execution_bind_oauth_ ubject_trigger()"},
		remainingFrameTriggerFact{"zasp_connector_credentials", "zasp_execution_bind_oauth_subject", "O", "public.zasp_execution_bind_oauth_subject_trigger()", "CREATE TRIGGER za p_execution_bind_oauth_ ubject AFTER INSERT OR UPDATE OF  tatu , metadata, credential_reference ON public.za p_connector_credential  FOR EACH ROW EXECUTE FUNCTION public.za p_execution_bind_oauth_ ubject_trigger()"},
	},
	{
		"public.zasp_discovery_syncs", "zasp_execution_sync_version", `["zasp_discovery_syncs", "zasp_execution_sync_version"]`,
		remainingFrameTriggerFact{"zasp_discovery_syncs", "zasp_execution_sync_version", "O", "zasp_execution_sync_version_trigger()", "CREATE TRIGGER za p_execution_ ync_ver ion BEFORE UPDATE ON za p_di covery_ ync  FOR EACH ROW EXECUTE FUNCTION za p_execution_ ync_ver ion_trigger()"},
		remainingFrameTriggerFact{"zasp_discovery_syncs", "zasp_execution_sync_version", "O", "public.zasp_execution_sync_version_trigger()", "CREATE TRIGGER za p_execution_ ync_ver ion BEFORE UPDATE ON public.za p_di covery_ ync  FOR EACH ROW EXECUTE FUNCTION public.za p_execution_ ync_ver ion_trigger()"},
	},
}

type remainingFramePrettyObservation struct {
	Rule                 string `json:"rule"`
	Relation             string `json:"relation"`
	Name                 string `json:"name"`
	OID                  uint32 `json:"oid"`
	LiveOIDRows          int    `json:"liveOIDRows"`
	CapturedSourceSHA    string `json:"capturedSourceSHA256"`
	PristineSHA          string `json:"pristineSHA256"`
	SourceSHA            string `json:"sourceFrameSHA256"`
	PristineText         string `json:"pristineText"`
	SourceText           string `json:"sourceFrameText"`
	SourceMatchesCapture bool   `json:"sourceMatchesCapture"`
}

type remainingFrameTemporalObservation struct {
	Relation                 string                    `json:"relation"`
	Name                     string                    `json:"name"`
	OID                      uint32                    `json:"oid"`
	LiveOIDRows              int                       `json:"liveOIDRows"`
	PinnedCapturedRows       int                       `json:"pinnedCapturedRows"`
	PinnedReferenceRows      int                       `json:"pinnedReferenceRows"`
	PinnedCatalogRows        int                       `json:"pinnedCatalogRows"`
	CapturedSourceKey        string                    `json:"capturedSourceKey"`
	QualifiedReferenceKey    string                    `json:"qualifiedReferenceKey"`
	Pristine                 remainingFrameTriggerFact `json:"pristine"`
	Source                   remainingFrameTriggerFact `json:"sourceFrame"`
	PristineMatchesReference bool                      `json:"pristineMatchesReference"`
	SourceMatchesCapture     bool                      `json:"sourceMatchesCapture"`
}

// This test only observes catalog-selected fields. It never invokes the three
// retained fingerprint helpers or a business-effect function. Root owns its
// single opt-in owned-PostgreSQL run and normal fixture cleanup.
func TestP7RemainingProjectionSourceFrame(t *testing.T) {
	switch os.Getenv("ZASP_ORDERED_CURRENT_REMAINING_FRAME_PROBE") {
	case "":
		t.Skip("explicit owned remaining projection frame probe required")
	case "1":
	default:
		t.Fatal("remaining projection frame probe mode refused")
	}
	for _, key := range []string{
		"ZASP_ORDERED_CURRENT_NATIVE379", "ZASP_ORDERED_CURRENT_PRECISION_FRAME_PROBE",
		"ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE", "ZASP_ORDERED_MISSING_REFERENCE_NATIVE",
		"ZASP_ORDERED_PREDECESSOR_CAPTURE", "ZASP_ORDERED_PREDECESSOR_RELEASE",
		"ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT", "ZASP_ORDERED_SUPPLEMENT_CAPTURE",
		"ZASP_ORDERED_READINESS_ATTRIBUTION", "ZASP_ORDERED_READINESS_CAPTURE",
		"ZASP_ORDERED_POLICY_CAPACITY", "ZASP_ORDERED_POLICY_PREFIX",
		"ZASP_P7_ORDERED69_RETIREMENT_ACL", "ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION",
		"ZASP_P7_ORDERED_BODY_CAPTURE", "ZASP_ORDERED62_FUNCTION_TIMING",
		"ZASP_ORDERED_POLICY_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_CAPTURE",
		"ZASP_ORDERED_POLICY_TRACE",
	} {
		if os.Getenv(key) != "" {
			t.Fatalf("remaining projection frame probe overlaps %s", key)
		}
	}
	remainingFrameVerifyPinned(t)
	consumed := false
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
		consumed = true
		remainingFrameObserveInstalled(t, ctx, owner)
		return true // Stop before approval, FGA, or effects.
	}, nil)
	if !consumed {
		t.Fatal("owned remaining projection callback not reached")
	}
}

func remainingFramePinnedFile(t *testing.T, path, hash string) []byte {
	t.Helper()
	raw, err := readOrderedSupplementFile(filepath.Join(orderedCurrentNative379Root(), path), 32*1024*1024)
	if err != nil || supplementSHA(raw) != hash {
		t.Fatal("remaining projection independent pinned source unavailable or changed", path)
	}
	return raw
}

func remainingFrameVerifyPinned(t *testing.T) {
	t.Helper()
	catalogRaw := remainingFramePinnedFile(t, ".superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p7-worker-enforcement/ordered-current-effective-catalog1.json", remainingFrameCatalogSHA)
	contractRaw := remainingFramePinnedFile(t, "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json", remainingFrameContractSHA)
	directRaw := remainingFramePinnedFile(t, "services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/direct-frame-acceptance.json", remainingFrameDirectSHA)
	missingRaw := remainingFramePinnedFile(t, "services/platform/migrations/tools/ordered-current-capture-intake-v1-artifacts/missing-reference-capture.json", remainingFrameMissingSHA)
	referenceRaw := remainingFramePinnedFile(t, "services/platform/migrations/tools/ordered-current-worker-source-closure-v1-artifacts/remaining-reference1.json", remainingFrameReferenceSHA)
	var catalog struct {
		Functions []struct {
			Identity, Definition, Owner, ACL string
			Config                           []string
			SecurityDefiner                  bool `json:"security_definer"`
		} `json:"functions"`
		Constraints []struct{ Relation, Name string }           `json:"constraints"`
		Triggers    []struct{ Relation, Name, Function string } `json:"triggers"`
	}
	var contract struct {
		Nodes []struct {
			Identity, Source, Definition, SourceSHA256, DefinitionSHA256, Owner, ACL string
			Config                                                                   []string
			SecurityDefiner                                                          bool `json:"security_definer"`
		} `json:"nodes"`
	}
	if json.Unmarshal(catalogRaw, &catalog) != nil || json.Unmarshal(contractRaw, &contract) != nil {
		t.Fatal("remaining projection catalog/contract shape refused")
	}
	for _, wanted := range remainingFrameHelpers {
		catalogCount, contractCount := 0, 0
		for _, helper := range catalog.Functions {
			if helper.Identity != wanted.identity {
				continue
			}
			catalogCount++
			if supplementSHA([]byte(helper.Definition)) != wanted.definitionSHA || helper.Owner != "zasp_discovery_authority" || helper.ACL != "{zasp_discovery_authority=X/zasp_discovery_authority}" || !reflect.DeepEqual(helper.Config, []string{"search_path=pg_catalog, public"}) || helper.SecurityDefiner != wanted.definer {
				t.Fatal("remaining projection pinned catalog helper frame refused", wanted.identity)
			}
		}
		for _, helper := range contract.Nodes {
			if helper.Identity != wanted.identity {
				continue
			}
			contractCount++
			if helper.SourceSHA256 != wanted.sourceSHA || supplementSHA([]byte(helper.Source)) != wanted.sourceSHA || helper.DefinitionSHA256 != wanted.definitionSHA || supplementSHA([]byte(helper.Definition)) != wanted.definitionSHA || helper.Owner != "zasp_discovery_authority" || helper.ACL != "{zasp_discovery_authority=X/zasp_discovery_authority}" || !reflect.DeepEqual(helper.Config, []string{"search_path=pg_catalog, public"}) || helper.SecurityDefiner != wanted.definer {
				t.Fatal("remaining projection pinned contract helper frame refused", wanted.identity)
			}
			expression := "pg_get_constraintdef(constraint_value.oid,true)"
			if wanted.identity == remainingFrameHelpers[1].identity {
				expression = "pg_get_triggerdef(trigger.oid,true)"
			} else if wanted.identity == remainingFrameHelpers[2].identity {
				expression = `regexp_replace(pg_get_triggerdef(trigger_value.oid,true),E'\s+',' ','g')`
			}
			if !strings.Contains(helper.Source, expression) {
				t.Fatal("remaining projection original selected expression refused", wanted.identity)
			}
		}
		if catalogCount != 1 || contractCount != 1 {
			t.Fatal("remaining projection pinned helper missing/duplicate", wanted.identity, catalogCount, contractCount)
		}
	}
	var direct struct {
		DirectFrame struct {
			ExpectedRows []struct {
				Kind, Identity string
				Fact           struct {
					DefinitionPretty string `json:"definition_pretty"`
				} `json:"fact"`
				Source struct{ RuleID, DescriptorIdentity, SourceIdentity, SourceSHA256, DefinitionSHA256, SiteSHA256, ExecutionFrameID, KeyFrame, CaptureFrame string } `json:"source"`
			} `json:"expectedRows"`
		} `json:"directFrame"`
	}
	if json.Unmarshal(directRaw, &direct) != nil {
		t.Fatal("remaining projection direct capture shape refused")
	}
	for _, wanted := range remainingFramePretty {
		count, objectCount := 0, 0
		identityRaw, _ := json.Marshal([]string{wanted.relation, wanted.name})
		outerRaw, _ := json.Marshal([]string{wanted.rule, string(identityRaw)})
		for _, row := range direct.DirectFrame.ExpectedRows {
			if row.Identity != string(outerRaw) {
				continue
			}
			count++
			helper := remainingFrameHelpers[0]
			siteSHA := "44cd6c19c5ad613a1f37c54615f42ec14809553986c54d607325632cda37cff9"
			if wanted.rule == "worker-edge:ordered_projected28:9" {
				helper = remainingFrameHelpers[1]
				siteSHA = "b48e38ee107d8084d71e348f2695df99dacf88104cf842ef416c1a2dd2b95aed"
			}
			expectedKind := "constraint"
			if wanted.rule == "worker-edge:ordered_projected28:9" {
				expectedKind = "trigger"
			}
			if row.Kind != expectedKind || row.Fact.DefinitionPretty != wanted.sourceText || row.Source.RuleID != wanted.rule || row.Source.DescriptorIdentity != string(identityRaw) || row.Source.SourceIdentity != helper.identity || row.Source.SourceSHA256 != helper.sourceSHA || row.Source.DefinitionSHA256 != helper.definitionSHA || row.Source.SiteSHA256 != siteSHA || row.Source.ExecutionFrameID != "sourceDiscoveryPublic" || row.Source.KeyFrame != "pg_catalog" || row.Source.CaptureFrame != "original-source-frame" {
				t.Fatal("remaining projection raw pretty source row refused", wanted.relation, wanted.name)
			}
		}
		if wanted.rule == "worker-edge:ordered_projected28:9" {
			for _, row := range catalog.Triggers {
				if row.Relation == wanted.relation && row.Name == wanted.name && row.Function == "public.zasp_policy_deployment_target_sequence_guard()" {
					objectCount++
				}
			}
		} else {
			for _, row := range catalog.Constraints {
				if row.Relation == wanted.relation && row.Name == wanted.name {
					objectCount++
				}
			}
		}
		if count != 1 || objectCount != 1 {
			t.Fatal("remaining projection raw pretty/object cardinality refused", wanted.relation, wanted.name, count, objectCount)
		}
	}
	var missing struct {
		Observations []struct {
			RuleID string `json:"ruleId"`
			Rows   []struct {
				Identity string
				Fields   remainingFrameTriggerFact
			}
		}
	}
	var reference struct {
		Role       string
		SearchPath []string `json:"searchPath"`
		Rows       []struct {
			Kind, Identity string
			Fact           remainingFrameTriggerFact
		}
	}
	if json.Unmarshal(missingRaw, &missing) != nil || json.Unmarshal(referenceRaw, &reference) != nil || reference.Role != "zasp_discovery_authority" || !reflect.DeepEqual(reference.SearchPath, []string{"pg_catalog"}) {
		t.Fatal("remaining projection temporal capture provenance refused")
	}
	groups := 0
	for _, observation := range missing.Observations {
		if observation.RuleID == "temporal72:trigger" {
			groups++
			if len(observation.Rows) != 2 {
				t.Fatal("remaining projection temporal alias count refused")
			}
		}
	}
	if groups != 1 {
		t.Fatal("remaining projection temporal source group missing/duplicate")
	}
	for _, wanted := range remainingFrameTemporal {
		aliasCount, referenceCount, objectCount := 0, 0, 0
		qualified, _ := json.Marshal([]string{wanted.relation, wanted.name})
		qualifiedOuter, _ := json.Marshal([]string{"temporal72:trigger", string(qualified)})
		for _, observation := range missing.Observations {
			if observation.RuleID == "temporal72:trigger" {
				for _, row := range observation.Rows {
					if row.Identity == wanted.capturedKey {
						aliasCount++
						if row.Fields != wanted.source {
							t.Fatal("remaining projection temporal source fact refused", wanted.name)
						}
					}
				}
			}
		}
		for _, row := range reference.Rows {
			if row.Kind == "trigger" && row.Identity == string(qualifiedOuter) {
				referenceCount++
				if row.Fact != wanted.pristine {
					t.Fatal("remaining projection temporal pristine reference refused", wanted.name)
				}
			}
		}
		for _, row := range catalog.Triggers {
			if row.Relation == wanted.relation && row.Name == wanted.name && row.Function == "public."+wanted.source.Function {
				objectCount++
			}
		}
		if aliasCount != 1 || referenceCount != 1 || objectCount != 1 {
			t.Fatal("remaining projection temporal source/reference/object cardinality refused", wanted.name, aliasCount, referenceCount, objectCount)
		}
	}
}

func remainingFrameObserveInstalled(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	const frameSQL = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),current_setting('transaction_read_only'),current_setting('transaction_isolation')`
	var before, pristine, source, restored, after [6]string
	if err := owner.QueryRow(ctx, frameSQL).Scan(&before[0], &before[1], &before[2], &before[3], &before[4], &before[5]); err != nil {
		t.Fatal("remaining projection installer frame unavailable", ordered62TraceClass(err))
	}
	var version, versionNum string
	if err := owner.QueryRow(ctx, `SELECT pg_catalog.version(),current_setting('server_version_num')`).Scan(&version, &versionNum); err != nil || version != transformAcceptancePostgres || versionNum != "180003" || before[0] != "zasp_test" || before[1] != "zasp_test" {
		t.Fatal("remaining projection owned PG18.3 identity refused", ordered62TraceClass(err))
	}
	installedHelpers := make([]map[string]any, 0, len(remainingFrameHelpers))
	for _, wanted := range remainingFrameHelpers {
		var config []string
		var definer bool
		var ownerName, acl, definition string
		if err := owner.QueryRow(ctx, `SELECT p.proconfig,p.prosecdef,p.proowner::regrole::text,COALESCE(p.proacl::text,''),pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure($1)`, wanted.identity).Scan(&config, &definer, &ownerName, &acl, &definition); err != nil {
			t.Fatal("remaining projection installed source helper unavailable", wanted.identity, ordered62TraceClass(err))
		}
		if !reflect.DeepEqual(config, []string{"search_path=pg_catalog, public"}) || definer != wanted.definer || ownerName != "zasp_discovery_authority" || acl != "{zasp_discovery_authority=X/zasp_discovery_authority}" {
			t.Fatal("remaining projection installed source helper frame altered", wanted.identity)
		}
		installedHelpers = append(installedHelpers, map[string]any{"identity": wanted.identity, "sourceSHA256": wanted.sourceSHA, "pinnedDefinitionSHA256": wanted.definitionSHA, "installedDefinitionSHA256": supplementSHA([]byte(definition)), "owner": ownerName, "acl": acl, "config": config, "securityDefiner": definer})
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("remaining projection read-only transaction unavailable", ordered62TraceClass(err))
	}
	active := true
	defer func() {
		if active {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer done()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("remaining projection rollback failed", ordered62TraceClass(err))
			}
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'; SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("remaining projection pristine frame unavailable", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&pristine[0], &pristine[1], &pristine[2], &pristine[3], &pristine[4], &pristine[5]); err != nil || pristine != [6]string{"zasp_test", "zasp_discovery_authority", "pg_catalog", "UTC", "on", "repeatable read"} {
		t.Fatal("remaining projection pristine frame refused", ordered62TraceClass(err))
	}
	pretty := make([]remainingFramePrettyObservation, 0, len(remainingFramePretty))
	temporal := make([]remainingFrameTemporalObservation, 0, len(remainingFrameTemporal))
	// Select exact public OIDs once. Neither field query uses a current result to
	// choose an expected identity, and each object must have cardinality one.
	for _, wanted := range remainingFramePretty {
		var oid uint32
		var count int
		var query string
		if wanted.rule == "worker-edge:ordered_projected28:9" {
			query = `SELECT count(*),min(t.oid::bigint)::oid FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND t.tgname=$2 AND NOT t.tgisinternal`
		} else {
			query = `SELECT count(*),min(k.oid::bigint)::oid FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND k.conname=$2`
		}
		if err := tx.QueryRow(ctx, query, wanted.relation[len("public."):], wanted.name).Scan(&count, &oid); err != nil || count != 1 {
			t.Fatal("remaining projection pretty OID missing/duplicate", wanted.name, count, ordered62TraceClass(err))
		}
		var text string
		if wanted.rule == "worker-edge:ordered_projected28:9" {
			err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_get_triggerdef($1::oid,true)`, oid).Scan(&text)
		} else {
			err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_get_constraintdef($1::oid,true)`, oid).Scan(&text)
		}
		if err != nil {
			t.Fatal("remaining projection pristine pretty deparse refused", wanted.name, ordered62TraceClass(err))
		}
		pretty = append(pretty, remainingFramePrettyObservation{Rule: wanted.rule, Relation: wanted.relation, Name: wanted.name, OID: oid, LiveOIDRows: count, CapturedSourceSHA: supplementSHA([]byte(wanted.sourceText)), PristineSHA: supplementSHA([]byte(text)), PristineText: text})
	}
	const temporalSQL = `SELECT c.relname::text,t.tgname::text,t.tgenabled::text,t.tgfoid::regprocedure::text,pg_catalog.regexp_replace(pg_catalog.pg_get_triggerdef(t.oid,true),E'\s+',' ','g') FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid WHERE t.oid=$1::oid`
	readTemporal := func(oid uint32) remainingFrameTriggerFact {
		var fact remainingFrameTriggerFact
		if err := tx.QueryRow(ctx, temporalSQL, oid).Scan(&fact.RelationName, &fact.Name, &fact.Enabled, &fact.Function, &fact.ExecutionDefinition); err != nil {
			t.Fatal("remaining projection temporal selected field refused", ordered62TraceClass(err))
		}
		return fact
	}
	for _, wanted := range remainingFrameTemporal {
		var oid uint32
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*),min(t.oid::bigint)::oid FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1 AND t.tgname=$2 AND NOT t.tgisinternal`, wanted.relation[len("public."):], wanted.name).Scan(&count, &oid); err != nil || count != 1 {
			t.Fatal("remaining projection temporal OID missing/duplicate", wanted.name, count, ordered62TraceClass(err))
		}
		qualified, _ := json.Marshal([]string{wanted.relation, wanted.name})
		temporal = append(temporal, remainingFrameTemporalObservation{Relation: wanted.relation, Name: wanted.name, OID: oid, LiveOIDRows: count, PinnedCapturedRows: 1, PinnedReferenceRows: 1, PinnedCatalogRows: 1, CapturedSourceKey: wanted.capturedKey, QualifiedReferenceKey: string(qualified), Pristine: readTemporal(oid)})
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog,public`); err != nil {
		t.Fatal("remaining projection original source frame unavailable", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&source[0], &source[1], &source[2], &source[3], &source[4], &source[5]); err != nil || source != [6]string{pristine[0], pristine[1], "pg_catalog, public", pristine[3], pristine[4], pristine[5]} {
		t.Fatal("remaining projection source frame refused", ordered62TraceClass(err))
	}
	for i, wanted := range remainingFramePretty {
		var text string
		if wanted.rule == "worker-edge:ordered_projected28:9" {
			err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_get_triggerdef($1::oid,true)`, pretty[i].OID).Scan(&text)
		} else {
			err = tx.QueryRow(ctx, `SELECT pg_catalog.pg_get_constraintdef($1::oid,true)`, pretty[i].OID).Scan(&text)
		}
		if err != nil {
			t.Fatal("remaining projection source pretty deparse refused", wanted.name, ordered62TraceClass(err))
		}
		pretty[i].SourceText = text
		pretty[i].SourceSHA = supplementSHA([]byte(text))
		pretty[i].SourceMatchesCapture = text == wanted.sourceText
	}
	for i, wanted := range remainingFrameTemporal {
		temporal[i].Source = readTemporal(temporal[i].OID)
		temporal[i].SourceMatchesCapture = temporal[i].Source == wanted.source
		temporal[i].PristineMatchesReference = temporal[i].Pristine == wanted.pristine
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog`); err != nil {
		t.Fatal("remaining projection pristine frame restore failed", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&restored[0], &restored[1], &restored[2], &restored[3], &restored[4], &restored[5]); err != nil || restored != pristine {
		t.Fatal("remaining projection pristine frame restoration refused", ordered62TraceClass(err))
	}
	cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = tx.Rollback(cleanup)
	done()
	active = false
	if err != nil {
		t.Fatal("remaining projection pristine rollback refused", ordered62TraceClass(err))
	}
	if err := owner.QueryRow(ctx, frameSQL).Scan(&after[0], &after[1], &after[2], &after[3], &after[4], &after[5]); err != nil || before != after {
		t.Fatal("remaining projection installer frame restoration refused", ordered62TraceClass(err))
	}
	evidence := map[string]any{
		"scope": "owned-remaining-projection-frame-diagnostic-only", "catalogSHA256": remainingFrameCatalogSHA,
		"contractSHA256": remainingFrameContractSHA, "directCaptureSHA256": remainingFrameDirectSHA,
		"missingCaptureSHA256": remainingFrameMissingSHA, "pristineReferenceSHA256": remainingFrameReferenceSHA,
		"postgres": version, "serverVersionNum": versionNum, "installerFrame": before, "pristineFrame": pristine,
		"sourceFrame": source, "restoredOuterFrame": restored, "afterRollbackFrame": after, "rolledBack": true,
		"frameRestored": before == after, "helperExecution": "none; invoker and definer metadata observed under their pinned owner role only",
		"installedHelpers": installedHelpers, "pretty": pretty, "temporal": temporal,
	}
	raw, err := json.Marshal(evidence)
	if err != nil || len(raw) > 32*1024 {
		t.Fatal("remaining projection bounded evidence refused")
	}
	t.Log("remaining-projection-frame", string(raw))
	for _, row := range pretty {
		if !row.SourceMatchesCapture {
			t.Error("remaining projection source pretty differs from independent capture", row.Relation, row.Name)
		}
	}
	for _, row := range temporal {
		if !row.SourceMatchesCapture || !row.PristineMatchesReference {
			t.Error("remaining projection temporal five-field capture differs", row.Relation, row.Name)
		}
	}
}
