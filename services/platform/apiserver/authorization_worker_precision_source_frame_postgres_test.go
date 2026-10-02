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

const precisionFrameCatalogSHA = "b13f25c70ac824e0b3db36969cd5a6a71953e6dc15ba3f269de2520134aae077"
const precisionFrameHelper = "zasp_temporal72.retained_precision_fingerprint()"

// These names and definition hashes were read from the approved final pinned
// effective-catalog1, not a native target, live OID spelling, or collector output.
var precisionFrameGuards = []struct{ signature, definitionSHA string }{
	{"zasp_runtime_precision_batch_insert_guard()", "04643b3ea72959d2550840df235efe7c596e80b383d0033a4f875cb0baec4b02"},
	{"zasp_runtime_precision_batch_update_guard()", "110c1af754d765c712fe89234ac2215df22e3c64a9aa8ac7db5213ae309c394f"},
	{"zasp_runtime_precision_claim_version_guard()", "76b72152be0a7617c6dfb5f2c37d4e012d0bf2249a7447eae55ea18b96492955"},
	{"zasp_runtime_precision_delivery_guard()", "861a9d2e31077953e5984c48c21dc375fd7bbe249de1d093b6225cc61c29aca6"},
	{"zasp_runtime_precision_outbox_guard()", "fbb7860449458cd66cecc205623430d68a73cfd498cc0221573d5e0f1002620d"},
	{"zasp_runtime_precision_reconciliation_guard()", "b4e16e4f3ac2c0af635e8a5ad5b269b127a425005887aeb74f5a43de5a4641f2"},
	{"zasp_runtime_precision_stage_insert_guard()", "8985c68337992bf5a3cf671438cfe9982ed7f8149677c7fa13561a08ea03cfa7"},
}

type precisionFrameObservation struct {
	SourceIdentity      string  `json:"sourceIdentity"`
	OID                 uint32  `json:"oid"`
	SavedKey            string  `json:"savedKey"`
	SavedDefinitionSHA  string  `json:"savedDefinitionSHA256"`
	SavedOwner          string  `json:"savedOwner"`
	SavedACL            string  `json:"savedACL"`
	PinnedDefinitionSHA string  `json:"pinnedDefinitionSHA256"`
	PinnedKeyMatches    bool    `json:"pinnedKeyMatches"`
	OuterLookupSHA      *string `json:"pgCatalogLookupSHA256"`
	SourceLookupSHA     *string `json:"sourceFrameLookupSHA256"`
}

// Break caught: lowering the retained precision collector's scalar predecessor
// lookup into pg_catalog only loses unqualified saved guard keys. This is the
// product's installed projection boundary, not Temporal/OpenFGA behavior.
// Root owns the opt-in PostgreSQL run and cleanup proof; compile/skip isn't RED.
func TestP7PrecisionPredecessorSourceFrame(t *testing.T) {
	switch os.Getenv("ZASP_ORDERED_CURRENT_PRECISION_FRAME_PROBE") {
	case "":
		t.Skip("explicit owned precision source-frame probe required")
	case "1":
	default:
		t.Fatal("precision source-frame probe mode refused")
	}
	for _, key := range []string{
		"ZASP_ORDERED_CURRENT_NATIVE379", "ZASP_ORDERED_PRIVATE_SUCCESSOR_CAPTURE",
		"ZASP_ORDERED_MISSING_REFERENCE_NATIVE", "ZASP_ORDERED_PREDECESSOR_CAPTURE",
		"ZASP_ORDERED_PREDECESSOR_RELEASE", "ZASP_ORDERED_PREDECESSOR_CATALOG_OUTPUT",
		"ZASP_ORDERED_SUPPLEMENT_CAPTURE", "ZASP_ORDERED_READINESS_ATTRIBUTION",
		"ZASP_ORDERED_READINESS_CAPTURE", "ZASP_ORDERED_POLICY_CAPACITY",
		"ZASP_ORDERED_POLICY_PREFIX", "ZASP_P7_ORDERED69_RETIREMENT_ACL",
		"ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "ZASP_P7_ORDERED_BODY_CAPTURE",
		"ZASP_ORDERED62_FUNCTION_TIMING", "ZASP_ORDERED_POLICY_FUNCTION_TIMING",
		"ZASP_ORDERED_POLICY_FUNCTION_CAPTURE", "ZASP_ORDERED_POLICY_TRACE",
	} {
		if os.Getenv(key) != "" {
			t.Fatalf("precision source-frame probe overlaps %s", key)
		}
	}
	precisionFrameVerifyPinnedBaseline(t)
	consumed := false
	runOrdered68PolicyAcceptanceWithCatalogCapture(t, false, false, false, func(t *testing.T, ctx context.Context, owner *pgx.Conn) bool {
		consumed = true
		precisionFrameObserveInstalled(t, ctx, owner)
		return true // Never fall through to checked approval, FGA, or effects.
	}, nil)
	if !consumed {
		t.Fatal("owned precision installation callback not reached")
	}
}

func precisionFrameVerifyPinnedBaseline(t *testing.T) {
	t.Helper()
	path := filepath.Join(orderedCurrentNative379Root(), ".superpowers", "sdd", "2026-09-22-temporal-openfga-execution-plan", "p7-worker-enforcement", "ordered-current-effective-catalog1.json")
	raw, err := readOrderedSupplementFile(path, 32*1024*1024)
	if err != nil || supplementSHA(raw) != precisionFrameCatalogSHA {
		t.Fatal("precision pinned final catalog unavailable or changed")
	}
	var catalog struct {
		Saved []struct {
			Schema, Signature, Definition, Owner, ACL string
		} `json:"saved_functions"`
		Functions []struct {
			Identity        string
			Config          []string
			SecurityDefiner bool `json:"security_definer"`
		} `json:"functions"`
	}
	if json.Unmarshal(raw, &catalog) != nil {
		t.Fatal("precision pinned catalog shape refused")
	}
	for _, guard := range precisionFrameGuards {
		count := 0
		for _, saved := range catalog.Saved {
			if saved.Schema == "zasp_authorization80_runtime" && (saved.Signature == guard.signature || saved.Signature == "public."+guard.signature) {
				count++
				if saved.Signature != guard.signature || saved.Definition == "" || supplementSHA([]byte(saved.Definition)) != guard.definitionSHA || saved.Owner != "zasp_discovery_authority" || saved.ACL != "{zasp_discovery_authority=X/zasp_discovery_authority}" {
					t.Fatal("precision pinned saved guard definition refused", guard.signature)
				}
			}
		}
		if count != 1 {
			t.Fatal("precision pinned saved guard missing/duplicate", guard.signature, count)
		}
	}
	helperCount := 0
	for _, helper := range catalog.Functions {
		if helper.Identity == precisionFrameHelper {
			helperCount++
			if helper.SecurityDefiner || !reflect.DeepEqual(helper.Config, []string{"search_path=pg_catalog, public"}) {
				t.Fatal("precision pinned source helper frame refused")
			}
		}
	}
	if helperCount != 1 {
		t.Fatal("precision pinned source helper missing/duplicate")
	}
}

func precisionFrameObserveInstalled(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	const frameSQL = `SELECT session_user,current_user,current_setting('search_path'),current_setting('TimeZone'),current_setting('transaction_read_only'),current_setting('transaction_isolation')`
	var before, pristine, source, restored, after [6]string
	if err := owner.QueryRow(ctx, frameSQL).Scan(&before[0], &before[1], &before[2], &before[3], &before[4], &before[5]); err != nil {
		t.Fatal("precision installer frame unavailable", ordered62TraceClass(err))
	}
	var version, versionNum string
	if err := owner.QueryRow(ctx, `SELECT pg_catalog.version(),current_setting('server_version_num')`).Scan(&version, &versionNum); err != nil || version != transformAcceptancePostgres || versionNum != "180003" || before[0] != "zasp_test" || before[1] != "zasp_test" {
		t.Fatal("precision owned PG18.3 installer identity refused", ordered62TraceClass(err))
	}
	var helperConfig []string
	var helperDefiner bool
	var helperOwner, helperACL, helperDefinition string
	if err := owner.QueryRow(ctx, `SELECT p.proconfig,p.prosecdef,p.proowner::regrole::text,COALESCE(p.proacl::text,''),pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure($1)`, precisionFrameHelper).Scan(&helperConfig, &helperDefiner, &helperOwner, &helperACL, &helperDefinition); err != nil {
		t.Fatal("precision installed source helper unavailable", ordered62TraceClass(err))
	}
	if helperDefiner || !reflect.DeepEqual(helperConfig, []string{"search_path=pg_catalog, public"}) {
		t.Fatal("precision installed source helper frame altered")
	}
	observations := make([]precisionFrameObservation, 0, 7)
	for _, guard := range precisionFrameGuards {
		rows, err := owner.Query(ctx, `SELECT p.oid,s.signature,s.definition,s.owner_name,s.acl FROM pg_catalog.pg_proc p JOIN zasp_authorization80_runtime.predecessor_functions s ON s.signature=$1 OR s.signature='public.'||$1 WHERE p.oid=pg_catalog.to_regprocedure('public.'||$1)`, guard.signature)
		if err != nil {
			t.Fatal("precision installed saved guard unavailable", ordered62TraceClass(err))
		}
		count := 0
		var observation precisionFrameObservation
		for rows.Next() {
			count++
			var definition *string
			if err := rows.Scan(&observation.OID, &observation.SavedKey, &definition, &observation.SavedOwner, &observation.SavedACL); err != nil {
				rows.Close()
				t.Fatal("precision installed saved guard scan refused", ordered62TraceClass(err))
			}
			if definition == nil || *definition == "" {
				rows.Close()
				t.Fatal("precision installed saved guard definition missing", guard.signature)
			}
			observation.SavedDefinitionSHA = supplementSHA([]byte(*definition))
		}
		streamErr := rows.Err()
		rows.Close()
		if streamErr != nil || count != 1 {
			t.Fatal("precision installed saved guard missing/duplicate", guard.signature, count, ordered62TraceClass(streamErr))
		}
		observation.SourceIdentity = "public." + guard.signature
		observation.PinnedDefinitionSHA = guard.definitionSHA
		observation.PinnedKeyMatches = observation.SavedKey == guard.signature
		observations = append(observations, observation)
	}
	tx, err := owner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("precision pristine transaction unavailable", ordered62TraceClass(err))
	}
	active := true
	defer func() {
		if active {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer done()
			if err := tx.Rollback(cleanup); err != nil {
				t.Error("precision rollback failed", ordered62TraceClass(err))
			}
		}
	}()
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SET LOCAL search_path=pg_catalog; SET LOCAL TimeZone='UTC'; SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		t.Fatal("precision pristine frame unavailable", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&pristine[0], &pristine[1], &pristine[2], &pristine[3], &pristine[4], &pristine[5]); err != nil || pristine != [6]string{"zasp_test", "zasp_discovery_authority", "pg_catalog", "UTC", "on", "repeatable read"} {
		t.Fatal("precision pristine native role/frame refused", ordered62TraceClass(err))
	}
	// Exact scalar predecessor lookup used by development-collector.sql. Public
	// source OIDs are selected separately, so this doesn't assume saved key spelling.
	const scalarSQL = `SELECT (SELECT definition FROM zasp_authorization80_runtime.predecessor_functions WHERE pg_catalog.to_regprocedure(signature)=p.oid) FROM pg_catalog.pg_proc p WHERE p.oid=$1::oid`
	lookup := func(oid uint32) *string {
		var definition *string
		if err := tx.QueryRow(ctx, scalarSQL, oid).Scan(&definition); err != nil {
			t.Fatal("precision collector scalar lookup refused", ordered62TraceClass(err))
		}
		if definition == nil {
			return nil
		}
		digest := supplementSHA([]byte(*definition))
		return &digest
	}
	for i := range observations {
		observations[i].OuterLookupSHA = lookup(observations[i].OID)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog,public`); err != nil {
		t.Fatal("precision original source frame unavailable", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&source[0], &source[1], &source[2], &source[3], &source[4], &source[5]); err != nil || source != [6]string{pristine[0], pristine[1], "pg_catalog, public", pristine[3], pristine[4], pristine[5]} {
		t.Fatal("precision source frame changed other settings", ordered62TraceClass(err))
	}
	for i := range observations {
		observations[i].SourceLookupSHA = lookup(observations[i].OID)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog`); err != nil {
		t.Fatal("precision outer frame restore failed", ordered62TraceClass(err))
	}
	if err := tx.QueryRow(ctx, frameSQL).Scan(&restored[0], &restored[1], &restored[2], &restored[3], &restored[4], &restored[5]); err != nil || restored != pristine {
		t.Fatal("precision outer frame restoration refused", ordered62TraceClass(err))
	}
	cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	err = tx.Rollback(cleanup)
	done()
	active = false
	if err != nil {
		t.Fatal("precision pristine rollback refused", ordered62TraceClass(err))
	}
	if err := owner.QueryRow(ctx, frameSQL).Scan(&after[0], &after[1], &after[2], &after[3], &after[4], &after[5]); err != nil || before != after {
		t.Fatal("precision installer frame restoration refused", ordered62TraceClass(err))
	}
	qualified, unqualified, transitions, reverseTransitions, keyDifferences := 0, 0, 0, 0, 0
	for _, observed := range observations {
		if strings.HasPrefix(observed.SavedKey, "public.") {
			qualified++
		} else {
			unqualified++
		}
		if !observed.PinnedKeyMatches {
			keyDifferences++
		}
		if observed.OuterLookupSHA == nil && observed.SourceLookupSHA != nil {
			transitions++
		}
		if observed.OuterLookupSHA != nil && observed.SourceLookupSHA == nil {
			reverseTransitions++
		}
		if observed.OuterLookupSHA != nil && *observed.OuterLookupSHA != observed.PinnedDefinitionSHA {
			t.Error("precision non-NULL outer lookup differs from pinned predecessor", observed.SourceIdentity)
		}
		if observed.SavedDefinitionSHA != observed.PinnedDefinitionSHA || observed.SourceLookupSHA == nil || *observed.SourceLookupSHA != observed.PinnedDefinitionSHA || observed.SavedOwner != "zasp_discovery_authority" || observed.SavedACL != "{zasp_discovery_authority=X/zasp_discovery_authority}" {
			t.Error("precision source-frame saved predecessor differs from pinned definition/owner/ACL", observed.SourceIdentity)
		}
	}
	evidence := map[string]any{
		"scope": "owned-precision-scalar-source-frame-diagnostic-only", "catalogSHA256": precisionFrameCatalogSHA,
		"postgres": version, "serverVersionNum": versionNum, "installerFrame": before,
		"pristineFrame": pristine, "sourceFrame": source, "restoredOuterFrame": restored,
		"afterRollbackFrame": after, "rolledBack": true, "frameRestored": before == after,
		"helperIdentity": precisionFrameHelper, "helperConfig": helperConfig, "helperSecurityInvoker": !helperDefiner,
		"helperOwner": helperOwner, "helperACL": helperACL, "helperDefinitionSHA256": supplementSHA([]byte(helperDefinition)),
		"qualifiedKeys": qualified, "unqualifiedKeys": unqualified, "keysDifferentFromPinned": keyDifferences,
		"nullToValueTransitions": transitions, "valueToNullTransitions": reverseTransitions, "guards": observations,
	}
	raw, err := json.Marshal(evidence)
	if err != nil || len(raw) > 32*1024 {
		t.Fatal("precision bounded evidence refused")
	}
	t.Log("precision-source-frame", string(raw))
	if keyDifferences > 0 && transitions == 0 {
		t.Log("actual fixture saved keys differ from pinned spelling; no NULL transitions observed")
	}
}
