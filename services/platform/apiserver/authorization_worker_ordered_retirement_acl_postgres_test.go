package apiserver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// This installer-only RED isolates the four raw execution capabilities. It
// does not call raw bodies with fabricated requests or repeat the accepted
// real settled-Test producer. Named settled recovery is a separate prerequisite.
func TestP7Ordered69RetirementInstalledACL(t *testing.T) {
	if os.Getenv("ZASP_ORDERED_READINESS_CAPTURE") != "" || os.Getenv("ZASP_ORDERED_READINESS_ATTRIBUTION") != "" {
		t.Fatal("raw69 ACL fixture cannot be combined with catalog capture or attribution")
	}
	t.Setenv("ZASP_P7_ORDERED69_RETIREMENT_ACL", "1")
	runOrdered68PolicyBoundary(t, true, false, false)
}

func TestP7Ordered69RetirementACLWithAttribution(t *testing.T) {
	t.Setenv("ZASP_P7_ORDERED69_RETIREMENT_ACL", "1")
	t.Setenv("ZASP_P7_ORDERED69_RETIREMENT_WITH_ATTRIBUTION", "1")
	t.Setenv("ZASP_ORDERED_READINESS_ATTRIBUTION", "1")
	runOrdered68PolicyBoundary(t, true, false, false)
}

// Mode2 is the only allowed combination. The parent must finish synchronous
// attribution first, then run all four ACL assertions before returning.
func ordered69RetirementCatalogMode(acl, combined, attribution, capture string) (int, bool) {
	if acl == "" && combined == "" {
		return 0, true // Leave unrelated existing catalog modes unchanged.
	}
	if acl != "1" || capture != "" {
		return 0, false
	}
	if combined == "" && attribution == "" {
		return 1, true
	}
	if combined == "1" && attribution == "1" {
		return 2, true
	}
	return 0, false
}

func TestOrdered69RetirementCatalogMode(t *testing.T) {
	for _, tc := range []struct {
		acl, combined, attribution, capture string
		mode                                int
		valid                               bool
	}{
		{"", "", "", "", 0, true},
		{"", "", "1", "", 0, true},
		{"", "", "", "existing-capture", 0, true},
		{"1", "", "", "", 1, true},
		{"1", "1", "1", "", 2, true},
		{"1", "", "1", "", 0, false},
		{"1", "1", "", "", 0, false},
		{"", "1", "1", "", 0, false},
		{"1", "1", "1", "capture", 0, false},
		{"1", "", "", "capture", 0, false},
		{"2", "", "", "", 0, false},
		{"1", "2", "1", "", 0, false},
		{"1", "1", "2", "", 0, false},
	} {
		mode, valid := ordered69RetirementCatalogMode(tc.acl, tc.combined, tc.attribution, tc.capture)
		if mode != tc.mode || valid != tc.valid {
			t.Fatalf("catalog mode input=%+v got=%d/%t", tc, mode, valid)
		}
	}
}

func assertOrdered69InstalledRetirementIfRequested(t *testing.T, ctx context.Context, owner, executor *pgx.Conn) bool {
	t.Helper()
	mode := os.Getenv("ZASP_P7_ORDERED69_RETIREMENT_ACL")
	if mode == "" {
		return false
	}
	if mode != "1" {
		t.Fatal("invalid raw69 retirement ACL fixture mode")
	}
	// Observation only: the installer has already checked its compiled pin.
	// This read is not an independent compiler artifact or upgrade allowlist.
	metadataCtx, metadataDone := context.WithTimeout(ctx, 10*time.Second)
	var registrations int
	var checksum, fingerprint string
	var validHashes bool
	metadataErr := owner.QueryRow(metadataCtx, `SELECT count(*),COALESCE(min(checksum),''),COALESCE(min(fingerprint),''),COALESCE(bool_and(checksum ~ '^[0-9a-f]{64}$' AND fingerprint ~ '^[0-9a-f]{64}$'),false) FROM zasp_authorization80_worker.registration`).Scan(&registrations, &checksum, &fingerprint, &validHashes)
	metadataLive := metadataCtx.Err() == nil
	metadataDone()
	if metadataErr != nil || !metadataLive || registrations != 1 || !validHashes {
		t.Fatal("raw69 observed registration metadata invalid", ordered68ErrorClass(metadataErr))
	}
	t.Logf("raw69 OBSERVED installed registration checksum=%s fingerprint=%s", checksum, fingerprint)
	config := owner.Config().Copy()
	config.User = "temporal_compensation_test_login"
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	compensation, err := pgx.ConnectConfig(connectCtx, config)
	cancel()
	if err != nil {
		t.Fatal("raw69 ACL registered compensation connection", ordered68ErrorClass(err))
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer done()
		if err := compensation.Close(cleanup); err != nil {
			t.Error("raw69 ACL compensation close", ordered68ErrorClass(err))
		}
	}()
	checked := 0
	for _, principal := range []struct {
		conn             *pgx.Conn
		role, secondEdge string
	}{
		{executor, "zasp_temporal_executor", "zasp_temporal69.inspect_message(jsonb)"},
		{compensation, "zasp_temporal_compensation", "zasp_temporal69.stop(jsonb)"},
	} {
		// These are actual registered login sessions, not SET ROLE or owner
		// catalog inspection. Keep both callable metadata gates and USAGE.
		callCtx, done := context.WithTimeout(ctx, 10*time.Second)
		var retained bool
		err := principal.conn.QueryRow(callCtx, `SELECT session_user=$1 AND current_user=session_user AND pg_has_role(session_user,$2,'USAGE') AND has_schema_privilege(session_user,'zasp_temporal69','USAGE') AND has_function_privilege(session_user,'zasp_temporal69.ready(text,text)','EXECUTE') AND has_function_privilege(session_user,'zasp_temporal69.principal_ready(text)','EXECUTE') AND zasp_temporal69.ready($3,$4) AND zasp_temporal69.principal_ready($2)`, principal.conn.Config().User, principal.role, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint()).Scan(&retained)
		live := callCtx.Err() == nil
		done()
		if err != nil || !live || !retained {
			t.Errorf("raw69 retained access prerequisite failed: role=%s live=%t retained=%t class=%s", principal.role, live, retained, ordered68ErrorClass(err))
			continue
		}
		t.Logf("raw69 retained access positive: role=%s schema_usage=true ready=true principal=true", principal.role)
		for _, signature := range []string{"zasp_temporal69.inspect(jsonb)", principal.secondEdge} {
			probeCtx, end := context.WithTimeout(ctx, 10*time.Second)
			var granted bool
			err := principal.conn.QueryRow(probeCtx, `SELECT has_function_privilege(session_user,$1,'EXECUTE')`, signature).Scan(&granted)
			live := probeCtx.Err() == nil
			end()
			if err != nil || !live {
				t.Errorf("raw69 ACL probe failed: role=%s function=%s live=%t class=%s", principal.role, signature, live, ordered68ErrorClass(err))
				continue
			}
			checked++
			// Errorf intentionally collects all four live ACL failures. A
			// function body's own42501 is not evidence of grant retirement.
			if granted {
				t.Errorf("raw69 retirement EXECUTE edge remains: role=%s function=%s granted=true", principal.role, signature)
			} else {
				t.Logf("raw69 retirement EXECUTE absent: role=%s function=%s", principal.role, signature)
			}
		}
	}
	if checked != 4 {
		t.Errorf("raw69 ACL group incomplete: checked=%d want=4; prerequisite/query failure is not retirement RED", checked)
	}
	t.Logf("raw69 ACL group completed: checked=%d", checked)
	return true
}
