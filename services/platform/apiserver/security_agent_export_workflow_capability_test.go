package apiserver

import (
	"context"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type exportDefinitionCapability interface {
	SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error)
}

type exportWorkflowCapabilityDriver struct {
	databaseDriver
	installed, ready, fail bool
	queries                int
}

func (d *exportWorkflowCapabilityDriver) QueryRow(_ context.Context, query string, args ...any) PostgresRow {
	d.queries++
	switch query {
	case `SELECT to_regprocedure('public.zasp_sa_export_workflow_readiness(text,text)') IS NOT NULL`:
		return exportCapabilityRow{value: d.installed, fail: d.fail || len(args) != 0}
	case `SELECT public.zasp_sa_export_workflow_readiness($1,$2)`:
		if len(args) != 2 || args[0] != migrations.ProductionSecurityAgentExports().Checksum() || args[1] != migrations.SecurityAgentExportsFingerprint() {
			return exportCapabilityRow{fail: true}
		}
		return exportCapabilityRow{value: d.ready, fail: d.fail}
	default:
		return exportCapabilityRow{fail: true}
	}
}

// Settlement-only installation must never stand in for public workflow
// admission. The real database adapter must query the dedicated pinned gate.
func TestSecurityAgentExportDefinitionsRequireAdmissionRelease(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		installed, ready, fail, want, wantErr bool
	}{
		{"absent", false, true, false, false, false},
		{"installed", true, true, false, true, false},
		{"drift", true, false, false, false, true},
		{"outage", true, true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &exportWorkflowCapabilityDriver{installed: tc.installed, ready: tc.ready, fail: tc.fail}
			db, err := NewPostgresJSONDatabase(d)
			if err != nil {
				t.Fatal(err)
			}
			capability, ok := any(db).(exportDefinitionCapability)
			if !ok {
				t.Fatal("public export admission capability missing")
			}
			got, err := capability.SecurityAgentExportDefinitionsAvailable(context.Background())
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("ready=%v error=%v", got, err)
			}
			calls := 1
			if tc.installed && !tc.fail {
				calls = 2
			}
			if d.queries != calls {
				t.Fatalf("unexpected probes=%d", d.queries)
			}
			if got, err := capability.SecurityAgentExportDefinitionsAvailable(nil); got || err == nil || d.queries != calls {
				t.Fatal("nil context reached database")
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if got, err := capability.SecurityAgentExportDefinitionsAvailable(cancelled); got || err == nil || d.queries != calls {
				t.Fatal("cancelled context reached database")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err := capability.SecurityAgentExportDefinitionsAvailable(context.Background()); got || err == nil || d.queries != calls {
				t.Fatal("closed database accepted")
			}
		})
	}
}
