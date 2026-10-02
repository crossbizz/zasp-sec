package apiserver

import (
	"context"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

type exportCapability interface {
	SecurityAgentExportsAvailable(context.Context) (bool, error)
}
type exportCapabilityDriver struct {
	databaseDriver
	installed, ready bool
	fail             bool
	statements       []string
	args             [][]any
}

func (d *exportCapabilityDriver) QueryRow(_ context.Context, s string, args ...any) PostgresRow {
	d.statements = append(d.statements, s)
	d.args = append(d.args, args)
	value := d.ready
	if s == `SELECT to_regprocedure('public.zasp_sa_export_readiness(text,text)') IS NOT NULL` {
		value = d.installed
	}
	return exportCapabilityRow{value: value, fail: d.fail}
}

type exportCapabilityRow struct{ value, fail bool }

func (r exportCapabilityRow) Scan(dest ...any) error {
	if r.fail {
		return errors.New("probe failed")
	}
	if len(dest) != 1 {
		return errors.New("wrong destinations")
	}
	p, ok := dest[0].(*bool)
	if !ok {
		return errors.New("wrong type")
	}
	*p = r.value
	return nil
}

func TestSecurityAgentExportCapabilityReleaseChecks(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		installed, ready, fail, want, wantErr bool
	}{
		{"absent", false, false, false, false, false}, {"ready", true, true, false, true, false}, {"drift", true, false, false, false, true}, {"outage", true, true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver := &exportCapabilityDriver{installed: tc.installed, ready: tc.ready, fail: tc.fail}
			db, err := NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			repository := &SecurityAgentWorkerRepository{database: db}
			capability, ok := any(repository).(exportCapability)
			if !ok {
				t.Fatal("production worker lacks export capability adapter")
			}
			got, err := capability.SecurityAgentExportsAvailable(context.Background())
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("capability=%t error=%v", got, err)
			}
			wantCalls := 1
			if tc.installed && !tc.fail {
				wantCalls = 2
			}
			if len(driver.statements) != wantCalls {
				t.Fatalf("unexpected SQL calls %v", driver.statements)
			}
			if wantCalls == 2 && (driver.statements[1] != `SELECT public.zasp_sa_export_readiness($1,$2)` || len(driver.args[1]) != 2 || driver.args[1][0] != migrations.ProductionSecurityAgentExports().Checksum() || driver.args[1][1] != migrations.SecurityAgentExportsFingerprint()) {
				t.Fatal("exact compiled release readiness not checked")
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err = capability.SecurityAgentExportsAvailable(context.Background()); got || err == nil {
				t.Fatal("closed database accepted")
			}
		})
	}
}
