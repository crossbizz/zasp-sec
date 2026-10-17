package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// These are application metadata readers, never provider or native acceptance.
type exposureMetadataDriver struct {
	original  *authorizationRoutingDriver
	rows      []authorizationRoutingRecord
	riskCalls int
	riskError error
	t         *testing.T
	pin       string
}

func (d *exposureMetadataDriver) QueryRow(ctx context.Context, q string, a ...any) PostgresRow {
	if q != postgresAgentExposureRiskSQL {
		return d.original.QueryRow(ctx, q, a...)
	}
	d.riskCalls++
	if len(a) != 4 || a[3] != d.pin {
		d.t.Fatal("risk metadata lost fixed compiled profile")
	}
	return authorizationRoutingRow(func(v ...any) error {
		if d.riskError != nil {
			return d.riskError
		}
		raw, e := json.Marshal(d.rows)
		if e != nil {
			return e
		}
		*v[0].(*[]byte) = raw
		return nil
	})
}
func (*exposureMetadataDriver) Exec(context.Context, string, ...any) error { return nil }
func (*exposureMetadataDriver) Close() error                               { return nil }

// Successor source coverage after the initial API attempt was setup blocked.
func TestAgentExposureRiskResolverKeepsCompleteScopedMetadataAndClosedComposition(t *testing.T) {
	for _, mode := range []string{"normal", "audit", "no_risk", "empty_findings", "foreign_scope", "wrong_kind", "duplicate_finding", "invalid_source", "over_limit", "metadata_refused", "wrong_database", "nested_wrapper", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			i := fixtureRequestIdentity(t)
			agent := authorizationRoutingRecordFor(i, "agent", "pid_91000001-0000-4000-8000-000000000001", 4)
			finding := authorizationRoutingRecordFor(i, "finding", "pid_91000002-0000-4000-8000-000000000002", 7)
			pin := migrations.AgentExposureFilterProfileChecksum()
			if mode == "audit" {
				pin = migrations.AgentExposureFilterAuditProfileChecksum()
			}
			driver := &exposureMetadataDriver{t: t, pin: pin, original: &authorizationRoutingDriver{t: t, rows: map[string][]authorizationRoutingRecord{"agent": {agent}}, err: map[string]error{}}, rows: []authorizationRoutingRecord{finding}}
			db := &PostgresJSONDatabase{driver: driver, currentAuthorization: true}
			original, _ := NewPostgresAuthorizationResolver(db)
			switch mode {
			case "empty_findings":
				driver.rows = []authorizationRoutingRecord{}
			case "foreign_scope":
				driver.rows[0].Environment = "pid_91000003-0000-4000-8000-000000000003"
			case "wrong_kind":
				driver.rows[0].Kind = "agent"
			case "duplicate_finding":
				driver.rows = append(driver.rows, finding)
			case "invalid_source":
				driver.rows[0].SourceID = "unbound"
			case "over_limit":
				driver.rows = make([]authorizationRoutingRecord, 10000)
				for n := range driver.rows {
					driver.rows[n] = finding
				}
			case "metadata_refused":
				driver.riskError = errors.New("private provider detail")
			}
			selected, err := NewAgentExposureFilterResolver(original, db, pin)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wrong_database" {
				if _, e := NewAgentExposureFilterResolver(original, &PostgresJSONDatabase{}, pin); e == nil {
					t.Fatal("cross-database resolver admitted")
				}
				return
			}
			if mode == "nested_wrapper" {
				if _, e := NewAgentExposureFilterResolver(selected, db, pin); e == nil {
					t.Fatal("recursive resolver admitted")
				}
				return
			}
			query := url.Values{"risk": {"high"}}
			if mode == "no_risk" {
				query = url.Values{"execution": {"shell"}}
			}
			ctx := context.WithValue(context.Background(), authorizationQueryContextKey{}, query)
			if mode == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			result, err := selected.ResolveAuthorization(ctx, i, RoutedOperation{OperationID: "listAgents"})
			accepted := mode == "normal" || mode == "audit" || mode == "no_risk" || mode == "empty_findings"
			if !accepted {
				if err == nil {
					t.Fatal("unbound or partial metadata admitted")
				}
				return
			}
			want := 2
			if mode == "no_risk" || mode == "empty_findings" {
				want = 1
			}
			if err != nil || !result.Complete || !result.Collection || len(result.Targets) != want {
				t.Fatal("complete scoped candidate union lost", err)
			}
			if mode == "no_risk" && driver.riskCalls != 0 || mode != "no_risk" && driver.riskCalls != 1 {
				t.Fatal("risk-only metadata selection lost")
			}
			snapshot, ok := postLoginSnapshotResolver(selected)
			if !ok || snapshot != original {
				t.Fatal("known decorator lost actual snapshot database")
			}
		})
	}
}
