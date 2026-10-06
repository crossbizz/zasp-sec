package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The original refusal characterization is retained in the SDD evidence packet.
// This regression now requires the real wrapper to reach the closed typed route.
func TestP7OrderedReadinessRoutingCharacterization(t *testing.T) {
	for _, current := range []bool{true, false} {
		name := "noncurrent exact release control"
		if current {
			name = "current typed release without actor proof"
		}
		t.Run(name, func(t *testing.T) {
			// Compute independent expected pins before the caller deadline starts.
			driver := &orderedRoutingCharacterizationDriver{
				t: t, current: current,
				expectedPublicChecksum:    migrations.ProductionSecurityAgentPublic().Checksum(),
				expectedPublicFingerprint: migrations.SecurityAgentPublicFingerprint(),
			}
			if current {
				driver.expectedAuthorizationChecksum = migrations.ProductionAuthorizationEnforcement().Checksum()
			}
			database, err := apiserver.NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := database.Close(); err != nil {
					t.Error(err)
				}
			})
			if current {
				if err := database.RequireCurrentAuthorization(); err != nil {
					t.Fatal(err)
				}
			}
			traced := &tracedJSONDatabase{next: database, metrics: newOperationalMetrics(), exporter: newStructuredSpanExporter(io.Discard)}
			if traced.CurrentAuthorizationRequired() != current {
				t.Fatal("wrapper lost current authorization mode")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = traced.VerifySecurityAgentOrderedHTTPRelease(ctx)
			wantQueries := 1
			if err != nil {
				t.Fatalf("exact installed release probe refused: %v", err)
			}
			if driver.queries != wantQueries || driver.begins != 0 || driver.execs != 0 {
				t.Fatalf("driver IO query=%d begin=%d exec=%d; want query=%d begin=0 exec=0", driver.queries, driver.begins, driver.execs, wantQueries)
			}
			t.Logf("current=%t refused=%t QueryRow=%d Begin=%d Exec=%d", current, err != nil, driver.queries, driver.begins, driver.execs)
		})
	}
}

type orderedRoutingCharacterizationDriver struct {
	t                             *testing.T
	current                       bool
	queries, begins, execs        int
	expectedAuthorizationChecksum string
	expectedPublicChecksum        string
	expectedPublicFingerprint     string
}

var _ apiserver.AuthorizationTransactionDriver = (*orderedRoutingCharacterizationDriver)(nil)

func (d *orderedRoutingCharacterizationDriver) QueryRow(ctx context.Context, statement string, args ...any) apiserver.PostgresRow {
	d.queries++
	if d.current {
		if statement != `SELECT zasp_authorization80.ready($1), zasp_ordered_public62.api($2,$3,'{"operation":"deployment_ready"}'::jsonb)` || len(args) != 3 || args[0] != d.expectedAuthorizationChecksum || args[1] != d.expectedPublicChecksum || args[2] != d.expectedPublicFingerprint {
			d.t.Error("wrong closed current release statement or compiled pins")
			return orderedRoutingCharacterizationRow{err: errors.New("unexpected current release binding")}
		}
		if deadline, ok := ctx.Deadline(); !ok || ctx.Err() != nil || time.Until(deadline) > 5*time.Second {
			d.t.Error("missing, expired or excessive release deadline")
		}
		return orderedRoutingCharacterizationRow{current: true}
	}
	if statement != `SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)` || len(args) != 3 {
		d.t.Error("wrong release statement or argument count")
		return orderedRoutingCharacterizationRow{err: errors.New("unexpected statement")}
	}
	body, ok := args[2].(json.RawMessage)
	if args[0] != d.expectedPublicChecksum || args[1] != d.expectedPublicFingerprint || !ok || string(body) != `{"operation":"deployment_ready"}` {
		d.t.Error("wrong compiled release pins or closed deployment request")
		return orderedRoutingCharacterizationRow{err: errors.New("unexpected release binding")}
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		d.t.Error("missing or expired release deadline")
		return orderedRoutingCharacterizationRow{err: errors.New("invalid deadline")}
	}
	return orderedRoutingCharacterizationRow{}
}

func (d *orderedRoutingCharacterizationDriver) Begin(context.Context) (pgx.Tx, error) {
	d.begins++
	return nil, errors.New("unexpected transaction")
}
func (d *orderedRoutingCharacterizationDriver) Exec(context.Context, string, ...any) error {
	d.execs++
	return errors.New("unexpected write")
}
func (*orderedRoutingCharacterizationDriver) Close() error { return nil }

type orderedRoutingCharacterizationRow struct {
	err     error
	current bool
}

func (r orderedRoutingCharacterizationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if r.current {
		if len(dest) != 2 {
			return errors.New("unexpected current release result shape")
		}
		ready, ok := dest[0].(*bool)
		if !ok {
			return errors.New("unexpected current readiness type")
		}
		*ready = true
		dest = dest[1:]
	}
	if len(dest) != 1 {
		return errors.New("unexpected release result shape")
	}
	body, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("unexpected release result type")
	}
	*body = []byte(`{"contract_version":62,"ready":true}`)
	return nil
}
