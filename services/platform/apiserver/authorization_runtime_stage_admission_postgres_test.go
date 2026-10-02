package apiserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Fingerprinting an inherited permission is not admission. The real installer
// must reject drift before it can register that drift as its expected baseline.
func TestP7RuntimeStageBaselineAdmission(t *testing.T) {
	runTemporalTestGrantFixture(t, func(parent context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for _, scenario := range []struct{ name, mutation string }{
			{"closed canonical baseline", ""},
			{"service table grant", `GRANT INSERT ON public.zasp_runtime_stage_work TO zasp_runtime_ingest`},
			{"PUBLIC table grant", `GRANT INSERT ON public.zasp_runtime_stage_work TO PUBLIC`},
			{"column grant", `GRANT INSERT(organization_id) ON public.zasp_runtime_stage_work TO zasp_runtime_ingest`},
			{"owner drift", `ALTER TABLE public.zasp_runtime_stage_work OWNER TO CURRENT_USER`},
			{"RLS disabled", `ALTER TABLE public.zasp_runtime_stage_work DISABLE ROW LEVEL SECURITY`},
			{"RLS unforced", `ALTER TABLE public.zasp_runtime_stage_work NO FORCE ROW LEVEL SECURITY`},
			{"policy drift", `ALTER POLICY zasp_runtime_stage_work_authority ON public.zasp_runtime_stage_work USING(false)`},
			{"extra policy", `CREATE POLICY stage_admission_extra ON public.zasp_runtime_stage_work TO PUBLIC USING(true)`},
		} {
			t.Run(scenario.name, func(t *testing.T) {
				outer, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer outer.Rollback(context.Background())
				if scenario.mutation != "" {
					if _, err := outer.Exec(ctx, scenario.mutation); err != nil {
						t.Fatal(err)
					}
				}
				database := &runtimeStageAdmissionDatabase{transaction: outer}
				installer, err := migrations.NewRunner(database)
				if err != nil {
					t.Fatal(err)
				}
				err = installer.UpProductionAuthorizationWorkerProfile(ctx)
				if scenario.mutation != "" {
					if err == nil {
						t.Error("installer registered inherited stage permission drift")
					} else if !errors.Is(err, migrations.ErrInvalidState) && !(errors.Is(err, migrations.ErrDatabase) && database.sqlState == "55000") {
						t.Error("installer failed without an admission refusal", err, database.sqlState)
					}
					return
				}
				if err != nil {
					t.Fatal("canonical stage baseline rejected", err)
				}
				var module, worker bool
				if err := outer.QueryRow(ctx, `SELECT zasp_authorization80_runtime.catalog_ready(),zasp_authorization80_worker.catalog_ready()`).Scan(&module, &worker); err != nil || !module || !worker {
					t.Fatal("actual installed baseline", module, worker, err)
				}
			})
		}
	})
}

// pgx nested transactions are actual database savepoints. The production Runner
// performs and commits its full installation; the fixture's enclosing rollback
// only isolates cases, without replacing any SQL or readiness result.
type runtimeStageAdmissionDatabase struct {
	transaction pgx.Tx
	sqlState    string
}

func (database *runtimeStageAdmissionDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) migrations.Row {
	return database.transaction.QueryRow(ctx, statement, arguments...)
}

func (database *runtimeStageAdmissionDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	nested, err := database.transaction.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &runtimeStageAdmissionTransaction{Transaction: &integrationMigrationTransaction{transaction: nested}, database: database}, nil
}

type runtimeStageAdmissionTransaction struct {
	migrations.Transaction
	database *runtimeStageAdmissionDatabase
}

func (transaction *runtimeStageAdmissionTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	err := transaction.Transaction.Exec(ctx, statement, arguments...)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		transaction.database.sqlState = native.Code
	}
	return err
}
