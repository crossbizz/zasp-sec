package migrations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fakeRow struct {
	values []any
	err    error
}

func (row fakeRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != len(row.values) {
		return errors.New("scan arity")
	}
	for index, value := range row.values {
		switch destination := destinations[index].(type) {
		case *bool:
			converted, ok := value.(bool)
			if !ok {
				return errors.New("scan bool")
			}
			*destination = converted
		case *int64:
			converted, ok := value.(int64)
			if !ok {
				return errors.New("scan int64")
			}
			*destination = converted
		case *string:
			converted, ok := value.(string)
			if !ok {
				return errors.New("scan string")
			}
			*destination = converted
		default:
			return errors.New("scan destination")
		}
	}
	return nil
}

type fakeTransaction struct {
	events               *[]string
	rows                 []Row
	execErrorAt          int
	queryErrorAt         int
	commitError          error
	rollbackError        error
	rollbackContextError error
	execs                int
	queries              int
}

func (transaction *fakeTransaction) Exec(ctx context.Context, statement string, arguments ...any) error {
	*transaction.events = append(*transaction.events, "exec:"+compactSQL(statement), argumentEvent(arguments))
	transaction.execs++
	if err := ctx.Err(); err != nil {
		return err
	}
	if transaction.execErrorAt == transaction.execs {
		return errors.New("database detail")
	}
	return nil
}

func (transaction *fakeTransaction) QueryRow(ctx context.Context, statement string, arguments ...any) Row {
	*transaction.events = append(*transaction.events, "query:"+compactSQL(statement), argumentEvent(arguments))
	transaction.queries++
	if err := ctx.Err(); err != nil {
		return fakeRow{err: err}
	}
	if transaction.queryErrorAt == transaction.queries {
		return fakeRow{err: errors.New("database detail")}
	}
	if len(transaction.rows) == 0 {
		return fakeRow{err: errors.New("missing scripted row")}
	}
	row := transaction.rows[0]
	transaction.rows = transaction.rows[1:]
	return row
}

func (transaction *fakeTransaction) Commit(ctx context.Context) error {
	*transaction.events = append(*transaction.events, "commit")
	if err := ctx.Err(); err != nil {
		return err
	}
	return transaction.commitError
}

func (transaction *fakeTransaction) Rollback(ctx context.Context) error {
	*transaction.events = append(*transaction.events, "rollback")
	transaction.rollbackContextError = ctx.Err()
	return transaction.rollbackError
}

type fakeDatabase struct {
	events      []string
	transaction *fakeTransaction
	rows        []Row
	beginError  error
	queries     int
}

type ambiguousBeginDatabase struct {
	events      []string
	transaction *fakeTransaction
}

func (database *ambiguousBeginDatabase) Begin(context.Context) (Transaction, error) {
	database.events = append(database.events, "begin")
	database.transaction.events = &database.events
	return database.transaction, errors.New("ambiguous begin detail")
}

func (database *ambiguousBeginDatabase) QueryRow(context.Context, string, ...any) Row {
	return fakeRow{err: errors.New("must not query")}
}

func (database *fakeDatabase) Begin(ctx context.Context) (Transaction, error) {
	database.events = append(database.events, "begin")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if database.beginError != nil {
		return nil, database.beginError
	}
	database.transaction.events = &database.events
	return database.transaction, nil
}

func (database *fakeDatabase) QueryRow(ctx context.Context, statement string, arguments ...any) Row {
	database.events = append(database.events, "query:"+compactSQL(statement), argumentEvent(arguments))
	database.queries++
	if err := ctx.Err(); err != nil {
		return fakeRow{err: err}
	}
	if len(database.rows) == 0 {
		return fakeRow{err: errors.New("missing scripted row")}
	}
	row := database.rows[0]
	database.rows = database.rows[1:]
	return row
}

func compactSQL(value string) string { return strings.Join(strings.Fields(value), " ") }

func argumentEvent(values []any) string {
	if len(values) == 0 {
		return "args:none"
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = fmt.Sprint(value)
	}
	return "args:" + strings.Join(parts, ",")
}

func exactRows() []Row {
	metadata := Baseline()
	return []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(1)}},
		fakeRow{values: []any{metadata.Version(), metadata.Name(), metadata.Checksum()}},
	}
}

func TestBaselineMetadataIsStableAndOpaque(t *testing.T) {
	metadata := Baseline()
	const expectedUp = `CREATE TABLE "public"."zasp_schema_versions" (
    "version" bigint PRIMARY KEY,
    "name" text NOT NULL UNIQUE CHECK (char_length("name") BETWEEN 1 AND 63),
    "checksum" text NOT NULL CHECK ("checksum" ~ '^[a-f0-9]{64}$'),
    "applied_at" timestamp with time zone NOT NULL DEFAULT transaction_timestamp()
);`
	const expectedDown = `DROP TABLE "public"."zasp_schema_versions";`
	const expectedChecksum = "feeec4a9f6da520b46d09ac4c9c6ea6d99b052e8f5e5d4408d0dfffd8e554670"
	if metadata.Version() != 1 || metadata.Name() != "schema_versions" {
		t.Fatalf("baseline identity = %d/%q", metadata.Version(), metadata.Name())
	}
	if len(metadata.Checksum()) != 64 || strings.Trim(metadata.Checksum(), "0123456789abcdef") != "" {
		t.Fatalf("baseline checksum = %q", metadata.Checksum())
	}
	if metadata.UpSQL() == "" || metadata.DownSQL() == "" || metadata.UpSQL() == metadata.DownSQL() {
		t.Fatal("embedded migration assets are missing")
	}
	if !strings.Contains(metadata.UpSQL(), `CREATE TABLE "public"."zasp_schema_versions"`) ||
		!strings.Contains(metadata.DownSQL(), `DROP TABLE "public"."zasp_schema_versions"`) {
		t.Fatal("baseline assets do not own only the schema-version table")
	}
	if Baseline() != metadata {
		t.Fatal("baseline metadata changed between reads")
	}
	if metadata.UpSQL() != expectedUp || metadata.DownSQL() != expectedDown || metadata.Checksum() != expectedChecksum {
		t.Fatalf("version-1 assets drifted: checksum=%q", metadata.Checksum())
	}
}

func TestProductionCoreMetadataOwnsOnlyMountedDurableSessionAndCoreSchema(t *testing.T) {
	metadata := ProductionCore()
	if metadata.Version() != 2 || metadata.Name() != "production_core" || len(metadata.Checksum()) != 64 {
		t.Fatalf("production core identity = %d/%q/%q", metadata.Version(), metadata.Name(), metadata.Checksum())
	}
	for _, fragment := range []string{"zasp_schema_metadata", "zasp_product_sessions", "zasp_product_api_tokens", "zasp_create_product_session", "zasp_core_payloads", "zasp_session_bootstrap", "zasp_core_read", "production-core-v1"} {
		if !strings.Contains(metadata.UpSQL(), fragment) {
			t.Fatalf("production core up migration missing %q", fragment)
		}
	}
	if strings.Contains(metadata.UpSQL(), "zasp_core_write") {
		t.Fatal("production core migration exposes an unmounted simulated mutation")
	}
	if metadata.UpSQL() == "" || metadata.DownSQL() == "" || ProductionCore() != metadata {
		t.Fatal("production core migration assets are missing or unstable")
	}
}

func TestRunnerDownCoreRequiresExactCoreAndRestoresBaseline(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	transaction := &fakeTransaction{rows: []Row{
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
		fakeRow{values: []any{true}},
		fakeRow{values: []any{int64(1)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
	}}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.DownCore(context.Background()); err != nil {
		t.Fatalf("DownCore: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:1",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:2",
		`exec:DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`, "args:2,production_core," + core.Checksum(),
		"exec:" + compactSQL(core.DownSQL()), "args:none",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerUpCoreRequiresBaselineAndRecordsExactRelease(t *testing.T) {
	baseline, core := Baseline(), ProductionCore()
	transaction := &fakeTransaction{rows: append(exactRows(),
		fakeRow{values: []any{int64(2)}},
		fakeRow{values: []any{baseline.Version(), baseline.Name(), baseline.Checksum()}},
		fakeRow{values: []any{core.Version(), core.Name(), core.Checksum()}},
	)}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.UpCore(context.Background()); err != nil {
		t.Fatalf("UpCore: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		"exec:" + compactSQL(core.UpSQL()), "args:none",
		`exec:INSERT INTO "public"."zasp_schema_versions" ("version", "name", "checksum") VALUES ($1, $2, $3)`,
		"args:2,production_core," + core.Checksum(),
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:1",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`, "args:2",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerUpCreatesAndRecordsExactBaselineInOneTransaction(t *testing.T) {
	metadata := Baseline()
	transaction := &fakeTransaction{rows: append([]Row{fakeRow{values: []any{false}}}, exactRows()...)}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}

	if err := runner.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"exec:" + compactSQL(metadata.UpSQL()), "args:none",
		"exec:INSERT INTO \"public\".\"zasp_schema_versions\" (\"version\", \"name\", \"checksum\") VALUES ($1, $2, $3)",
		"args:1,schema_versions," + metadata.Checksum(),
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"query:SELECT count(*) FROM \"public\".\"zasp_schema_versions\"", "args:none",
		"query:SELECT \"version\", \"name\", \"checksum\" FROM \"public\".\"zasp_schema_versions\" ORDER BY \"version\"", "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
	if transaction.execs != 2 || transaction.queries != 4 {
		t.Fatalf("calls = exec %d query %d", transaction.execs, transaction.queries)
	}
}

func TestRunnerDownRequiresExactStateAndRestoresAbsence(t *testing.T) {
	metadata := Baseline()
	transaction := &fakeTransaction{rows: append(exactRows(), fakeRow{values: []any{false}})}
	database := &fakeDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}

	want := []string{
		"begin",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		`exec:LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`, "args:none",
		`query:SELECT count(*) FROM "public"."zasp_schema_versions"`, "args:none",
		`query:SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`, "args:none",
		`exec:DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`,
		"args:1,schema_versions," + metadata.Checksum(),
		"exec:" + compactSQL(metadata.DownSQL()), "args:none",
		"query:SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL", "args:none",
		"commit",
	}
	if !reflect.DeepEqual(database.events, want) {
		t.Fatalf("events = %#v, want %#v", database.events, want)
	}
}

func TestRunnerStateReportsOnlyAbsentOrExactBaseline(t *testing.T) {
	metadata := Baseline()
	for name, rows := range map[string][]Row{
		"absent": {fakeRow{values: []any{false}}},
		"exact":  exactRows(),
	} {
		t.Run(name, func(t *testing.T) {
			database := &fakeDatabase{rows: rows}
			runner, err := NewRunner(database)
			if err != nil {
				t.Fatal(err)
			}
			state, err := runner.State(context.Background())
			if err != nil {
				t.Fatalf("State: %v", err)
			}
			if name == "absent" && state.Applied() {
				t.Fatal("absent state was applied")
			}
			if name == "exact" && (!state.Applied() || state.Version() != metadata.Version() || state.Name() != metadata.Name() || state.Checksum() != metadata.Checksum()) {
				t.Fatalf("exact state = %#v", state)
			}
		})
	}

	for name, rows := range map[string][]Row{
		"extra row":      {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(2)}}},
		"wrong version":  {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{int64(2), metadata.Name(), metadata.Checksum()}}},
		"wrong name":     {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{metadata.Version(), "other", metadata.Checksum()}}},
		"wrong checksum": {fakeRow{values: []any{true}}, fakeRow{values: []any{int64(1)}}, fakeRow{values: []any{metadata.Version(), metadata.Name(), strings.Repeat("0", 64)}}},
	} {
		t.Run(name, func(t *testing.T) {
			runner, _ := NewRunner(&fakeDatabase{rows: rows})
			if _, err := runner.State(context.Background()); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("State error = %v", err)
			}
		})
	}
}

func TestRunnerRejectsExistingOrMissingStateWithoutMutation(t *testing.T) {
	for name, operation := range map[string]struct {
		rows []Row
		run  func(*Runner) error
	}{
		"up exact collision":   {rows: exactRows(), run: func(runner *Runner) error { return runner.Up(context.Background()) }},
		"up foreign collision": {rows: []Row{fakeRow{values: []any{true}}, fakeRow{values: []any{int64(2)}}}, run: func(runner *Runner) error { return runner.Up(context.Background()) }},
		"down absent":          {rows: []Row{fakeRow{values: []any{false}}}, run: func(runner *Runner) error { return runner.Down(context.Background()) }},
	} {
		t.Run(name, func(t *testing.T) {
			transaction := &fakeTransaction{rows: operation.rows}
			database := &fakeDatabase{transaction: transaction}
			runner, _ := NewRunner(database)
			if err := operation.run(runner); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("error = %v", err)
			}
			if transaction.execs != 0 {
				t.Fatalf("collision executed %d mutations", transaction.execs)
			}
			if !contains(database.events, "rollback") {
				t.Fatalf("rollback missing: %#v", database.events)
			}
		})
	}
}

func TestRunnerRollsBackWithFixedErrorsAndCleanupPrecedence(t *testing.T) {
	for name, transaction := range map[string]*fakeTransaction{
		"query":               {rows: []Row{fakeRow{values: []any{false}}}, queryErrorAt: 2},
		"exec":                {rows: []Row{fakeRow{values: []any{false}}}, execErrorAt: 1},
		"commit":              {rows: append([]Row{fakeRow{values: []any{false}}}, exactRows()...), commitError: errors.New("commit detail")},
		"rollback precedence": {rows: []Row{fakeRow{values: []any{false}}}, execErrorAt: 1, rollbackError: errors.New("rollback detail")},
	} {
		t.Run(name, func(t *testing.T) {
			database := &fakeDatabase{transaction: transaction}
			runner, _ := NewRunner(database)
			if err := runner.Up(context.Background()); !errors.Is(err, ErrDatabase) {
				t.Fatalf("Up error = %v", err)
			}
			if !contains(database.events, "rollback") {
				t.Fatalf("rollback missing: %#v", database.events)
			}
		})
	}
}

func TestRunnerRollsBackTransactionReturnedWithBeginError(t *testing.T) {
	transaction := &fakeTransaction{}
	database := &ambiguousBeginDatabase{transaction: transaction}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}

	if err := runner.Up(context.Background()); !errors.Is(err, ErrDatabase) {
		t.Fatalf("Up error = %v", err)
	}
	if !reflect.DeepEqual(database.events, []string{"begin", "rollback"}) {
		t.Fatalf("events = %#v", database.events)
	}
	if transaction.rollbackContextError != nil {
		t.Fatalf("rollback inherited failed context: %v", transaction.rollbackContextError)
	}
}

func TestRunnerRejectsCancellationAndMalformedBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	database := &fakeDatabase{transaction: &fakeTransaction{}}
	runner, err := NewRunner(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Up = %v", err)
	}
	if len(database.events) != 0 {
		t.Fatalf("canceled Up touched database: %#v", database.events)
	}
	if _, err := runner.State(nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("nil State = %v", err)
	}
	if err := runner.Down(nil); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("nil Down = %v", err)
	}

	var typedNil *fakeDatabase
	if _, err := NewRunner(typedNil); !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("typed nil database = %v", err)
	}
	if _, err := NewRunner(nil); !errors.Is(err, ErrInvalidDatabase) {
		t.Fatalf("nil database = %v", err)
	}
	if _, err := (*Runner)(nil).State(context.Background()); !errors.Is(err, ErrInvalidRunner) {
		t.Fatalf("nil runner = %v", err)
	}
	runner, _ = NewRunner(&fakeDatabase{rows: []Row{nil}})
	if _, err := runner.State(context.Background()); !errors.Is(err, ErrDatabase) {
		t.Fatalf("nil row = %v", err)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
