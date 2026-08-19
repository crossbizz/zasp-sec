package migrations

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"
)

const (
	baselineVersion = int64(1)
	baselineName    = "schema_versions"
	coreVersion     = int64(2)
	coreName        = "production_core"
	workflowVersion = int64(3)
	workflowName    = "production_workflows"
	rollbackTimeout = 5 * time.Second

	tableExistsSQL = "SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL"
	countRowsSQL   = `SELECT count(*) FROM "public"."zasp_schema_versions"`
	readRowSQL     = `SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`
	readVersionSQL = `SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" WHERE "version" = $1`
	lockTableSQL   = `LOCK TABLE "public"."zasp_schema_versions" IN ACCESS EXCLUSIVE MODE`
	insertRowSQL   = `INSERT INTO "public"."zasp_schema_versions" ("version", "name", "checksum") VALUES ($1, $2, $3)`
	deleteRowSQL   = `DELETE FROM "public"."zasp_schema_versions" WHERE "version" = $1 AND "name" = $2 AND "checksum" = $3`
)

var (
	ErrInvalidContext  = errors.New("invalid migration context")
	ErrInvalidDatabase = errors.New("invalid migration database")
	ErrInvalidRunner   = errors.New("invalid migration runner")
	ErrInvalidState    = errors.New("invalid migration state")
	ErrDatabase        = errors.New("migration database failed")
)

//go:embed sql/0001_schema_versions.up.sql
var baselineUpSQL string

//go:embed sql/0001_schema_versions.down.sql
var baselineDownSQL string

//go:embed sql/0002_production_core.up.sql
var coreUpSQL string

//go:embed sql/0002_production_core.down.sql
var coreDownSQL string

//go:embed sql/0003_production_workflows.up.sql
var workflowUpSQL string

//go:embed sql/0003_production_workflows.down.sql
var workflowDownSQL string

type Metadata struct {
	version  int64
	name     string
	checksum string
	up       string
	down     string
}

func Baseline() Metadata {
	up := strings.TrimSpace(baselineUpSQL)
	down := strings.TrimSpace(baselineDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{
		version:  baselineVersion,
		name:     baselineName,
		checksum: hex.EncodeToString(digest[:]),
		up:       up,
		down:     down,
	}
}

func ProductionCore() Metadata {
	up := strings.TrimSpace(coreUpSQL)
	down := strings.TrimSpace(coreDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{
		version:  coreVersion,
		name:     coreName,
		checksum: hex.EncodeToString(digest[:]),
		up:       up,
		down:     down,
	}
}

func ProductionWorkflows() Metadata {
	up := strings.TrimSpace(workflowUpSQL)
	down := strings.TrimSpace(workflowDownSQL)
	digest := sha256.Sum256([]byte(up + "\x00" + down))
	return Metadata{version: workflowVersion, name: workflowName, checksum: hex.EncodeToString(digest[:]), up: up, down: down}
}

func ProductionWorkflowsSemanticFingerprint() string {
	const marker = "'production_workflows_fingerprint', '"
	start := strings.Index(workflowUpSQL, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	if len(workflowUpSQL) < start+64 {
		return ""
	}
	value := workflowUpSQL[start : start+64]
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || len(workflowUpSQL) == start+64 || workflowUpSQL[start+64] != '\'' {
		return ""
	}
	return value
}

func (metadata Metadata) Version() int64   { return metadata.version }
func (metadata Metadata) Name() string     { return metadata.name }
func (metadata Metadata) Checksum() string { return metadata.checksum }
func (metadata Metadata) UpSQL() string    { return metadata.up }
func (metadata Metadata) DownSQL() string  { return metadata.down }

type State struct {
	applied  bool
	version  int64
	name     string
	checksum string
}

func (state State) Applied() bool    { return state.applied }
func (state State) Version() int64   { return state.version }
func (state State) Name() string     { return state.name }
func (state State) Checksum() string { return state.checksum }

type Row interface {
	Scan(...any) error
}

type Queryer interface {
	QueryRow(context.Context, string, ...any) Row
}

type Transaction interface {
	Queryer
	Exec(context.Context, string, ...any) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type Database interface {
	Queryer
	Begin(context.Context) (Transaction, error)
}

type Runner struct {
	database Database
}

func NewRunner(database Database) (*Runner, error) {
	if nilInterface(database) {
		return nil, ErrInvalidDatabase
	}
	return &Runner{database: database}, nil
}

func (runner *Runner) State(ctx context.Context) (State, error) {
	if runner == nil || nilInterface(runner.database) {
		return State{}, ErrInvalidRunner
	}
	if ctx == nil {
		return State{}, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	return readState(ctx, runner.database)
}

// Version returns the exact release target installed in the database: zero for
// an empty database, one for the immutable baseline, and two for production
// core. Any partial, extra, or checksum-drifted state is rejected.
func (runner *Runner) Version(ctx context.Context) (int64, error) {
	if runner == nil || nilInterface(runner.database) {
		return 0, ErrInvalidRunner
	}
	if ctx == nil {
		return 0, ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	present, err := tablePresent(ctx, runner.database)
	if err != nil || !present {
		return 0, err
	}
	var count int64
	if err := scanRow(ctx, runner.database, countRowsSQL, nil, &count); err != nil {
		return 0, fixedDatabaseError(ctx, err)
	}
	if count < 1 || count > 3 {
		return 0, ErrInvalidState
	}
	metadata := []Metadata{Baseline()}
	if count >= 2 {
		metadata = append(metadata, ProductionCore())
	}
	if count == 3 {
		metadata = append(metadata, ProductionWorkflows())
	}
	for _, expected := range metadata {
		var version int64
		var name, checksum string
		if err := scanRow(ctx, runner.database, readVersionSQL, []any{expected.Version()}, &version, &name, &checksum); err != nil {
			return 0, fixedDatabaseError(ctx, err)
		}
		if version != expected.Version() || name != expected.Name() || checksum != expected.Checksum() {
			return 0, ErrInvalidState
		}
	}
	return count, nil
}

func (runner *Runner) Up(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		if state.Applied() {
			return ErrInvalidState
		}
		metadata := Baseline()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err = readState(ctx, transaction)
		if err != nil {
			return err
		}
		if !state.Applied() {
			return ErrInvalidState
		}
		return nil
	})
}

// UpCore applies the first production data boundary only when the immutable
// baseline is the database's exact current state. Release tooling calls this
// explicitly; the API process never mutates its schema during startup.
func (runner *Runner) UpCore(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		baseline := Baseline()
		if !state.Applied() || state.Version() != baseline.Version() || state.Name() != baseline.Name() || state.Checksum() != baseline.Checksum() {
			return ErrInvalidState
		}
		metadata := ProductionCore()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readCoreState(ctx, transaction)
	})
}

// DownCore removes only the production data boundary, leaving the immutable
// baseline installed for a subsequent exact release migration.
func (runner *Runner) DownCore(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil {
			return err
		}
		if !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readCoreState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionCore()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err := readState(ctx, transaction)
		if err != nil {
			return err
		}
		baseline := Baseline()
		if !state.Applied() || state.Version() != baseline.Version() || state.Name() != baseline.Name() || state.Checksum() != baseline.Checksum() {
			return ErrInvalidState
		}
		return nil
	})
}

func (runner *Runner) UpWorkflows(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		if err := readCoreState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionWorkflows()
		if err := transaction.Exec(ctx, metadata.UpSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, insertRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readWorkflowState(ctx, transaction)
	})
}

func (runner *Runner) DownWorkflows(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil || !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := readWorkflowState(ctx, transaction); err != nil {
			return err
		}
		metadata := ProductionWorkflows()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return readCoreState(ctx, transaction)
	})
}

func (runner *Runner) Down(ctx context.Context) error {
	if runner == nil || nilInterface(runner.database) {
		return ErrInvalidRunner
	}
	return runner.withTransaction(ctx, func(ctx context.Context, transaction Transaction) error {
		present, err := tablePresent(ctx, transaction)
		if err != nil {
			return err
		}
		if !present {
			return ErrInvalidState
		}
		if err := transaction.Exec(ctx, lockTableSQL); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err := readPresentState(ctx, transaction)
		if err != nil {
			return err
		}
		if !state.Applied() {
			return ErrInvalidState
		}
		metadata := Baseline()
		if err := transaction.Exec(ctx, deleteRowSQL, metadata.Version(), metadata.Name(), metadata.Checksum()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if err := transaction.Exec(ctx, metadata.DownSQL()); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		state, err = readState(ctx, transaction)
		if err != nil {
			return err
		}
		if state.Applied() {
			return ErrInvalidState
		}
		return nil
	})
}

func (runner *Runner) withTransaction(ctx context.Context, operation func(context.Context, Transaction) error) (resultErr error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	transaction, err := runner.database.Begin(ctx)
	if nilInterface(transaction) {
		if err != nil {
			return fixedDatabaseError(ctx, err)
		}
		return ErrInvalidDatabase
	}
	if err != nil {
		if rollbackTransaction(ctx, transaction) != nil {
			return ErrDatabase
		}
		return fixedDatabaseError(ctx, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if err := rollbackTransaction(ctx, transaction); err != nil {
			resultErr = ErrDatabase
		}
	}()
	if err := operation(ctx, transaction); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := transaction.Commit(ctx); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	committed = true
	return nil
}

func rollbackTransaction(ctx context.Context, transaction Transaction) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	return transaction.Rollback(rollbackCtx)
}

func readState(ctx context.Context, queryer Queryer) (State, error) {
	present, err := tablePresent(ctx, queryer)
	if err != nil {
		return State{}, err
	}
	if !present {
		return State{}, nil
	}
	return readPresentState(ctx, queryer)
}

func tablePresent(ctx context.Context, queryer Queryer) (bool, error) {
	if nilInterface(queryer) {
		return false, ErrInvalidDatabase
	}
	var present bool
	if err := scanRow(ctx, queryer, tableExistsSQL, nil, &present); err != nil {
		return false, fixedDatabaseError(ctx, err)
	}
	return present, nil
}

func readPresentState(ctx context.Context, queryer Queryer) (State, error) {
	var count int64
	if err := scanRow(ctx, queryer, countRowsSQL, nil, &count); err != nil {
		return State{}, fixedDatabaseError(ctx, err)
	}
	if count != 1 {
		return State{}, ErrInvalidState
	}
	state := State{applied: true}
	if err := scanRow(ctx, queryer, readRowSQL, nil, &state.version, &state.name, &state.checksum); err != nil {
		return State{}, fixedDatabaseError(ctx, err)
	}
	metadata := Baseline()
	if state.version != metadata.Version() || state.name != metadata.Name() || state.checksum != metadata.Checksum() {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func readCoreState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore()})
}

func readWorkflowState(ctx context.Context, queryer Queryer) error {
	return readExactReleaseState(ctx, queryer, []Metadata{Baseline(), ProductionCore(), ProductionWorkflows()})
}

func readExactReleaseState(ctx context.Context, queryer Queryer, expected []Metadata) error {
	var count int64
	if err := scanRow(ctx, queryer, countRowsSQL, nil, &count); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if count != int64(len(expected)) {
		return ErrInvalidState
	}
	for _, metadata := range expected {
		state := State{applied: true}
		if err := scanRow(ctx, queryer, readVersionSQL, []any{metadata.Version()}, &state.version, &state.name, &state.checksum); err != nil {
			return fixedDatabaseError(ctx, err)
		}
		if state.version != metadata.Version() || state.name != metadata.Name() || state.checksum != metadata.Checksum() {
			return ErrInvalidState
		}
	}
	return nil
}

func scanRow(ctx context.Context, queryer Queryer, statement string, arguments []any, destinations ...any) error {
	row := queryer.QueryRow(ctx, statement, arguments...)
	if nilInterface(row) {
		return ErrInvalidDatabase
	}
	return row.Scan(destinations...)
}

func fixedDatabaseError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return ErrDatabase
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
