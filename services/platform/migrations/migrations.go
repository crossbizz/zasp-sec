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
	rollbackTimeout = 5 * time.Second

	tableExistsSQL = "SELECT to_regclass('public.zasp_schema_versions') IS NOT NULL"
	countRowsSQL   = `SELECT count(*) FROM "public"."zasp_schema_versions"`
	readRowSQL     = `SELECT "version", "name", "checksum" FROM "public"."zasp_schema_versions" ORDER BY "version"`
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
