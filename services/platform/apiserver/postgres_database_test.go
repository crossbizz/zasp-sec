package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPostgresJSONDatabaseRunsSchemaReadAndWriteBoundaries(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaVersionSQL: []byte(CoreSchemaVersion),
		"SELECT payload":         []byte(`{"items":[]}`),
	}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != CoreSchemaVersion {
		t.Fatalf("version = (%q, %v)", version, err)
	}
	payload, err := database.QueryJSON(context.Background(), "SELECT payload", "organization")
	if err != nil || string(payload) != `{"items":[]}` {
		t.Fatalf("payload = (%q, %v)", payload, err)
	}
	if err := database.Exec(context.Background(), "UPDATE session", "token"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(driver.execArguments, []any{"token"}) {
		t.Fatalf("exec args = %#v", driver.execArguments)
	}
	if err := database.Close(); err != nil || driver.closes != 1 {
		t.Fatalf("close = (%v, %d)", err, driver.closes)
	}
}

func TestPostgresJSONDatabaseFailsClosedOnDriverErrors(t *testing.T) {
	driver := &databaseDriver{rowErr: errors.New("secret database failure"), execErr: errors.New("secret database failure")}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.SchemaVersion(context.Background()); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("schema error = %v", err)
	}
	if _, err := database.QueryJSON(context.Background(), "SELECT payload"); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("query error = %v", err)
	}
	if err := database.Exec(context.Background(), "UPDATE session"); !errors.Is(err, ErrRepositoryOperation) {
		t.Fatalf("exec error = %v", err)
	}
}

type databaseDriver struct {
	responses     map[string][]byte
	rowErr        error
	execErr       error
	execArguments []any
	closes        int
}

func (driver *databaseDriver) QueryRow(_ context.Context, statement string, _ ...any) PostgresRow {
	return databaseRow{value: driver.responses[statement], err: driver.rowErr}
}
func (driver *databaseDriver) Exec(_ context.Context, _ string, arguments ...any) error {
	driver.execArguments = arguments
	return driver.execErr
}
func (driver *databaseDriver) Close() error { driver.closes++; return nil }

type databaseRow struct {
	value []byte
	err   error
}

func (row databaseRow) Scan(destination ...any) error {
	if row.err != nil {
		return row.err
	}
	switch target := destination[0].(type) {
	case *string:
		*target = string(row.value)
	case *[]byte:
		*target = append([]byte(nil), row.value...)
	default:
		return errors.New("unsupported destination")
	}
	return nil
}
