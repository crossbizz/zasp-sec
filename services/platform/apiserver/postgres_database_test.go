package apiserver

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
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
	if _, err := database.SchemaVersion(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("schema error = %v", err)
	}
	if _, err := database.QueryJSON(context.Background(), "SELECT payload"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("query error = %v", err)
	}
	if err := database.Exec(context.Background(), "UPDATE session"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("exec error = %v", err)
	}
}

func TestPostgresJSONDatabaseCloseWaitsForInflightQuery(t *testing.T) {
	driver := &blockingDatabaseDriver{started: make(chan struct{}), release: make(chan struct{})}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := database.QueryJSON(context.Background(), "SELECT payload")
		queryDone <- queryErr
	}()
	<-driver.started
	closeDone := make(chan error, 1)
	go func() { closeDone <- database.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close completed during inflight query: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(driver.release)
	if err := <-queryDone; err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if err := <-closeDone; err != nil || driver.closes != 1 {
		t.Fatalf("close = (%v, %d)", err, driver.closes)
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

type blockingDatabaseDriver struct {
	started chan struct{}
	release chan struct{}
	closes  int
}

func (driver *blockingDatabaseDriver) QueryRow(context.Context, string, ...any) PostgresRow {
	return blockingDatabaseRow{started: driver.started, release: driver.release}
}
func (*blockingDatabaseDriver) Exec(context.Context, string, ...any) error { return nil }
func (driver *blockingDatabaseDriver) Close() error                        { driver.closes++; return nil }

type blockingDatabaseRow struct {
	started chan struct{}
	release chan struct{}
}

func (row blockingDatabaseRow) Scan(destinations ...any) error {
	close(row.started)
	<-row.release
	*(destinations[0].(*[]byte)) = []byte(`{"items":[]}`)
	return nil
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
