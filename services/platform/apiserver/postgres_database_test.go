package apiserver

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestPostgresSchemaReadinessRequiresExactWorkflowRelease(t *testing.T) {
	if CoreSchemaVersion != "production-risk-projection-v1" {
		t.Fatalf("schema target = %q", CoreSchemaVersion)
	}
	if !strings.Contains(postgresSchemaVersionSQL, "release.version = 9") || !strings.Contains(postgresSchemaVersionSQL, "release.name = 'production_risk_projection'") {
		t.Fatalf("schema readiness query does not require provenance release: %s", postgresSchemaVersionSQL)
	}
	if !strings.Contains(postgresSchemaVersionSQL, "release.version = 11") || !strings.Contains(postgresSchemaVersionSQL, "release.name = 'connector_authorization'") || !strings.Contains(postgresSchemaVersionSQL, "connector_authorization_fingerprint") {
		t.Fatalf("schema readiness query does not require connector authorization release: %s", postgresSchemaVersionSQL)
	}
	if !strings.Contains(postgresSchemaVersionSQL, "release.version = 12") || !strings.Contains(postgresSchemaVersionSQL, "release.name = 'reference_authorization'") || !strings.Contains(postgresSchemaVersionSQL, "reference_authorization_fingerprint") || !strings.Contains(postgresSchemaVersionSQL, "pg_get_triggerdef") {
		t.Fatalf("schema readiness query does not require reference authorization and connector triggers: %s", postgresSchemaVersionSQL)
	}
	if strings.Contains(postgresSchemaVersionSQL, "zasp_execution_readiness") || strings.Contains(postgresSchemaVersionSQL, "release.version = 13") {
		t.Fatalf("legacy schema readiness query directly references v13 authority: %s", postgresSchemaVersionSQL)
	}
	if !strings.Contains(postgresDiscoveryExecutionSchemaVersionSQL, "release.version = 13") || !strings.Contains(postgresDiscoveryExecutionSchemaVersionSQL, "release.name = 'production_discovery_execution'") || !strings.Contains(postgresDiscoveryExecutionSchemaVersionSQL, "zasp_execution_readiness($1, $2)") {
		t.Fatalf("v13 schema readiness query does not require production discovery execution readiness: %s", postgresDiscoveryExecutionSchemaVersionSQL)
	}
	if !strings.Contains(postgresTypedInventorySchemaVersionSQL, "release.version = 14") || !strings.Contains(postgresTypedInventorySchemaVersionSQL, "release.name = 'typed_inventory_cutover'") || !strings.Contains(postgresTypedInventorySchemaVersionSQL, "zasp_inventory_readiness($1, $2)") {
		t.Fatalf("v14 schema readiness query does not require typed inventory readiness: %s", postgresTypedInventorySchemaVersionSQL)
	}
	if !strings.Contains(postgresSchemaVersionSQL, "production_discovery_release_fingerprint") || !strings.Contains(postgresSchemaVersionSQL, "COALESCE(release_fingerprint.value, expected_fingerprint.value)") {
		t.Fatalf("schema readiness query does not recognize the v11-to-v10 compatibility contract: %s", postgresSchemaVersionSQL)
	}
	for _, fragment := range []string{"pg_get_expr", "pg_get_constraintdef", "pg_get_indexdef", "prosrc", "provolatile", "prosecdef", "attnotnull", "format_type", "production_risk_projection_fingerprint"} {
		if !strings.Contains(postgresSchemaVersionSQL, fragment) {
			t.Fatalf("schema readiness query missing exact fingerprint %q: %s", fragment, postgresSchemaVersionSQL)
		}
	}
	if expectedCoreSchemaChecksum() != migrations.ProductionRiskProjection().Checksum() {
		t.Fatal("schema readiness checksum is not the risk projection release checksum")
	}
	if expectedCoreSchemaFingerprint() != migrations.ProductionRiskProjectionSemanticFingerprint() || len(expectedCoreSchemaFingerprint()) != 64 {
		t.Fatal("schema readiness fingerprint is not derived from the risk projection migration")
	}
}

func TestPostgresJSONDatabaseRunsSchemaReadAndWriteBoundaries(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaMarkerSQL:  []byte(CoreSchemaVersion),
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
	if !reflect.DeepEqual(driver.queryArguments, []any{expectedCoreSchemaChecksum(), expectedCoreSchemaFingerprint(), expectedDiscoverySchemaChecksum(), expectedDiscoverySchemaFingerprint(), expectedConnectorSchemaChecksum(), expectedConnectorSchemaFingerprint(), expectedReferenceSchemaChecksum(), expectedReferenceSchemaFingerprint()}) {
		t.Fatalf("schema checksum arguments = %#v", driver.queryArguments)
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

func TestPostgresJSONDatabaseUsesV13ReadinessOnlyForV13Marker(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaMarkerSQL:                    []byte(DiscoveryExecutionSchemaVersion),
		postgresDiscoveryExecutionSchemaVersionSQL: []byte(DiscoveryExecutionSchemaVersion),
	}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != DiscoveryExecutionSchemaVersion {
		t.Fatalf("version = (%q, %v)", version, err)
	}
	if !reflect.DeepEqual(driver.queryArguments, []any{expectedDiscoveryExecutionSchemaChecksum(), expectedDiscoveryExecutionSchemaFingerprint()}) {
		t.Fatalf("v13 schema checksum arguments = %#v", driver.queryArguments)
	}
}

func TestPostgresJSONDatabaseUsesV14ReadinessOnlyForV14Marker(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaMarkerSQL:                []byte(TypedInventorySchemaVersion),
		postgresTypedInventorySchemaVersionSQL: []byte(TypedInventorySchemaVersion),
	}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != TypedInventorySchemaVersion {
		t.Fatalf("version = (%q, %v)", version, err)
	}
	if !reflect.DeepEqual(driver.queryArguments, []any{expectedTypedInventorySchemaChecksum(), expectedTypedInventorySchemaFingerprint()}) {
		t.Fatalf("v14 schema checksum arguments = %#v", driver.queryArguments)
	}
}

func TestPostgresJSONDatabaseClassifiesMissingValidationAndConflict(t *testing.T) {
	for _, test := range []struct {
		name    string
		driver  *databaseDriver
		wantErr error
	}{
		{name: "no rows", driver: &databaseDriver{rowErr: pgx.ErrNoRows}, wantErr: ErrRepositoryNotFound},
		{name: "null payload", driver: &databaseDriver{responses: map[string][]byte{"SELECT payload": nil}}, wantErr: ErrRepositoryNotFound},
		{name: "validation", driver: &databaseDriver{rowErr: &pgconn.PgError{Code: "22023"}}, wantErr: ErrRepositoryOperation},
		{name: "conflict", driver: &databaseDriver{rowErr: &pgconn.PgError{Code: "23505"}}, wantErr: ErrRepositoryConflict},
		{name: "workflow missing", driver: &databaseDriver{rowErr: &pgconn.PgError{Code: "P0002"}}, wantErr: ErrRepositoryNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := NewPostgresJSONDatabase(test.driver)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.QueryJSON(context.Background(), "SELECT payload"); !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
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
	responses      map[string][]byte
	rowErr         error
	execErr        error
	execArguments  []any
	queryArguments []any
	closes         int
}

func (driver *databaseDriver) QueryRow(_ context.Context, statement string, arguments ...any) PostgresRow {
	driver.queryArguments = arguments
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
