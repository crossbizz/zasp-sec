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
	for _, release := range []struct{ statement, version, name, readiness string }{
		{postgresRuntimeDataPlaneSchemaVersionSQL, "15", "runtime_data_plane", "zasp_runtime_data_plane_readiness($1, $2)"},
		{postgresRuntimeGatewayReconciliationSchemaVersionSQL, "16", "runtime_gateway_reconciliation", "zasp_runtime_gateway_reconciliation_readiness($1, $2)"},
		{postgresRuntimeIngestReconciliationSchemaVersionSQL, "17", "runtime_ingest_reconciliation", "zasp_runtime_ingest_reconciliation_readiness($1, $2)"},
	} {
		if !strings.Contains(release.statement, "release.version = "+release.version) || !strings.Contains(release.statement, "release.name = '"+release.name+"'") || !strings.Contains(release.statement, release.readiness) {
			t.Fatalf("v%s schema readiness query does not require exact release readiness: %s", release.version, release.statement)
		}
	}
	if !strings.Contains(postgresSecurityAgentExecutionSchemaVersionSQL, "release.version = 18") || !strings.Contains(postgresSecurityAgentExecutionSchemaVersionSQL, "release.name = 'security_agent_execution'") || !strings.Contains(postgresSecurityAgentExecutionSchemaVersionSQL, "zasp_security_agent_readiness($1, $2)") {
		t.Fatalf("v18 schema readiness query does not require security agent execution readiness: %s", postgresSecurityAgentExecutionSchemaVersionSQL)
	}
	if !strings.Contains(postgresSecurityAgentControlsSchemaVersionSQL, "release.version = 20") || !strings.Contains(postgresSecurityAgentControlsSchemaVersionSQL, "release.name = 'security_agent_controls'") || !strings.Contains(postgresSecurityAgentControlsSchemaVersionSQL, "zasp_security_agent_controls_readiness($1, $2)") {
		t.Fatalf("v20 schema readiness query does not require security agent controls readiness: %s", postgresSecurityAgentControlsSchemaVersionSQL)
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

func TestPostgresJSONDatabaseUsesV15ReadinessOnlyForV15Marker(t *testing.T) {
	for _, test := range []struct {
		release, version, statement string
		checksum, fingerprint       string
	}{
		{"15", RuntimeDataPlaneSchemaVersion, postgresRuntimeDataPlaneSchemaVersionSQL, expectedRuntimeDataPlaneSchemaChecksum(), expectedRuntimeDataPlaneSchemaFingerprint()},
		{"16", RuntimeGatewayReconciliationSchemaVersion, postgresRuntimeGatewayReconciliationSchemaVersionSQL, expectedRuntimeGatewayReconciliationSchemaChecksum(), expectedRuntimeGatewayReconciliationSchemaFingerprint()},
		{"17", RuntimeIngestReconciliationSchemaVersion, postgresRuntimeIngestReconciliationSchemaVersionSQL, expectedRuntimeIngestReconciliationSchemaChecksum(), expectedRuntimeIngestReconciliationSchemaFingerprint()},
	} {
		t.Run(test.release, func(t *testing.T) {
			driver := &databaseDriver{responses: map[string][]byte{postgresSchemaMarkerSQL: []byte(RuntimeDataPlaneSchemaVersion), postgresRuntimeDataPlaneReleaseSQL: []byte(test.release), test.statement: []byte(test.version)}}
			database, err := NewPostgresJSONDatabase(driver)
			if err != nil {
				t.Fatal(err)
			}
			version, err := database.SchemaVersion(context.Background())
			if err != nil || version != test.version {
				t.Fatalf("version = (%q, %v)", version, err)
			}
			if !reflect.DeepEqual(driver.queryArguments, []any{test.checksum, test.fingerprint}) {
				t.Fatalf("v%s schema checksum arguments = %#v", test.release, driver.queryArguments)
			}
		})
	}
}

func TestPostgresJSONDatabaseUsesV18ReadinessOnlyForV18Marker(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaMarkerSQL:                        []byte(SecurityAgentExecutionSchemaVersion),
		postgresSecurityAgentExecutionSchemaVersionSQL: []byte(SecurityAgentExecutionSchemaVersion),
	}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != SecurityAgentExecutionSchemaVersion {
		t.Fatalf("version = (%q, %v)", version, err)
	}
	if !reflect.DeepEqual(driver.queryArguments, []any{expectedSecurityAgentExecutionSchemaChecksum(), expectedSecurityAgentExecutionSchemaFingerprint()}) {
		t.Fatalf("v18 schema checksum arguments = %#v", driver.queryArguments)
	}
}

func TestPostgresJSONDatabaseUsesV20ReadinessOnlyForV20Marker(t *testing.T) {
	driver := &databaseDriver{responses: map[string][]byte{
		postgresSchemaMarkerSQL:                       []byte(SecurityAgentControlsSchemaVersion),
		postgresSecurityAgentControlsSchemaVersionSQL: []byte(SecurityAgentControlsSchemaVersion),
	}}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	version, err := database.SchemaVersion(context.Background())
	if err != nil || version != SecurityAgentControlsSchemaVersion {
		t.Fatalf("version = (%q, %v)", version, err)
	}
	if !reflect.DeepEqual(driver.queryArguments, []any{expectedSecurityAgentControlsSchemaChecksum(), expectedSecurityAgentControlsSchemaFingerprint()}) {
		t.Fatalf("v20 schema checksum arguments = %#v", driver.queryArguments)
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
