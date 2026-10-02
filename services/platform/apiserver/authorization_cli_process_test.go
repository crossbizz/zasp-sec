package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// This runs the built operator executable, not the reconciliation Go helper.
// The private PostgreSQL owner is joined by the existing fixture. FGA/Temporal
// are borrowed; only a freshly created FGA store receives tuples/model writes.
func TestP7AuthorizationCLIProcessConfigureReconcileRepair(t *testing.T) {
	if os.Getenv("ZASP_P7_AUTHORIZATION_CLI_TEST") != "1" {
		t.Skip("requires owned PostgreSQL and retained local FGA/Temporal services")
	}
	for _, program := range []string{"go", "docker", "initdb", "postgres", "pg_ctl", "pg_isready"} {
		if _, err := exec.LookPath(program); err != nil {
			t.Fatalf("required local program unavailable: %s", program)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "zasp-authorization-reconcile")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "../cmd/zasp-authorization-reconcile")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("CLI build failed: %v\n%s", err, output)
	}
	t.Log("built real cmd/zasp-authorization-reconcile executable")
	dsn := startDisposablePostgres(t)
	owner, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned PostgreSQL connection failed")
	}
	defer owner.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, owner)
	for _, up := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution, runner.UpProductionAuthorizationProjection} {
		if err := up(ctx); err != nil {
			t.Fatalf("registered CLI prerequisites: %v", err)
		}
	}
	execute := func(query string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"cli_api_login", "cli_discovery_login", "cli_ingest_login", "cli_runtime_login", "cli_outbox_login", "cli_gateway_login"} {
		execute(fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, name))
	}
	execute(`SELECT zasp_discovery_register_principals(session_user,'cli_api_login','cli_discovery_login','cli_ingest_login','cli_runtime_login','cli_outbox_login','cli_gateway_login')`)
	workerURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("owned PostgreSQL worker configuration failed")
	}
	workerURL.User = url.User("cli_outbox_login")
	workerDSN := workerURL.String()
	identity := fixtureRequestIdentity(t)
	o, w, e, principal := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	const queuedFirst = "pid_79100001-0000-4000-8000-000000000001"
	execute(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'CLI queue first','cli-first.invalid')`, queuedFirst)
	execute(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'CLI target','cli-target.invalid')`, o)
	execute(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'CLI target')`, o, w)
	execute(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'CLI target','production')`, o, w, e)
	execute(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-cli','member-cli','security_admin',true)`, principal, o)
	execute(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'CLI target','["view"]',true)`, principal, o, w, e)
	fgaClient, config := newAuthorizationProjectionFGA(t)
	config.Namespace = "zasp-dev"
	config.FGATokenFile = authorizationCLITokenFile(t, ctx)
	checker, err := authorization.NewOpenFGA(fgaClient, config)
	if err != nil {
		t.Fatal(err)
	}
	check := authorization.CheckRequest{PrincipalKind: "user", PrincipalID: principal, OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ResourceType: "environment", ResourceID: e, Permission: "manage_identity"}
	invoke := func(database string, wantExit int, arguments ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, binary, append(arguments, "-timeout=30s")...)
		command.Env = authorizationCLIEnvironment(database, config)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		exit := 0
		if err != nil {
			var process *exec.ExitError
			if !errors.As(err, &process) {
				t.Fatalf("CLI process did not exit normally: %v", err)
			}
			exit = process.ExitCode()
		}
		t.Logf("CLI %s -timeout=30s exit=%d stdout=%s stderr=%s", strings.Join(arguments, " "), exit, strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()))
		if exit != wantExit || wantExit == 0 && stderr.Len() != 0 {
			t.Fatalf("CLI exit=%d, want=%d", exit, wantExit)
		}
		return stdout.Bytes()
	}
	decodeConfiguration := func(output []byte) authorization.PendingProjection {
		t.Helper()
		var value authorization.PendingProjection
		if json.Unmarshal(output, &value) != nil || value.StoreID != config.StoreID || value.ModelID != config.ModelID || value.Generation < 1 || value.PendingSince.IsZero() {
			t.Fatalf("invalid configure output: %s", output)
		}
		return value
	}
	decodeStatus := func(output []byte, org string) authorizationCLIStatus {
		t.Helper()
		var value authorizationCLIStatus
		if json.Unmarshal(output, &value) != nil || value.OrganizationID != org || value.Status != "applied" || !value.Receipt.Applied || value.Receipt.Revision.OrganizationID != org || value.Receipt.Revision.Desired != value.Receipt.Revision.Applied {
			t.Fatalf("invalid process receipt: %s", output)
		}
		return value
	}
	decodeConfiguration(invoke(dsn, 0, "-mode=configure", "-organization="+queuedFirst))
	initial := decodeConfiguration(invoke(dsn, 0, "-mode=configure", "-organization="+o))
	if got := decodeConfiguration(invoke(dsn, 0, "-mode=configure", "-organization="+o)); got.Revision != initial.Revision {
		t.Fatal("unchanged configure rewrote generation/revision")
	}
	var first string
	if err := owner.QueryRow(ctx, `SELECT organization_id FROM zasp_authorization79.organizations WHERE desired<>applied ORDER BY COALESCE(last_attempt_at,pending_since),organization_id LIMIT 1`).Scan(&first); err != nil || first != queuedFirst {
		t.Fatal("target was not outside the queue limit")
	}
	outside := decodeStatus(invoke(workerDSN, 0, "-mode=reconcile", "-organization="+o, "-limit=1"), o)
	if outside.PendingSince != nil {
		t.Errorf("outside-limit timestamp must be omitted when unavailable, got %s", outside.PendingSince.Format(time.RFC3339Nano))
	}
	if outside.Receipt.TupleCount < 1 {
		t.Fatal("CLI did not project real source tuples")
	}
	if decision, err := checker.Check(ctx, check); err != nil || !decision.Allowed {
		t.Fatal("CLI receipt did not correspond to applied FGA grant", err)
	}
	// Repair must re-read current source; the prior elevated role must disappear.
	execute(`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1 AND principal_id=$2`, o, principal)
	repaired := decodeConfiguration(invoke(dsn, 0, "-mode=configure", "-organization="+o, "-repair"))
	if repaired.Generation != initial.Generation+1 || repaired.Desired <= initial.Desired {
		t.Fatal("repair did not create a new pending generation")
	}
	known := decodeStatus(invoke(workerDSN, 0, "-mode=reconcile", "-organization="+o, "-limit=100"), o)
	if known.PendingSince == nil || !known.PendingSince.Equal(repaired.PendingSince) {
		t.Errorf("known pending timestamp lost: got=%v want=%s", known.PendingSince, repaired.PendingSince.Format(time.RFC3339Nano))
	}
	if known.Receipt.Revision.Generation != repaired.Generation {
		t.Fatal("CLI applied wrong repair generation")
	}
	if decision, err := checker.Check(ctx, check); err != nil || decision.Allowed {
		t.Fatal("CLI repair retained revoked elevated role", err)
	}
	queued := decodeStatus(invoke(workerDSN, 0, "-mode=reconcile", "-limit=1"), queuedFirst)
	if queued.PendingSince == nil || queued.PendingSince.IsZero() {
		t.Fatal("queue-wide mode lost its pending timestamp")
	}
	var receipts, targetReceipts, unapplied int
	if err := owner.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE organization_id=$1) FROM zasp_authorization79.receipts`, o).Scan(&receipts, &targetReceipts); err != nil || receipts != 3 || targetReceipts != 2 {
		t.Fatalf("CLI durable receipts total=%d target=%d: %v", receipts, targetReceipts, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization79.organizations WHERE desired<>applied`).Scan(&unapplied); err != nil || unapplied != 0 {
		t.Fatal("CLI queue did not settle", err)
	}
	if output := invoke(workerDSN, 1, "-mode=configure", "-organization="+o, "-repair"); len(output) != 0 {
		t.Fatal("outbox principal emitted configuration success")
	}
	var currentGeneration int64
	if err := owner.QueryRow(ctx, `SELECT generation FROM zasp_authorization79.organizations WHERE organization_id=$1`, o).Scan(&currentGeneration); err != nil || currentGeneration != repaired.Generation {
		t.Fatal("rejected principal changed configuration", err)
	}
	t.Logf("actual CLI configure/reconcile/repair: %d durable SQL receipts, target receipts=%d; real FGA grant applied then revoked; Temporal readiness dependency=%s/%s", receipts, targetReceipts, config.TemporalAddress, config.Namespace)
}

type authorizationCLIStatus struct {
	OrganizationID string                          `json:"organization_id"`
	Status         string                          `json:"status"`
	Receipt        authorization.ProjectionReceipt `json:"receipt"`
	PendingSince   *time.Time                      `json:"pending_since"`
}

func authorizationCLIEnvironment(dsn string, config runtimeservices.Config) []string {
	values := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ZASP_") {
			values = append(values, entry)
		}
	}
	for key, value := range map[string]string{
		"ZASP_POSTGRES_DSN": dsn, "ZASP_RUNTIME_SERVICES_ENABLED": "true", "ZASP_ENVIRONMENT": "test",
		"ZASP_RUNTIME_SERVICES_TIMEOUT": config.Timeout.String(), "ZASP_TEMPORAL_ADDRESS": config.TemporalAddress,
		"ZASP_TEMPORAL_NAMESPACE": config.Namespace, "ZASP_TEMPORAL_TASK_QUEUE": config.TaskQueue, "ZASP_TEMPORAL_DISCOVERY_TASK_QUEUE": config.DiscoveryTaskQueue,
		"ZASP_OPENFGA_URL": config.FGAURL, "ZASP_OPENFGA_STORE_ID": config.StoreID, "ZASP_OPENFGA_MODEL_ID": config.ModelID, "ZASP_OPENFGA_TOKEN_FILE": config.FGATokenFile,
	} {
		values = append(values, key+"="+value)
	}
	return values
}

func authorizationCLITokenFile(t *testing.T, ctx context.Context) string {
	t.Helper()
	data, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{json .Config.Env}}", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("retained local credential inspection unavailable")
	}
	var environment []string
	if json.Unmarshal(data, &environment) != nil {
		t.Fatal("retained local credential metadata invalid")
	}
	token := ""
	for _, entry := range environment {
		if strings.HasPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(entry, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.ContainsAny(token, ",\r\n\t ") {
		t.Fatal("retained local credential unavailable")
	}
	path := filepath.Join(t.TempDir(), "openfga-token")
	if os.WriteFile(path, []byte(token), 0600) != nil {
		t.Fatal("owned credential file unavailable")
	}
	return path
}
