package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a disposable database installed with the current schema
// profile (agentsec-migrate up-authorization-runtime-profile) and the
// migration operator's DSN in ZASP_BOOTSTRAP_TEST_DSN. They write uniquely
// named Organizations and leave them in place; never point them at a database
// that holds customer data.
func bootstrapTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ZASP_BOOTSTRAP_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_BOOTSTRAP_TEST_DSN is not set; installed-schema bootstrap store tests not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func uniqueRecords(t *testing.T) Records {
	t.Helper()
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(raw)
	return Records{
		Name: "Bootstrap Test " + suffix, Domain: suffix + ".bootstrap-test.example",
		OrganizationReference: "organization-test-" + suffix, MemberReference: "member-test-" + suffix,
	}
}

func provisionForTest(t *testing.T, pool *pgxpool.Pool, records Records) (Result, error) {
	t.Helper()
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return store.Provision(ctx, records)
}

func count(t *testing.T, pool *pgxpool.Pool, statement string, arguments ...any) int {
	t.Helper()
	var value int
	if err := pool.QueryRow(context.Background(), statement, arguments...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestPostgresStoreProvisionsOneOrganizationWithDefaultScopesAndIsIdempotent(t *testing.T) {
	pool := bootstrapTestPool(t)
	records := uniqueRecords(t)

	first, err := provisionForTest(t, pool, records)
	if err != nil || !first.OrganizationCreated || !first.AdminCreated {
		t.Fatalf("first provision = (%#v, %v)", first, err)
	}
	classes := map[string]string{}
	for _, environment := range first.Environments {
		classes[environment.Name] = environment.Class
	}
	if want := map[string]string{"Production": "production", "Staging": "staging", "Development": "development"}; !reflect.DeepEqual(classes, want) {
		t.Fatalf("environments = %#v", first.Environments)
	}

	var name, domainName string
	if err := pool.QueryRow(context.Background(), `SELECT name, domain FROM zasp_organizations WHERE id=$1`, first.OrganizationID).Scan(&name, &domainName); err != nil || name != records.Name || domainName != records.Domain {
		t.Fatalf("organization row = (%q, %q, %v)", name, domainName, err)
	}
	var role string
	var active bool
	if err := pool.QueryRow(context.Background(), `SELECT role, active FROM zasp_identity_memberships WHERE organization_reference=$1 AND member_reference=$2 AND organization_id=$3 AND principal_id=$4`,
		records.OrganizationReference, records.MemberReference, first.OrganizationID, first.PrincipalID).Scan(&role, &active); err != nil || role != "organization_admin" || !active {
		t.Fatalf("membership = (%q, %v, %v)", role, active, err)
	}
	// The administrator holds the full administrator permission set in every
	// default Environment, and exactly one of them is the default scope.
	rows, err := pool.Query(context.Background(), `SELECT label, is_default, permissions::text FROM zasp_authorized_scopes WHERE principal_id=$1 AND organization_id=$2 AND workspace_id=$3 ORDER BY label`, first.PrincipalID, first.OrganizationID, first.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	type scope struct {
		Label       string
		Default     bool
		Permissions string
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowToStructByPos[scope])
	if err != nil {
		t.Fatal(err)
	}
	permissions := `["investigate_sessions", "manage_api_tokens", "manage_data_controls", "manage_findings", "manage_identity", "manage_workflows", "revoke_sessions", "run_tests", "view", "view_audit", "view_compliance"]`
	if want := []scope{{"Development", false, permissions}, {"Production", true, permissions}, {"Staging", false, permissions}}; !reflect.DeepEqual(scopes, want) {
		t.Fatalf("scopes = %#v", scopes)
	}
	// Production data collection starts metadata-only, as the plan requires.
	if got := count(t, pool, `SELECT count(*) FROM zasp_data_controls WHERE organization_id=$1 AND collection_mode='metadata_only'`, first.OrganizationID); got != 3 {
		t.Fatalf("data controls = %d", got)
	}

	second, err := provisionForTest(t, pool, records)
	if err != nil || second.OrganizationCreated || second.AdminCreated {
		t.Fatalf("repeated provision = (%#v, %v)", second, err)
	}
	second.OrganizationCreated, second.AdminCreated = true, true
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated provision changed records:\n first %#v\nsecond %#v", first, second)
	}
	for statement, want := range map[string]int{
		`SELECT count(*) FROM zasp_organizations WHERE domain=$1`:                                                                1,
		`SELECT count(*) FROM zasp_workspaces w JOIN zasp_organizations o ON o.id=w.organization_id WHERE o.domain=$1`:           1,
		`SELECT count(*) FROM zasp_environments e JOIN zasp_organizations o ON o.id=e.organization_id WHERE o.domain=$1`:         3,
		`SELECT count(*) FROM zasp_identity_memberships m JOIN zasp_organizations o ON o.id=m.organization_id WHERE o.domain=$1`: 1,
		`SELECT count(*) FROM zasp_authorized_scopes s JOIN zasp_organizations o ON o.id=s.organization_id WHERE o.domain=$1`:    3,
	} {
		if got := count(t, pool, statement, records.Domain); got != want {
			t.Fatalf("%s = %d, want %d", statement, got, want)
		}
	}
}

func TestPostgresStoreMapsEachProviderOrganizationToItsOwnProductOrganization(t *testing.T) {
	pool := bootstrapTestPool(t)
	a, errA := provisionForTest(t, pool, uniqueRecords(t))
	b, errB := provisionForTest(t, pool, uniqueRecords(t))
	if errA != nil || errB != nil {
		t.Fatalf("provision = (%v, %v)", errA, errB)
	}
	if a.OrganizationID == b.OrganizationID || a.WorkspaceID == b.WorkspaceID || a.PrincipalID == b.PrincipalID {
		t.Fatalf("organizations share records: %#v %#v", a, b)
	}
	// Neither administrator holds any scope in the other Organization.
	if got := count(t, pool, `SELECT count(*) FROM zasp_authorized_scopes WHERE principal_id=$1 AND organization_id=$2 OR principal_id=$3 AND organization_id=$4`, a.PrincipalID, b.OrganizationID, b.PrincipalID, a.OrganizationID); got != 0 {
		t.Fatalf("cross-organization scopes = %d", got)
	}
}

func TestPostgresStoreSerializesConcurrentProvisioningOfOneProviderOrganization(t *testing.T) {
	pool := bootstrapTestPool(t)
	records := uniqueRecords(t)
	const attempts = 6
	results := make([]Result, attempts)
	failures := make([]error, attempts)
	var group sync.WaitGroup
	for index := range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			results[index], failures[index] = provisionForTest(t, pool, records)
		}()
	}
	group.Wait()
	created := 0
	for index := range attempts {
		if failures[index] != nil {
			t.Fatalf("attempt %d: %v", index, failures[index])
		}
		if results[index].OrganizationID != results[0].OrganizationID || results[index].PrincipalID != results[0].PrincipalID {
			t.Fatalf("attempt %d resolved different records", index)
		}
		if results[index].OrganizationCreated {
			created++
		}
	}
	if created != 1 || count(t, pool, `SELECT count(*) FROM zasp_organizations WHERE domain=$1`, records.Domain) != 1 {
		t.Fatalf("organizations created = %d", created)
	}
}

func TestPostgresStoreAddsASecondAdministratorToTheSameOrganization(t *testing.T) {
	pool := bootstrapTestPool(t)
	records := uniqueRecords(t)
	first, err := provisionForTest(t, pool, records)
	if err != nil {
		t.Fatal(err)
	}
	other := records
	other.MemberReference += "-second"
	second, err := provisionForTest(t, pool, other)
	if err != nil || second.OrganizationID != first.OrganizationID || second.OrganizationCreated || !second.AdminCreated || second.PrincipalID == first.PrincipalID {
		t.Fatalf("second administrator = (%#v, %v)", second, err)
	}
}

func TestPostgresStoreRefusesRecordsThatDisagreeAndWritesNothing(t *testing.T) {
	pool := bootstrapTestPool(t)
	records := uniqueRecords(t)
	first, err := provisionForTest(t, pool, records)
	if err != nil {
		t.Fatal(err)
	}

	pinned := records
	pinned.OrganizationID = "pid_10000001-0000-4000-8000-0000000000aa"
	if _, err := provisionForTest(t, pool, pinned); !errors.Is(err, ErrConflict) {
		t.Fatalf("different pinned organization = %v", err)
	}

	// A new provider Organization may not claim an existing product ID.
	stolen := uniqueRecords(t)
	stolen.OrganizationID = first.OrganizationID
	if _, err := provisionForTest(t, pool, stolen); !errors.Is(err, ErrConflict) {
		t.Fatalf("claimed existing organization = %v", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM zasp_identity_memberships WHERE organization_reference=$1`, stolen.OrganizationReference); got != 0 {
		t.Fatalf("membership written for refused organization = %d", got)
	}

	// Bootstrap never reactivates or promotes a membership an administrator
	// has since changed.
	for name, change := range map[string]string{
		"deactivated": `UPDATE zasp_identity_memberships SET active=false WHERE organization_reference=$1 AND member_reference=$2`,
		"demoted":     `UPDATE zasp_identity_memberships SET active=true, role='read_only_viewer' WHERE organization_reference=$1 AND member_reference=$2`,
	} {
		if _, err := pool.Exec(context.Background(), change, records.OrganizationReference, records.MemberReference); err != nil {
			t.Fatal(err)
		}
		if _, err := provisionForTest(t, pool, records); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s membership = %v", name, err)
		}
	}
	var role string
	if err := pool.QueryRow(context.Background(), `SELECT role FROM zasp_identity_memberships WHERE organization_reference=$1 AND member_reference=$2`, records.OrganizationReference, records.MemberReference).Scan(&role); err != nil || role != "read_only_viewer" {
		t.Fatalf("membership role after refusal = (%q, %v)", role, err)
	}
}

func TestPostgresStoreRecordsAPendingPermissionProjectionAndBindsItOnce(t *testing.T) {
	pool := bootstrapTestPool(t)
	result, err := provisionForTest(t, pool, uniqueRecords(t))
	if err != nil {
		t.Fatal(err)
	}
	read := func() (desired, applied int64, storeID, modelID, blocked string) {
		t.Helper()
		if err := pool.QueryRow(context.Background(), `SELECT desired, applied, store_id, model_id, blocked_reason FROM zasp_authorization79.organizations WHERE organization_id=$1`, result.OrganizationID).Scan(&desired, &applied, &storeID, &modelID, &blocked); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Permissions stay unavailable until the projector applies them: the
	// installed triggers recorded a desired revision and nothing is applied.
	desired, applied, storeID, _, blocked := read()
	if desired < 1 || applied != 0 || storeID != "" || blocked == "" {
		t.Fatalf("projection after provision = desired %d applied %d store %q blocked %q", desired, applied, storeID, blocked)
	}
	store, err := NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	// Authorization store and model identifiers are 26-character ULIDs.
	const storeULID, modelULID = "01HZX0B00TSTRAPTESTST0RE01", "01HZX0B00TSTRAPTESTM0DE001"
	if err := store.BindAuthorization(context.Background(), result.OrganizationID, storeULID, modelULID); err != nil {
		t.Fatal(err)
	}
	bound, applied, storeID, modelID, blocked := read()
	if storeID != storeULID || modelID != modelULID || applied != 0 || blocked != "pending" || bound < desired {
		t.Fatalf("projection after binding = desired %d applied %d store %q model %q blocked %q", bound, applied, storeID, modelID, blocked)
	}
	if err := store.BindAuthorization(context.Background(), result.OrganizationID, storeULID, modelULID); err != nil {
		t.Fatal(err)
	}
	if again, _, _, _, _ := read(); again != bound {
		t.Fatalf("repeated binding forced a replay: desired %d -> %d", bound, again)
	}
}
