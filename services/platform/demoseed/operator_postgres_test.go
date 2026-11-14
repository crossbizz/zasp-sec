package demoseed

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

// testDirectory is an identity provider that knows the Organizations and
// members a test gives it. It counts what a real provider would send.
type testDirectory struct {
	mutex         sync.Mutex
	organizations map[string]identity.DriverOrganization // by domain
	members       map[string]string                      // "reference email" to member reference
	invitations   int
}

func newTestDirectory() *testDirectory {
	return &testDirectory{organizations: map[string]identity.DriverOrganization{}, members: map[string]string{}}
}

func (directory *testDirectory) AuthenticateJWT(context.Context, string) (identity.DriverSession, error) {
	return identity.DriverSession{}, identity.ErrProvider
}
func (directory *testDirectory) RevalidateSession(context.Context, string) (identity.DriverSession, error) {
	return identity.DriverSession{}, identity.ErrProvider
}
func (directory *testDirectory) GetOrganization(context.Context, string) (identity.DriverOrganization, error) {
	return identity.DriverOrganization{}, identity.ErrProvider
}
func (directory *testDirectory) EnsureOrganization(_ context.Context, name, domainName string) (identity.DriverOrganization, error) {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	if existing, found := directory.organizations[domainName]; found {
		if existing.Name != name {
			return identity.DriverOrganization{}, identity.ErrProvider
		}
		return existing, nil
	}
	created := identity.DriverOrganization{Reference: "organization-test-" + strings.ReplaceAll(domainName, ".", "-"), Name: name, Domain: domainName}
	directory.organizations[domainName] = created
	return created, nil
}
func (directory *testDirectory) InviteAdmin(_ context.Context, organization, email string) (identity.DriverInvitation, error) {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	reference, found := directory.members[organization+" "+email]
	if !found {
		directory.invitations++
		reference = "member-test-" + strings.NewReplacer("@", "-", ".", "-").Replace(email) + "-" + organization[len("organization-test-"):]
		directory.members[organization+" "+email] = reference
	}
	return identity.DriverInvitation{MemberReference: reference, OrganizationReference: organization, Email: email}, nil
}
func (directory *testDirectory) FindMember(_ context.Context, organization, email string) (identity.DriverInvitation, bool, error) {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	reference, found := directory.members[organization+" "+email]
	if !found {
		return identity.DriverInvitation{}, false, nil
	}
	return identity.DriverInvitation{MemberReference: reference, OrganizationReference: organization, Email: email}, true, nil
}
func (directory *testDirectory) ListSSOConnections(context.Context, string) ([]identity.DriverSSOConnection, error) {
	return nil, identity.ErrProvider
}
func (directory *testDirectory) CreateSSOConnection(context.Context, string, identity.DriverSSOConfig) (identity.DriverSSOConnection, error) {
	return identity.DriverSSOConnection{}, identity.ErrProvider
}
func (directory *testDirectory) DeleteSSOConnection(context.Context, string, string) (string, error) {
	return "", identity.ErrProvider
}
func (directory *testDirectory) TestSSOConnection(context.Context, string, string) error {
	return identity.ErrProvider
}
func (directory *testDirectory) ListSCIMConnections(context.Context, string) ([]identity.DriverSCIMConnection, error) {
	return nil, identity.ErrProvider
}
func (directory *testDirectory) CreateSCIMConnection(context.Context, string, identity.DriverSCIMConfig) (identity.DriverSCIMCredential, error) {
	return identity.DriverSCIMCredential{}, identity.ErrProvider
}
func (directory *testDirectory) DeleteSCIMConnection(context.Context, string, string) (string, error) {
	return "", identity.ErrProvider
}

func (directory *testDirectory) adapter(t *testing.T) *identity.Adapter {
	t.Helper()
	adapter, err := identity.NewAdapter(directory, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

// operatorConnection connects as the migration operator of an installed
// baseline. ZASP_DEMO_OPERATOR_TEST_DSN names it: the zasp_operator role as
// `agentsec-migrate install-baseline` requires it (LOGIN, CREATEROLE,
// BYPASSRLS, owner of the database), which is not a superuser. The tests of
// this file prove that role is enough for every demo command.
func operatorConnection(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	dsn := os.Getenv("ZASP_DEMO_OPERATOR_TEST_DSN")
	if dsn == "" {
		t.Skip("ZASP_DEMO_OPERATOR_TEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	var user string
	var super bool
	if err := connection.QueryRow(ctx, `SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&user, &super); err != nil || user != "zasp_operator" || super {
		t.Fatalf("the test needs the non-superuser zasp_operator role, got %q superuser=%t err=%v", user, super, err)
	}
	return connection, ctx
}

func TestSeedAsTheOperator(t *testing.T) {
	connection, ctx := operatorConnection(t)
	directory := newTestDirectory()
	seeder, err := New(connection, directory.adapter(t), testWriter{t})
	if err != nil {
		t.Fatal(err)
	}
	report, err := seeder.Seed(ctx, Request{Email: "jordan.rivera@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", report)
	scopes, err := seeder.Status(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status %+v", scopes)
	if os.Getenv("ZASP_DEMO_TEST_REMOVE") == "1" {
		removals, err := seeder.Remove(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, removal := range removals {
			t.Logf("removed %+v", removal)
		}
	}
}

type testWriter struct{ t *testing.T }

func (writer testWriter) Write(line []byte) (int, error) {
	writer.t.Log(strings.TrimRight(string(line), "\n"))
	return len(line), nil
}
