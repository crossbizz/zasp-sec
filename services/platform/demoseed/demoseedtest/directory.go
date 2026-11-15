// Package demoseedtest is the test kit of the demo seeder: an identity
// provider that lives in memory, for tests that run the seeder without a
// provider project.
package demoseedtest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

// Directory is an identity provider that knows the Organizations and
// members a test gives it. It counts what a real provider would send.
type Directory struct {
	mutex         sync.Mutex
	organizations map[string]identity.DriverOrganization // by domain
	members       map[string]string                      // "reference email" to member reference
	invitations   int
}

func NewDirectory() *Directory {
	return &Directory{organizations: map[string]identity.DriverOrganization{}, members: map[string]string{}}
}

func (directory *Directory) AuthenticateJWT(context.Context, string) (identity.DriverSession, error) {
	return identity.DriverSession{}, identity.ErrProvider
}
func (directory *Directory) RevalidateSession(context.Context, string) (identity.DriverSession, error) {
	return identity.DriverSession{}, identity.ErrProvider
}
func (directory *Directory) GetOrganization(context.Context, string) (identity.DriverOrganization, error) {
	return identity.DriverOrganization{}, identity.ErrProvider
}
func (directory *Directory) EnsureOrganization(_ context.Context, name, domainName string) (identity.DriverOrganization, error) {
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
func (directory *Directory) InviteAdmin(_ context.Context, organization, email string) (identity.DriverInvitation, error) {
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
func (directory *Directory) FindMember(_ context.Context, organization, email string) (identity.DriverInvitation, bool, error) {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	reference, found := directory.members[organization+" "+email]
	if !found {
		return identity.DriverInvitation{}, false, nil
	}
	return identity.DriverInvitation{MemberReference: reference, OrganizationReference: organization, Email: email}, true, nil
}
func (directory *Directory) ListSSOConnections(context.Context, string) ([]identity.DriverSSOConnection, error) {
	return nil, identity.ErrProvider
}
func (directory *Directory) CreateSSOConnection(context.Context, string, identity.DriverSSOConfig) (identity.DriverSSOConnection, error) {
	return identity.DriverSSOConnection{}, identity.ErrProvider
}
func (directory *Directory) DeleteSSOConnection(context.Context, string, string) (string, error) {
	return "", identity.ErrProvider
}
func (directory *Directory) TestSSOConnection(context.Context, string, string) error {
	return identity.ErrProvider
}
func (directory *Directory) ListSCIMConnections(context.Context, string) ([]identity.DriverSCIMConnection, error) {
	return nil, identity.ErrProvider
}
func (directory *Directory) CreateSCIMConnection(context.Context, string, identity.DriverSCIMConfig) (identity.DriverSCIMCredential, error) {
	return identity.DriverSCIMCredential{}, identity.ErrProvider
}
func (directory *Directory) DeleteSCIMConnection(context.Context, string, string) (string, error) {
	return "", identity.ErrProvider
}

// Adapter is the identity adapter the seeder is given, over this directory.
func (directory *Directory) Adapter(t testing.TB) *identity.Adapter {
	t.Helper()
	adapter, err := identity.NewAdapter(directory, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

// Invitations is how many invitations a real provider would have sent.
func (directory *Directory) Invitations() int {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	return directory.invitations
}

// AddMember makes an address a member of a provider Organization without
// an invitation, as a person who joined earlier is, and returns the member
// reference.
func (directory *Directory) AddMember(organization, email, reference string) {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	directory.members[organization+" "+email] = reference
}
