// Package demoseed fills a dedicated scope of a deployment with the demo
// dataset of package demodata, shows what it filled, and removes it again.
//
// It is an operator tool, like the first-Organization bootstrap: it runs with
// the migration operator's database identity and is not reachable from the
// product API. It gives nobody a session. The person named by Email signs in
// the way every member does and sees the demo because they hold an ordinary
// membership and an ordinary authorized scope for the demo Environment.
//
// Confinement. Everything the seeder writes belongs to one Environment that
// holds nothing but demo data:
//
//   - by default a dedicated Organization, created through the same
//     provisioning the bootstrap command uses, with one Workspace and one
//     Environment;
//   - with ExistingOrganizationID, a dedicated Workspace and Environment
//     inside that Organization, visible only to the named member.
//
// The seeder refuses an Environment that holds an integration without the
// demo marker, and every statement it runs names that one Environment.
package demoseed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/zasp-ai/zasp-sec/services/platform/bootstrap"
	"github.com/zasp-ai/zasp-sec/services/platform/demodata"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

const (
	// datasetName is the value of the marker on every demo integration.
	datasetName = "northwind-robotics"
	// DefaultName names the dedicated Organization, Workspace and
	// Environment unless the operator chooses other names.
	DefaultName = "Zasp Demo"
	// DefaultExistingEnvironment names the Environment created inside an
	// existing Organization.
	DefaultExistingEnvironment = "Demo"
	// environmentClass is the class of the demo Environment. It is not
	// production: red team tests are refused in a production Environment.
	environmentClass = "staging"
)

var (
	// ErrInvalid means the request itself is malformed.
	ErrInvalid = errors.New("demo request is invalid")
	// ErrNotDemo means the target holds something that is not demo data.
	// Nothing was written.
	ErrNotDemo = errors.New("the scope holds data that is not demo data")
	// ErrNotMember means the address has no active membership in the
	// existing Organization. The seeder creates no membership there.
	ErrNotMember = errors.New("the address is not an active member of the organization")
	// ErrConflict means existing records disagree with the request.
	ErrConflict = errors.New("demo request conflicts with existing records")
	// ErrProvider means the identity provider refused.
	ErrProvider = errors.New("the identity provider refused")

	emailPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Directory is the identity provider boundary. identity.Adapter implements
// it. Seeding with ExistingOrganizationID calls FindMember only.
type Directory interface {
	bootstrap.Directory
	FindMember(ctx context.Context, organizationReference, email string) (identity.ExternalInvitation, bool, error)
}

// Request says who the demo is for and where it goes.
type Request struct {
	// Email is the person who will look at the demo, lower case.
	Email string
	// Organization, Workspace and Environment name the dedicated scope.
	// Empty selects the defaults.
	Organization, Workspace, Environment string
	// Domain is the email domain of the dedicated Organization: the
	// identity provider keys an Organization by it. Empty selects
	// "demo.<domain of Email>", which cannot collide with the person's own
	// Organization.
	Domain string
	// ExistingOrganizationID places the demo in a dedicated Workspace and
	// Environment of this Organization instead of a dedicated Organization.
	ExistingOrganizationID string
	// Dedicated forces the dedicated Organization.
	Dedicated bool
	// SignInOrganizationReference is the provider Organization the
	// deployment's sign-in is bound to, if any. When neither
	// ExistingOrganizationID nor Dedicated nor an Organization name or
	// Domain is given, and the person is an active member of the product
	// Organization bound to it, the demo goes into that Organization: it is
	// the one the person reaches by signing in. Otherwise the dedicated
	// Organization is used.
	SignInOrganizationReference string
	// Providers limits the dataset to these providers. Empty selects all.
	Providers []string
	// AuthorizationStoreID and AuthorizationModelID bind a new dedicated
	// Organization's permission projection, as the bootstrap does. Both or
	// neither.
	AuthorizationStoreID, AuthorizationModelID string
}

// IntegrationReport is what one demo integration received.
type IntegrationReport struct {
	Key, Name, Provider, ID string
	Created                 bool
	Entities                int
}

// Report is the result of a seeding.
type Report struct {
	OrganizationID, WorkspaceID, EnvironmentID string
	OrganizationName, EnvironmentName          string
	PrincipalID                                string
	// OrganizationCreated and MemberCreated are false when a repeated run
	// found them present. MemberCreated means the identity provider sent,
	// or had already sent, the person an invitation to the demo
	// Organization.
	OrganizationCreated, MemberCreated bool
	// Dedicated says the demo is in an Organization of its own.
	Dedicated                        bool
	Integrations                     []IntegrationReport
	Agents, OpenFindings, MCPServers int
	AttackPaths                      int
	Extras                           []string
	Skipped                          []string
}

// Seeder runs the demo commands on one operator connection.
type Seeder struct {
	database  *pgx.Conn
	directory Directory
	now       func() time.Time
	log       io.Writer
}

// New binds a seeder. directory may be nil for Status and Remove.
func New(database *pgx.Conn, directory Directory, log io.Writer) (*Seeder, error) {
	if database == nil {
		return nil, ErrInvalid
	}
	if log == nil {
		log = io.Discard
	}
	return &Seeder{database: database, directory: directory, now: func() time.Time { return time.Now().UTC() }, log: log}, nil
}

func (seeder *Seeder) say(format string, arguments ...any) {
	fmt.Fprintf(seeder.log, format+"\n", arguments...)
}

// normalize validates the request and fills the defaults.
func (request Request) normalize() (Request, error) {
	if !emailPattern.MatchString(request.Email) || len(request.Email) > 254 {
		return Request{}, fmt.Errorf("%w: the email address must be a lower-case address", ErrInvalid)
	}
	existing := request.ExistingOrganizationID != ""
	if existing {
		if _, err := domain.ParseProductID(request.ExistingOrganizationID); err != nil {
			return Request{}, fmt.Errorf("%w: the organization ID is not a product ID", ErrInvalid)
		}
		if request.Organization != "" || request.Domain != "" {
			return Request{}, fmt.Errorf("%w: an organization name or domain cannot be combined with an existing organization", ErrInvalid)
		}
	}
	if request.Organization == "" {
		request.Organization = DefaultName
	}
	if request.Workspace == "" {
		request.Workspace = DefaultName
	}
	if request.Environment == "" {
		request.Environment = DefaultName
		if existing {
			request.Environment = DefaultExistingEnvironment
		}
	}
	if request.Domain == "" {
		request.Domain = "demo." + request.Email[strings.LastIndex(request.Email, "@")+1:]
	}
	for _, name := range []string{request.Organization, request.Workspace, request.Environment} {
		if len(name) < 2 || len(name) > 64 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\x00\r\n\t") {
			return Request{}, fmt.Errorf("%w: a name must be 2 to 64 characters", ErrInvalid)
		}
	}
	if !domainPattern.MatchString(request.Domain) || len(request.Domain) > 253 {
		return Request{}, fmt.Errorf("%w: the domain must be a lower-case DNS name", ErrInvalid)
	}
	if (request.AuthorizationStoreID == "") != (request.AuthorizationModelID == "") {
		return Request{}, fmt.Errorf("%w: the authorization store and model are set together", ErrInvalid)
	}
	known := map[string]bool{}
	for _, provider := range demodata.Providers {
		known[provider] = true
	}
	for _, provider := range request.Providers {
		if !known[provider] {
			return Request{}, fmt.Errorf("%w: unknown provider %q (known: %s)", ErrInvalid, provider, strings.Join(demodata.Providers, ", "))
		}
	}
	sort.Strings(request.Providers)
	return request, nil
}

func (request Request) wants(provider string) bool {
	if len(request.Providers) == 0 {
		return true
	}
	for _, wanted := range request.Providers {
		if wanted == provider {
			return true
		}
	}
	return false
}
