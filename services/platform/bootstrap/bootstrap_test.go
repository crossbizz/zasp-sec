package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/identity"
)

// fakeDriver is the provider behind a real identity.Adapter, so these tests
// exercise the adapter's own validation of provider responses.
type fakeDriver struct {
	identity.StytchDriver
	organization                   identity.DriverOrganization
	invitation                     identity.DriverInvitation
	organizationErr, invitationErr error
	calls                          []string
}

func (driver *fakeDriver) EnsureOrganization(_ context.Context, name, domainName string) (identity.DriverOrganization, error) {
	driver.calls = append(driver.calls, "organization:"+name+":"+domainName)
	return driver.organization, driver.organizationErr
}

func (driver *fakeDriver) InviteAdmin(_ context.Context, organization, email string) (identity.DriverInvitation, error) {
	driver.calls = append(driver.calls, "invite:"+organization+":"+email)
	return driver.invitation, driver.invitationErr
}

type fakeStore struct {
	records []Records
	result  Result
	err     error
}

func (store *fakeStore) Provision(_ context.Context, records Records) (Result, error) {
	store.records = append(store.records, records)
	return store.result, store.err
}

func newTestProvisioner(t *testing.T, driver *fakeDriver, store *fakeStore) *Provisioner {
	t.Helper()
	adapter, err := identity.NewAdapter(driver, func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	provisioner, err := NewProvisioner(adapter, store)
	if err != nil {
		t.Fatal(err)
	}
	return provisioner
}

func acmeDriver() *fakeDriver {
	return &fakeDriver{
		organization: identity.DriverOrganization{Reference: "organization-test-acme", Name: "Acme Security", Domain: "acme.example"},
		invitation:   identity.DriverInvitation{MemberReference: "member-test-admin", OrganizationReference: "organization-test-acme", Email: "admin@acme.example"},
	}
}

var acmeRequest = Request{Name: "Acme Security", Domain: "acme.example", AdminEmail: "admin@acme.example"}

func TestProvisionPersistsOnlyProviderConfirmedReferences(t *testing.T) {
	driver, store := acmeDriver(), &fakeStore{result: Result{OrganizationID: "pid_10000001-0000-4000-8000-000000000001"}}
	result, err := newTestProvisioner(t, driver, store).Provision(context.Background(), acmeRequest)
	if err != nil || result.OrganizationID != store.result.OrganizationID {
		t.Fatalf("provision = (%#v, %v)", result, err)
	}
	if want := []string{"organization:Acme Security:acme.example", "invite:organization-test-acme:admin@acme.example"}; !reflect.DeepEqual(driver.calls, want) {
		t.Fatalf("provider calls = %v", driver.calls)
	}
	want := []Records{{Name: "Acme Security", Domain: "acme.example", OrganizationReference: "organization-test-acme", MemberReference: "member-test-admin"}}
	if !reflect.DeepEqual(store.records, want) {
		t.Fatalf("stored records = %#v", store.records)
	}
}

func TestProvisionWritesNothingWhenTheProviderDoesNotConfirmTheRequest(t *testing.T) {
	for name, change := range map[string]func(*fakeDriver){
		"organization unavailable":           func(driver *fakeDriver) { driver.organizationErr = errors.New("provider down") },
		"organization for another customer":  func(driver *fakeDriver) { driver.organization.Domain = "other.example" },
		"organization renamed by provider":   func(driver *fakeDriver) { driver.organization.Name = "Someone Else" },
		"invitation unavailable":             func(driver *fakeDriver) { driver.invitationErr = errors.New("provider down") },
		"invitation for another member":      func(driver *fakeDriver) { driver.invitation.Email = "intruder@acme.example" },
		"invitation in another organization": func(driver *fakeDriver) { driver.invitation.OrganizationReference = "organization-test-other" },
		"invitation without member":          func(driver *fakeDriver) { driver.invitation.MemberReference = "" },
	} {
		t.Run(name, func(t *testing.T) {
			driver, store := acmeDriver(), &fakeStore{}
			change(driver)
			if _, err := newTestProvisioner(t, driver, store).Provision(context.Background(), acmeRequest); err == nil {
				t.Fatal("provision succeeded")
			}
			if len(store.records) != 0 {
				t.Fatalf("product records written: %#v", store.records)
			}
		})
	}
}

func TestProvisionRefusesMalformedOperatorInputBeforeCallingTheProvider(t *testing.T) {
	for name, request := range map[string]Request{
		"empty name":          {Domain: "acme.example", AdminEmail: "admin@acme.example"},
		"upper case domain":   {Name: "Acme Security", Domain: "Acme.example", AdminEmail: "admin@acme.example"},
		"single label domain": {Name: "Acme Security", Domain: "acme", AdminEmail: "admin@acme.example"},
		"malformed pinned id": {Name: "Acme Security", Domain: "acme.example", AdminEmail: "admin@acme.example", OrganizationID: "acme"},
	} {
		t.Run(name, func(t *testing.T) {
			driver, store := acmeDriver(), &fakeStore{}
			if _, err := newTestProvisioner(t, driver, store).Provision(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("provision error = %v", err)
			}
			if len(driver.calls) != 0 || len(store.records) != 0 {
				t.Fatalf("provider calls %v, records %v", driver.calls, store.records)
			}
		})
	}
	// A malformed administrator address is refused before any invitation,
	// after the Organization has been resolved.
	driver, store := acmeDriver(), &fakeStore{}
	request := acmeRequest
	request.AdminEmail = "Admin@acme.example"
	if _, err := newTestProvisioner(t, driver, store).Provision(context.Background(), request); !errors.Is(err, ErrInvalid) || len(store.records) != 0 {
		t.Fatalf("provision error = %v, records %v", err, store.records)
	}
	if want := []string{"organization:Acme Security:acme.example"}; !reflect.DeepEqual(driver.calls, want) {
		t.Fatalf("provider calls = %v", driver.calls)
	}
}

func TestProvisionCarriesAPinnedOrganizationAndReportsStoreConflicts(t *testing.T) {
	driver, store := acmeDriver(), &fakeStore{err: ErrConflict}
	request := acmeRequest
	request.OrganizationID = "pid_10000001-0000-4000-8000-000000000001"
	if _, err := newTestProvisioner(t, driver, store).Provision(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("provision error = %v", err)
	}
	if len(store.records) != 1 || store.records[0].OrganizationID != request.OrganizationID {
		t.Fatalf("stored records = %#v", store.records)
	}
}

// A deployment bound to one provider Organization refuses a request that
// resolves to another before any invitation is sent.
func TestProvisionRefusesAnOrganizationOtherThanTheDeploymentsBeforeInviting(t *testing.T) {
	driver, store := acmeDriver(), &fakeStore{}
	request := acmeRequest
	request.ExpectedOrganizationReference = "organization-test-bound"
	if _, err := newTestProvisioner(t, driver, store).Provision(context.Background(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("provision error = %v", err)
	}
	if want := []string{"organization:Acme Security:acme.example"}; !reflect.DeepEqual(driver.calls, want) || len(store.records) != 0 {
		t.Fatalf("provider calls %v, records %v", driver.calls, store.records)
	}
	request.ExpectedOrganizationReference = "organization-test-acme"
	if _, err := newTestProvisioner(t, acmeDriver(), &fakeStore{}).Provision(context.Background(), request); err != nil {
		t.Fatalf("matching organization refused: %v", err)
	}
}

func TestDefaultEnvironmentsAreProductionStagingAndDevelopment(t *testing.T) {
	want := []DefaultEnvironment{{"Production", "production"}, {"Staging", "staging"}, {"Development", "development"}}
	if !reflect.DeepEqual(DefaultEnvironments, want) {
		t.Fatalf("default environments = %#v", DefaultEnvironments)
	}
}
