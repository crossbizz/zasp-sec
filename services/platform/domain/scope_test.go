package domain

import (
	"errors"
	"reflect"
	"testing"
)

func mustProductID(t *testing.T, text string) ProductID {
	t.Helper()
	id, err := ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q): %v", text, err)
	}
	return id
}

func validScopeIDs(t *testing.T) (ProductID, ProductID, ProductID) {
	t.Helper()
	return mustProductID(t, "pid_10000000-0000-4000-8000-000000000001"),
		mustProductID(t, "pid_20000000-0000-4000-8000-000000000002"),
		mustProductID(t, "pid_30000000-0000-4000-8000-000000000003")
}

func TestScopeConstructsExactComparableHierarchy(t *testing.T) {
	organizationID, workspaceID, environmentID := validScopeIDs(t)
	scope, err := NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	if scope.IsZero() {
		t.Fatal("constructed scope is zero")
	}
	if err := scope.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if scope.OrganizationID() != organizationID || scope.WorkspaceID() != workspaceID || scope.EnvironmentID() != environmentID {
		t.Fatalf("scope accessors returned the wrong hierarchy: %#v", scope)
	}
	if got := map[Scope]string{scope: "present"}[scope]; got != "present" {
		t.Fatalf("comparable scope lookup = %q", got)
	}

	typeOfScope := reflect.TypeOf(Scope{})
	for index := 0; index < typeOfScope.NumField(); index++ {
		if typeOfScope.Field(index).IsExported() {
			t.Fatalf("Scope field %q is exported", typeOfScope.Field(index).Name)
		}
	}
}

func TestScopeRejectsMissingOrDuplicateHierarchyLevels(t *testing.T) {
	organizationID, workspaceID, environmentID := validScopeIDs(t)
	for name, ids := range map[string][3]ProductID{
		"missing organization":               {{}, workspaceID, environmentID},
		"missing workspace":                  {organizationID, {}, environmentID},
		"missing environment":                {organizationID, workspaceID, {}},
		"organization workspace duplicate":   {organizationID, organizationID, environmentID},
		"organization environment duplicate": {organizationID, workspaceID, organizationID},
		"workspace environment duplicate":    {organizationID, workspaceID, workspaceID},
	} {
		t.Run(name, func(t *testing.T) {
			scope, err := NewScope(ids[0], ids[1], ids[2])
			if !errors.Is(err, ErrInvalidScope) {
				t.Fatalf("error = %v, want ErrInvalidScope", err)
			}
			if !scope.IsZero() {
				t.Fatalf("rejected scope retained hierarchy: %#v", scope)
			}
		})
	}
}

func TestScopeValidationRejectsZeroPartialAndMalformedInternalValues(t *testing.T) {
	organizationID, workspaceID, environmentID := validScopeIDs(t)
	malformed := ProductID{value: [16]byte{0, 0, 0, 0, 0, 0, 0x10, 0, 0x80, 0, 0, 0, 0, 0, 0, 1}}
	for name, scope := range map[string]Scope{
		"zero":                   {},
		"partial":                {organizationID: organizationID, workspaceID: workspaceID},
		"malformed organization": {organizationID: malformed, workspaceID: workspaceID, environmentID: environmentID},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(scope.Validate(), ErrInvalidScope) {
				t.Fatalf("Validate(%#v) did not return ErrInvalidScope", scope)
			}
		})
	}
	if !(Scope{}).IsZero() {
		t.Fatal("zero scope is not zero")
	}
}

func TestScopeSeparatesEnvironmentAndExternalIdentity(t *testing.T) {
	organizationID, workspaceID, environmentID := validScopeIDs(t)
	otherEnvironment := mustProductID(t, "pid_40000000-0000-4000-8000-000000000004")
	first, err := NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewScope(organizationID, workspaceID, otherEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct environments produced equal scopes")
	}
	for _, vendorID := range []string{"arn:aws:organizations::000000000000:organization/o-example", "123456789012"} {
		if _, err := ParseProductID(vendorID); !errors.Is(err, ErrInvalidProductID) {
			t.Fatalf("vendor ID %q entered the scope product-ID boundary", vendorID)
		}
	}
}
