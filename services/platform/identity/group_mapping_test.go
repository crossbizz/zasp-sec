package identity

import (
	"context"
	"testing"
)

func TestGroupMappingUpdateChangesTheNextResolvedAuthorization(t *testing.T) {
	store := newFixtureStore(t)
	organization, _, workspace, environments := seedHTTPIdentity(t, store)
	mappings, err := NewGroupMappingStore(store)
	if err != nil {
		t.Fatal(err)
	}
	created, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
		GroupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", Role: RoleReadOnlyViewer,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 0,
	})
	if err != nil || created.Version() != 1 {
		t.Fatalf("first Upsert() = %#v, %v", created, err)
	}
	resolved, err := mappings.Resolve(context.Background(), organization.ID(), []string{"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31"})
	if err != nil || len(resolved) != 1 || resolved[0].Role() != RoleReadOnlyViewer {
		t.Fatalf("first Resolve() = %#v, %v", resolved, err)
	}
	updated, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
		GroupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", Role: RoleSecurityEngineer,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 1,
	})
	if err != nil || updated.Version() != 2 {
		t.Fatalf("second Upsert() = %#v, %v", updated, err)
	}
	resolved, err = mappings.Resolve(context.Background(), organization.ID(), []string{"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31"})
	if err != nil || len(resolved) != 1 || resolved[0].Role() != RoleSecurityEngineer {
		t.Fatalf("updated Resolve() = %#v, %v", resolved, err)
	}
	if _, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
		GroupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", Role: RoleOrganizationAdmin,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 1,
	}); err != ErrConflict {
		t.Fatalf("stale Upsert() error = %v", err)
	}
}

func TestGroupMappingRequiresProviderOwnedStytchSCIMGroupReference(t *testing.T) {
	store := newFixtureStore(t)
	organization, _, workspace, environments := seedHTTPIdentity(t, store)
	mappings, err := NewGroupMappingStore(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{
		"idp-group-engineering",
		"scim-group-stage-018f85a0-2c17-7ba3-91d1-7f0382dd7c31",
		"scim-group-test-",
	} {
		if _, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
			GroupReference: reference, Role: RoleReadOnlyViewer, WorkspaceID: workspace.ID(),
			EnvironmentID: environments[0].ID(), ExpectedVersion: 0,
		}); err != ErrInvalidRecord {
			t.Fatalf("Upsert(%q) error = %v", reference, err)
		}
	}
}
