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
		GroupReference: "idp-group-engineering", Role: RoleReadOnlyViewer,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 0,
	})
	if err != nil || created.Version() != 1 {
		t.Fatalf("first Upsert() = %#v, %v", created, err)
	}
	resolved, err := mappings.Resolve(context.Background(), organization.ID(), []string{"idp-group-engineering"})
	if err != nil || len(resolved) != 1 || resolved[0].Role() != RoleReadOnlyViewer {
		t.Fatalf("first Resolve() = %#v, %v", resolved, err)
	}
	updated, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
		GroupReference: "idp-group-engineering", Role: RoleSecurityEngineer,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 1,
	})
	if err != nil || updated.Version() != 2 {
		t.Fatalf("second Upsert() = %#v, %v", updated, err)
	}
	resolved, err = mappings.Resolve(context.Background(), organization.ID(), []string{"idp-group-engineering"})
	if err != nil || len(resolved) != 1 || resolved[0].Role() != RoleSecurityEngineer {
		t.Fatalf("updated Resolve() = %#v, %v", resolved, err)
	}
	if _, err := mappings.Upsert(context.Background(), organization.ID(), GroupMappingInput{
		GroupReference: "idp-group-engineering", Role: RoleOrganizationAdmin,
		WorkspaceID: workspace.ID(), EnvironmentID: environments[0].ID(), ExpectedVersion: 1,
	}); err != ErrConflict {
		t.Fatalf("stale Upsert() error = %v", err)
	}
}
