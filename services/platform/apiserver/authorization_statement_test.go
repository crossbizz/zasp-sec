package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A signed decision is not a general-purpose SQL capability. These cases catch
// reuse for another effect, principal, scope, or native resource argument.
func TestP7AuthorizationStatementBinding(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, w, e := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String()
	id := "pid_88000001-0000-4000-8000-000000000001"
	foreign := "pid_88000002-0000-4000-8000-000000000002"
	detail := `SELECT zasp_authorization80.sensor_detail($1,$2,$3,$4)`
	for _, tc := range []struct {
		name, operation, query string
		args                   []any
		allow                  bool
	}{
		{"exact current detail", "getSensor", detail, []any{o, w, e, id}, true},
		{"unknown SQL", "getSensor", `SELECT protected_product_effect()`, nil, false},
		{"wrong operation", "getFinding", detail, []any{o, w, e, id}, false},
		{"foreign organization", "getSensor", detail, []any{foreign, w, e, id}, false},
		{"foreign workspace", "getSensor", detail, []any{o, foreign, e, id}, false},
		{"foreign environment", "getSensor", detail, []any{o, w, foreign, id}, false},
		{"different native target", "getSensor", detail, []any{o, w, e, foreign}, false},
		{"missing argument", "getSensor", detail, []any{o, w, e}, false},
		{"extra argument", "getSensor", detail, []any{o, w, e, id, foreign}, false},
		{"read proof on mutation", "getSensor", `SELECT zasp_authorization80.delete_sensor($1,$2,$3,$4,$5,$6,$7,$8)`, []any{o, w, e, i.PrincipalID.String(), id, int64(1), "stable-key", []byte{1}}, false},
		{"different actor", "deleteSensor", `SELECT zasp_authorization80.delete_sensor($1,$2,$3,$4,$5,$6,$7,$8)`, []any{o, w, e, foreign, id, int64(1), "stable-key", []byte{1}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := AuthorizationTarget{Scope: i.Scope, Kind: "sensor", ID: id, SourceID: id, Version: 1}
			grant := RequestAuthorization{OperationID: tc.operation, Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "statement-current", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}}
			grant, err := attestAuthorization(grant, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			c := context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant)
			body, err := db.QueryJSON(c, tc.query, tc.args...)
			if tc.allow {
				if err != nil || string(body) != `{"ok":true}` {
					t.Fatalf("checked statement body=%s error=%v", body, err)
				}
			} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
				t.Fatalf("unbound SQL reached effect: body=%s error=%v steps=%v", body, err, tx.steps)
			}
		})
	}
}

func TestP7ParentStatementSelectors(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	id := "pid_89800001-0000-4000-8000-000000000001"
	event := "pid_89800002-0000-4000-8000-000000000002"
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	k := CredentialBinding{Kind: CredentialBrowserSession, ID: "selector-current", Digest: [32]byte{1}}
	for _, tc := range []struct {
		name, operation, kind, query string
		parameters                   map[string]string
		args                         []any
		allow                        bool
	}{
		{"exact event", "getSessionEvent", "session", `SELECT zasp_authorization80.runtime_session_event_get($1,$2,$3,$4,$5,$6)`, map[string]string{"id": id, "eventId": event}, []any{o, w, e, p, id, event}, true},
		{"different event same allowed session", "getSessionEvent", "session", `SELECT zasp_authorization80.runtime_session_event_get($1,$2,$3,$4,$5,$6)`, map[string]string{"id": id, "eventId": event}, []any{o, w, e, p, id, id}, false},
		{"exact evidence", "getComplianceEvidence", "finding", `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`, map[string]string{"id": id, "sourceKind": "finding"}, []any{o, w, e, p, k.Digest[:], "getEvidence", json.RawMessage(`{"source_kind":"finding","source_id":"` + id + `"}`), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()}, true},
		{"different evidence selector", "getComplianceEvidence", "finding", `SELECT zasp_authorization80.compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`, map[string]string{"id": id, "sourceKind": "finding"}, []any{o, w, e, p, k.Digest[:], "getEvidence", json.RawMessage(`{"source_kind":"finding","source_id":"` + event + `"}`), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := AuthorizationTarget{Scope: i.Scope, Kind: tc.kind, ID: id, Version: 1}
			a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: authorizationDecisionFixture{allow: map[string]bool{id: true}, model: rev.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{target}}}, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
			g, err := a.Authorize(context.Background(), i, k, RoutedOperation{OperationID: tc.operation, PathParameters: tc.parameters})
			if err != nil {
				t.Fatal(err)
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			_, err = db.QueryJSON(context.WithValue(context.Background(), requestAuthorizationContextKey{}, g), tc.query, tc.args...)
			if tc.allow {
				if err != nil {
					t.Fatal(err)
				}
				// Router-owned maps are copied, then covered by the attestation.
				tc.parameters["id"] = "changed-after-authorization"
				if _, err := authorizationProofJSON(g); err != nil {
					t.Fatalf("route map was not copied: %v", err)
				}
				g.PathParameters["id"] = "changed-private-proof"
				if _, err := authorizationProofJSON(g); !errors.Is(err, ErrAuthorizationDenied) {
					t.Fatalf("selector tampering accepted: %v", err)
				}
			} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 {
				t.Fatalf("unbound selector reached SQL: %v %v", err, tx.steps)
			}
		})
	}
}

func TestP7WorkflowStatementKinds(t *testing.T) {
	i := fixtureRequestIdentity(t)
	q := `SELECT zasp_authorization80.workflow_page($1,$2,$3,$4,NULLIF($5,''),$6)`
	g := RequestAuthorization{OperationID: "listPolicies", Identity: i, Collection: true}
	for _, tc := range []struct {
		kind  string
		allow bool
	}{{"policy", true}, {"integration", false}, {"security_agent", false}} {
		t.Run(tc.kind, func(t *testing.T) {
			got := authorizationStatementAllowed(g, q, []any{tc.kind, i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), "", 1})
			if got != tc.allow {
				t.Fatalf("workflow kind admitted=%v want=%v", got, tc.allow)
			}
		})
	}
}

func TestP7HierarchyStatementBinding(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	o, p := i.Scope.OrganizationID().String(), i.PrincipalID.String()
	w := "pid_88000003-0000-4000-8000-000000000003"
	revision := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	a := &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{revision}, Checker: authorizationDecisionFixture{model: revision.ModelID}, Resolver: authorizationTargetFixture{AuthorizationTargets{Complete: true, Collection: true}}, StoreID: revision.StoreID, ModelID: revision.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	credential := CredentialBinding{Kind: CredentialBrowserSession, ID: "hierarchy-current", Digest: [32]byte{1}}
	for _, tc := range []struct {
		name, operation, query string
		args                   []any
		allow                  bool
	}{
		{"empty requested workspace", "listEnvironments", `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`, []any{o, w, p, "", 2}, true},
		{"empty sibling workspace denied", "listEnvironments", `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`, []any{o, i.Scope.WorkspaceID().String(), p, "", 2}, false},
		{"foreign actor denied", "listEnvironments", `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`, []any{o, w, w, "", 2}, false},
		{"foreign organization denied", "listEnvironments", `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`, []any{w, w, p, "", 2}, false},
		{"wrong operation denied", "listWorkspaces", `SELECT zasp_authorization80.hierarchy_page('environment',$1,$2,$3,$4,$5)`, []any{o, w, p, "", 2}, false},
		{"empty workspaces allowed", "listWorkspaces", `SELECT zasp_authorization80.hierarchy_page('workspace',$1,NULL,$2,$3,$4)`, []any{o, p, "", 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := context.WithValue(context.Background(), authorizationQueryContextKey{}, url.Values{"workspace_id": {w}})
			grant, err := a.Authorize(c, i, credential, RoutedOperation{OperationID: tc.operation})
			if err != nil {
				t.Fatal(err)
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			_, err = db.QueryJSON(context.WithValue(c, requestAuthorizationContextKey{}, grant), tc.query, tc.args...)
			if tc.allow {
				if err != nil {
					t.Fatal(err)
				}
				if tc.operation == "listEnvironments" {
					grant.WorkspaceSelector = i.Scope.WorkspaceID().String()
					if _, err := authorizationProofJSON(grant); !errors.Is(err, ErrAuthorizationDenied) {
						t.Fatalf("signed workspace selector changed: %v", err)
					}
				}
			} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 {
				t.Fatalf("unbound hierarchy reached SQL: %v %v", err, tx.steps)
			}
		})
	}
}
