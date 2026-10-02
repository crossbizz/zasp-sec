package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type currentTestActivationDB struct {
	JSONDatabase
	legacy, current int
	body            json.RawMessage
	failure         error
}

func TestCurrentTestActivationCheckedStatement(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind, i.FreshAuthenticated, i.FreshAuthExpiresAt = CredentialBrowserSession, true, time.Now().UTC().Add(time.Minute)
	id, other := automaticSourceID(8790), automaticSourceID(8799)
	for _, mutation := range []string{"exact", "organization", "workspace", "environment", "target", "actor", "route", "operation", "collection", "credential", "fresh", "key", "version", "version-type", "activation", "fresh-value", "audit", "duplicate-receipt", "arity", "allowed", "legacy", "unknown"} {
		t.Run(mutation, func(t *testing.T) {
			target := AuthorizationTarget{Scope: i.Scope, Kind: "security_agent", ID: id, SourceID: id, Version: 1}
			g := RequestAuthorization{OperationID: "activateSecurityAgent", Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session-activation-contract", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}, PathParameters: map[string]string{"id": id}}
			args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), id, i.PrincipalID.String(), "current-test-activate-0001", int64(1), "validated", i.FreshAuthExpiresAt, automaticSourceID(8791), automaticSourceID(8792), automaticSourceID(8793)}
			query := currentTestActivateSQL
			switch mutation {
			case "organization":
				args[0] = other
			case "workspace":
				args[1] = other
			case "environment":
				args[2] = other
			case "target":
				args[3] = other
			case "actor":
				args[4] = other
			case "route":
				g.PathParameters["id"] = other
			case "operation":
				g.OperationID = "getSecurityAgent"
			case "collection":
				g.Collection = true
			case "credential":
				g.Identity.CredentialKind = CredentialBearerToken
			case "fresh":
				g.Identity.FreshAuthenticated = false
			case "key":
				args[5] = "short"
			case "version":
				args[6] = int64(0)
			case "version-type":
				args[6] = "1"
			case "activation":
				args[7] = "draft"
			case "fresh-value":
				args[8] = i.FreshAuthExpiresAt.Add(time.Second)
			case "audit":
				args[9] = "bad"
			case "duplicate-receipt":
				args[11] = args[9]
			case "arity":
				args = args[:11]
			case "allowed":
				g.Allowed = nil
			case "legacy":
				query = `SELECT zasp_temporal74.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
			case "unknown":
				query += " "
			}
			if mutation != "exact" {
				if authorizationStatementAllowed(g, query, args) {
					t.Fatal("unbound activation passed checked statement")
				}
				return
			}
			var err error
			g, err = attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			tx := &authorizationTxFixture{}
			driver := &authorizationDriverFixture{tx: tx}
			db, _ := NewPostgresJSONDatabase(driver)
			if db.RequireCurrentAuthorization() != nil {
				t.Fatal("current configuration")
			}
			body, err := db.ActivateCurrentTemporalTestDefinition(context.WithValue(context.Background(), requestAuthorizationContextKey{}, g), args...)
			if err != nil || string(body) != `{"ok":true}` || driver.direct || len(tx.steps) == 0 {
				t.Fatalf("checked activation body=%s err=%v direct=%t steps=%d", body, err, driver.direct, len(tx.steps))
			}
		})
	}
}

func (*currentTestActivationDB) CurrentAuthorizationRequired() bool { return true }
func (d *currentTestActivationDB) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	d.legacy++
	return nil, ErrRepositoryOperation
}
func (d *currentTestActivationDB) ActivateCurrentTemporalTestDefinition(context.Context, ...any) (json.RawMessage, error) {
	d.current++
	return d.body, d.failure
}

func TestCurrentTestActivationSelectsCheckedRoute(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind, i.FreshAuthenticated, i.FreshAuthExpiresAt = CredentialBrowserSession, true, time.Now().UTC().Add(time.Minute)
	q := SecurityAgentActivation{DefinitionID: automaticSourceID(8790), IdempotencyKey: "current-test-activation-0001", ExpectedVersion: 1, TargetActivation: "validated", FreshAuthExpiresAt: i.FreshAuthExpiresAt, AuditID: automaticSourceID(8791), CorrelationID: automaticSourceID(8792), ReceiptID: automaticSourceID(8793)}
	body, err := json.Marshal(SecurityAgentActivationResult{ID: q.DefinitionID, Activation: q.TargetActivation, Version: 2, AuditID: q.AuditID, CorrelationID: q.CorrelationID, ReceiptID: q.ReceiptID})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		body      json.RawMessage
		failure   error
		wantError bool
	}{
		{"exact", body, nil, false}, {"denied", nil, ErrAuthorizationDenied, true}, {"unavailable", nil, ErrRepositoryUnavailable, true}, {"malformed", json.RawMessage(`{}`), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &currentTestActivationDB{body: tc.body, failure: tc.failure}
			r := &PostgresRepository{database: d, securityAgentExecution: true}
			result, err := r.ActivateSecurityAgent(context.Background(), i, q)
			if d.legacy != 0 || d.current != 1 || (err != nil) != tc.wantError || tc.failure != nil && !errors.Is(err, tc.failure) || !tc.wantError && result.Version != 2 {
				t.Fatalf("legacy=%d current=%d result=%+v error=%v", d.legacy, d.current, result, err)
			}
		})
	}
}
