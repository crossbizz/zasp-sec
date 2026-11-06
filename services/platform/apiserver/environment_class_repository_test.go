package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

type environmentClassRecordingDatabase struct {
	JSONDatabase
	queries int
	query   string
	args    []any
	err     error
}

func (d *environmentClassRecordingDatabase) QueryJSON(_ context.Context, q string, args ...any) (json.RawMessage, error) {
	d.queries++
	d.query = q
	d.args = append([]any(nil), args...)
	return json.RawMessage(`{"version":1}`), d.err
}

func TestEnvironmentClassificationRepositorySelectsOneClosedWriter(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	for _, operation := range []string{"createEnvironment", "updateEnvironment"} {
		for _, mode := range []string{"legacy_omission", "legacy_explicit_refused", "selected_omission", "selected_explicit", "selected_without_authorization", "uncertain_commit"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				d := &environmentClassRecordingDatabase{}
				r := &PostgresRepository{database: d, currentAuthorization: true}
				selected := mode != "legacy_omission" && mode != "legacy_explicit_refused"
				if selected && r.RequireEnvironmentClassProfile(migrations.EnvironmentClassProfileChecksum()) != nil {
					t.Fatal("compiled selected profile refused")
				}
				m := administrationMutation{Operation: operation, ID: i.Scope.EnvironmentID().String(), WorkspaceID: i.Scope.WorkspaceID().String(), Name: "Classified", AuditID: "pid_f0830000-0000-4000-8000-000000000001", ExpectedVersion: 1}
				if mode == "selected_explicit" || mode == "legacy_explicit_refused" {
					m.EnvironmentClass = "staging"
					m.EnvironmentClassPresent = true
				}
				c := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{OperationID: operation, Identity: i})
				if mode == "selected_without_authorization" {
					c = context.Background()
				}
				uncertain := errors.New("controlled commit uncertainty")
				if mode == "uncertain_commit" {
					d.err = uncertain
				}
				_, err := r.MutateAdministration(c, i, m)
				refused := mode == "legacy_explicit_refused" || mode == "selected_without_authorization"
				if refused {
					if err == nil || d.queries != 0 {
						t.Fatal("unselected or unauthorized classification reached a writer")
					}
					return
				}
				if d.queries != 1 {
					t.Fatal("mutation was not issued exactly once")
				}
				if mode == "uncertain_commit" {
					if !errors.Is(err, uncertain) {
						t.Fatal("uncertain result lost original failure")
					}
					return
				}
				if err != nil {
					t.Fatal("closed mutation refused", err)
				}
				expected := postgresCreateEnvironmentCurrentSQL
				if operation == "updateEnvironment" {
					expected = postgresUpdateEnvironmentSQL
				}
				if selected {
					expected = postgresClassifiedEnvironmentCreateSQL
					if operation == "updateEnvironment" {
						expected = postgresClassifiedEnvironmentUpdateSQL
					}
					if d.args[len(d.args)-1] != migrations.EnvironmentClassProfileChecksum() {
						t.Fatal("writer lost selected compiled pin")
					}
					classIndex := 4
					if operation == "updateEnvironment" {
						classIndex = 5
					}
					var class any
					if mode == "selected_explicit" {
						class = "staging"
					} else if operation == "createEnvironment" {
						class = "development"
					}
					if d.args[classIndex] != class {
						t.Fatal("writer collapsed omission or explicit class")
					}
				}
				if d.query != expected {
					t.Fatal("wrong writer selected or legacy fallback attempted")
				}
			})
		}
	}
}
