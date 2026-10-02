package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestLinkedRedTeamRunProtocol(t *testing.T) {
	scope := fixtureRequestIdentity(t).Scope
	run := "pid_99000001-0000-4000-8000-000000000001"
	for _, value := range []struct{ raw, want string }{
		{`{"protocol":"linked"}`, "linked"}, {`{"protocol":"legacy"}`, "legacy"},
		{`{"protocol":"unknown"}`, ""}, {`{"protocol":null}`, ""}, {`{"Protocol":"legacy"}`, ""},
		{`{"protocol":"linked","protocol":"legacy"}`, ""}, {`{"protocol":"legacy","extra":true}`, ""},
		{`{"protocol":"legacy"} {}`, ""}, {`{"protocol":"legacy"}` + strings.Repeat(" ", 1024), ""},
	} {
		t.Run(value.raw[:min(len(value.raw), 60)], func(t *testing.T) {
			db := &discoveryCallDatabase{responses: map[string]json.RawMessage{postgresLinkedRedTeamProtocolSQL: json.RawMessage(value.raw)}}
			repo := &LinkedRedTeamExecutionRepository{database: db}
			got, err := repo.RunProtocol(context.Background(), scope, run)
			if value.want == "" {
				if err == nil || got != "" {
					t.Fatalf("ambiguous protocol accepted: %q %v", got, err)
				}
				return
			}
			if err != nil || got != value.want {
				t.Fatalf("protocol=%q err=%v", got, err)
			}
			calls := db.callsFor(postgresLinkedRedTeamProtocolSQL)
			if len(calls) != 1 || len(calls[0]) != 6 || calls[0][0] != scope.OrganizationID().String() || calls[0][1] != scope.WorkspaceID().String() || calls[0][2] != scope.EnvironmentID().String() || calls[0][3] != run || calls[0][4] != migrations.ProductionSecurityAgentExistingTests().Checksum() || calls[0][5] != migrations.SecurityAgentExistingTestsFingerprint() {
				t.Fatalf("protocol lost scoped release authority: %#v", calls)
			}
		})
	}
	db := &discoveryCallDatabase{}
	repo := &LinkedRedTeamExecutionRepository{database: db}
	if _, err := repo.RunProtocol(context.Background(), scope, "untrusted"); err == nil || len(db.callsFor(postgresLinkedRedTeamProtocolSQL)) != 0 {
		t.Fatal("malformed run reached authority")
	}
}
