package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var agentCurrentReadContracts = []struct{ operation, query, legacy string }{
	{"getAgent", `SELECT zasp_agent_read_v1.detail($1,$2,$3,$4,$5)`, postgresInventoryDetailSQL},
	{"getAgentCapabilities", `SELECT zasp_agent_read_v1.capabilities($1,$2,$3,$4,NULLIF($5,''),$6,$7)`, postgresInventoryCapabilitiesSQL},
	{"getAgentRelationships", `SELECT zasp_agent_read_v1.relationships($1,$2,$3,$4,NULLIF($5,''),$6,$7)`, postgresInventoryRelationshipsSQL},
	{"listAgentSessions", `SELECT zasp_agent_read_v1.sessions($1,$2,$3,$4,NULLIF($5,''),$6,$7)`, postgresInventorySessionsSQL},
}

func agentCurrentReadGrant(t *testing.T, operation string) RequestAuthorization {
	t.Helper()
	i := fixtureRequestIdentity(t)
	i.CredentialKind = CredentialBrowserSession
	id := "pid_88000001-0000-4000-8000-000000000001"
	target := AuthorizationTarget{Scope: i.Scope, Kind: "agent", ID: id, SourceID: id, Version: 1}
	g := RequestAuthorization{OperationID: operation, Identity: i, PathParameters: map[string]string{"id": id}, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "agent-read-test", Digest: [32]byte{1}}, Revision: authorization.Revision{OrganizationID: i.Scope.OrganizationID().String(), Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, Targets: []AuthorizationTarget{target}, Allowed: []AuthorizationTarget{target}}
	g, err := attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAgentCurrentReadClosedStatementsFenceEveryDrawerRoute(t *testing.T) {
	for _, contract := range agentCurrentReadContracts {
		t.Run(contract.operation, func(t *testing.T) {
			for _, mode := range []string{"normal", "audit", "wrong purpose", "wrong parent", "foreign scope", "collection", "unknown profile", "legacy SQL", "invalid bounds"} {
				t.Run(mode, func(t *testing.T) {
					g := agentCurrentReadGrant(t, contract.operation)
					pin := migrations.AgentReadProfileChecksum()
					if mode == "audit" {
						pin = migrations.AgentReadAuditProfileChecksum()
					}
					args := []any{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"], pin}
					if contract.operation != "getAgent" {
						args = []any{args[0], args[1], args[2], args[3], "", 1, pin}
					}
					query := contract.query
					switch mode {
					case "wrong purpose":
						g.OperationID = "getFinding"
					case "wrong parent":
						args[3] = "pid_88000002-0000-4000-8000-000000000002"
					case "foreign scope":
						args[1] = "pid_88000002-0000-4000-8000-000000000002"
					case "collection":
						g.Collection = true
					case "unknown profile":
						args[len(args)-1] = strings.Repeat("a", 64)
					case "legacy SQL":
						query = contract.legacy
						if contract.operation == "getAgent" {
							args[4] = InventoryKindAgent
						} else {
							args = args[:6]
						}
					case "invalid bounds":
						if contract.operation == "getAgent" {
							args[3] = "invalid"
						} else {
							args[5] = 101
						}
					}
					var err error
					g, err = attestAuthorization(g, authorizationFixtureAttestor(t), time.Now())
					if err != nil {
						t.Fatal(err)
					}
					tx := &authorizationTxFixture{}
					driver := &authorizationDriverFixture{tx: tx}
					db, _ := NewPostgresJSONDatabase(driver)
					ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
					_, err = db.QueryJSON(ctx, query, args...)
					accepted := mode == "normal" || mode == "audit"
					if accepted {
						if err != nil || driver.direct || !reflect.DeepEqual(tx.steps, []string{"begin", "fence", "effect", "commit", "rollback"}) {
							t.Fatal("exact current Agent read did not use committed same-transaction proof fence")
						}
					} else if !errors.Is(err, ErrAuthorizationDenied) || len(tx.steps) != 0 || driver.direct {
						t.Fatal("Agent read escaped purpose, scope, parent, profile or legacy refusal")
					}
				})
			}
		})
	}
}

func TestAgentCurrentReadRepositoryUsesSelectedPrivateRoutesAndRefusesMissingProfile(t *testing.T) {
	for _, contract := range agentCurrentReadContracts {
		t.Run(contract.operation, func(t *testing.T) {
			g := agentCurrentReadGrant(t, contract.operation)
			ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, g)
			id, _ := domain.ParseProductID(g.PathParameters["id"])
			db := &inventoryJSONDatabase{responses: map[string]json.RawMessage{contract.query: agentCurrentReadPayload(t, contract.operation, id.String())}}
			repository := &PostgresInventoryRepository{database: db}
			if err := repository.RequireAgentReadProfile(migrations.AgentReadProfileChecksum()); err != nil {
				t.Fatal(err)
			}
			call := func() error {
				switch contract.operation {
				case "getAgent":
					v, e := repository.GetInventory(ctx, g.Identity.Scope, id, InventoryKindAgent)
					if e == nil && v.Summary.ID != id.String() {
						t.Fatal("detail parent changed")
					}
					return e
				case "getAgentCapabilities":
					v, e := repository.ListAgentCapabilitiesPage(ctx, g.Identity.Scope, id, "", 1)
					if e == nil && len(v.Items) != 1 {
						t.Fatal("capability body lost")
					}
					return e
				case "getAgentRelationships":
					v, e := repository.ListAgentRelationshipsPage(ctx, g.Identity.Scope, id, "", 1)
					if e == nil && len(v.Items) != 1 {
						t.Fatal("relationship body lost")
					}
					return e
				default:
					v, e := repository.ListAgentSessionsPage(ctx, g.Identity.Scope, id, "", 1)
					if e == nil && len(v.Items) != 1 {
						t.Fatal("nonempty observed session body replaced by empty legacy page")
					}
					return e
				}
			}
			if err := call(); err != nil || db.statement != contract.query || db.arguments[len(db.arguments)-1] != migrations.AgentReadProfileChecksum() {
				t.Fatal("repository did not select exact configured private Agent read")
			}
			repository = &PostgresInventoryRepository{database: db}
			db.statement = ""
			if err := call(); !errors.Is(err, ErrRepositoryUnavailable) || db.statement != "" {
				t.Fatal("unconfigured current read reached SQL or legacy fallback")
			}
		})
	}
}

func agentCurrentReadPayload(t *testing.T, operation, id string) json.RawMessage {
	t.Helper()
	target := "pid_88000002-0000-4000-8000-000000000002"
	evidence := "pid_20000001-0000-4000-8000-000000000001"
	if operation == "getAgent" {
		var summary InventorySummary
		if json.Unmarshal([]byte(inventorySummaryJSON(id, "agent")), &summary) != nil {
			t.Fatal("summary fixture")
		}
		detail := InventoryDetail{Summary: summary, Sources: []InventorySourceObservation{{IntegrationID: "pid_30000001-0000-4000-8000-000000000001", Provider: "aws", Source: "aws", SourceIdentifier: "sha256:" + strings.Repeat("b", 64), SnapshotID: "pid_40000001-0000-4000-8000-000000000001", Generation: 1, EvidenceID: evidence, ConfidenceBasisPoints: 9000, ObservedAt: summary.ObservedAt, FreshUntil: summary.FreshUntil, ProjectionVersion: 1, Winning: true}}, Evidence: []InventoryEvidenceReference{{ID: evidence, Checksum: "sha256:" + strings.Repeat("a", 64), MediaType: "application/json", SchemaVersion: "raw-v1", ParserVersion: "parser-v1", ToolVersion: "tool-v1", CollectedAt: summary.ObservedAt, SizeBytes: 128}}}
		b, err := json.Marshal(detail)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var items any
	switch operation {
	case "getAgentCapabilities":
		items = []Capability{{AgentID: id, TargetID: target, TargetKind: "resource", Category: "action_execute", Outcome: "execute", State: "blocked", Reachable: true, EvidenceIDs: []string{evidence}}}
	case "getAgentRelationships":
		items = []Relationship{{ID: target, FromID: id, ToID: target, Type: "uses", EvidenceID: evidence}}
	default:
		items = []AgentSession{{ID: target, AgentID: id, StartedAt: "2026-10-17T14:00:00Z"}}
	}
	b, err := json.Marshal(map[string]any{"items": items, "next_key": nil})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
