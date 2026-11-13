package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

type secondaryFixture struct {
	identity   RequestIdentity
	credential CredentialBinding
	authorizer *OpenFGAAuthorizer
	// resolved records every resolution: the operation and whether it was
	// made for a statement of the Security Agent database.
	resolved []string
	denied   map[string]bool // resource type -> the view decision is refused
}

func newSecondaryFixture(t *testing.T) *secondaryFixture {
	t.Helper()
	f := &secondaryFixture{identity: fixtureRequestIdentity(t), denied: map[string]bool{}}
	f.identity.Permissions = []string{"view", "manage_workflows"}
	f.identity.CredentialKind = CredentialBrowserSession
	f.identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Microsecond)
	o := f.identity.Scope.OrganizationID().String()
	rev := authorization.Revision{OrganizationID: o, Desired: 1, Applied: 1, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}
	f.credential = CredentialBinding{Kind: CredentialBrowserSession, ID: "secondary-current", Digest: [32]byte{7}}
	f.identity.credentialBinding = f.credential
	resolver := authorizationTargetFunc(func(ctx context.Context, identity RequestIdentity, route RoutedOperation) (AuthorizationTargets, error) {
		policy, err := authorizationTargetPolicy(route.OperationID)
		if err != nil {
			return AuthorizationTargets{}, err
		}
		database := "product"
		if securityAgentAuthorization(ctx) {
			database = "security-agent"
		}
		f.resolved = append(f.resolved, database+":"+route.OperationID)
		if policy.Kind == "*" {
			if database == "security-agent" {
				return AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: "security_agent_run", ID: "pid_40000001-0000-4000-8000-000000000001", Version: 2}}}, nil
			}
			return AuthorizationTargets{Complete: true, Collection: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: "finding", ID: "pid_40000002-0000-4000-8000-000000000002", Version: 1}}}, nil
		}
		id := identity.Scope.EnvironmentID().String()
		if policy.Mode == "object" && policy.Kind != "environment" {
			id = route.PathParameters["id"]
		}
		return AuthorizationTargets{Complete: true, Targets: []AuthorizationTarget{{Scope: identity.Scope, Kind: policy.Kind, ID: id, Version: 3}}}, nil
	})
	checker := authorizationDecisionFunc(func(_ context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
		return authorization.Decision{Allowed: !(q.Permission == "view" && f.denied[q.ResourceType]), ModelID: rev.ModelID}, nil
	})
	f.authorizer = &OpenFGAAuthorizer{Reader: authorizationRevisionFixture{rev}, Checker: checker, Resolver: resolver, StoreID: rev.StoreID, ModelID: rev.ModelID, AttestationKey: authorizationFixtureAttestor(t)}
	return f
}

// request authorizes the route the way the router does and returns the
// context a handler receives.
func (f *secondaryFixture) request(t *testing.T, route RoutedOperation) context.Context {
	t.Helper()
	grant, err := f.authorizer.Authorize(context.Background(), f.identity, f.credential, route)
	if err != nil {
		t.Fatalf("authorize %s: %v", route.OperationID, err)
	}
	return context.WithValue(context.WithValue(context.Background(), requestAuthorizationContextKey{}, grant), requestAuthorizerContextKey{}, RequestAuthorizer(f.authorizer))
}

func (f *secondaryFixture) database(t *testing.T, payload string) (*PostgresJSONDatabase, *completionTxFixture, *completionDriverFixture) {
	t.Helper()
	tx := &completionTxFixture{payload: payload}
	driver := &completionDriverFixture{tx: tx, ready: true}
	database, err := NewPostgresJSONDatabase(driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	return database, tx, driver
}

func attestedBody(t *testing.T, envelope string) map[string]json.RawMessage {
	t.Helper()
	var outer struct {
		Body string `json:"body"`
	}
	if json.Unmarshal([]byte(envelope), &outer) != nil || outer.Body == "" {
		t.Fatalf("not an attestation envelope: %.80s", envelope)
	}
	raw, err := base64.StdEncoding.DecodeString(outer.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// A second decision exists only inside a request the router authorized, for
// the same principal, scope and credential, and is a decision of its own.
func TestSecondaryRequestAuthorization(t *testing.T) {
	f := newSecondaryFixture(t)
	finding := "pid_30000005-0000-4000-8000-000000000005"
	route := RoutedOperation{OperationID: "getFinding", PathParameters: map[string]string{"id": finding}}
	if _, err := secondaryRequestAuthorization(context.Background(), f.identity, route); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("unauthorized request obtained a second decision: %v", err)
	}
	ctx := f.request(t, RoutedOperation{OperationID: "runSecurityAgent", PathParameters: map[string]string{"id": "pid_20000001-0000-4000-8000-000000000001"}})
	grant, err := secondaryRequestAuthorization(ctx, f.identity, route)
	if err != nil || grant.OperationID != "getFinding" || len(grant.Allowed) != 1 || grant.Allowed[0].Kind != "finding" || grant.Allowed[0].ID != finding || len(grant.attestation) == 0 {
		t.Fatalf("second decision=%+v error=%v", grant, err)
	}
	primary, _ := requestAuthorizationFromContext(ctx)
	if primary.OperationID != "runSecurityAgent" || slices.ContainsFunc(primary.Allowed, func(target AuthorizationTarget) bool { return target.Kind == "finding" }) {
		t.Fatalf("the request's own proof changed: %+v", primary)
	}
	other := f.identity
	other.PrincipalID = f.identity.Scope.OrganizationID()
	if _, err := secondaryRequestAuthorization(ctx, other, route); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("another principal obtained a second decision: %v", err)
	}
	f.denied["finding"] = true
	if _, err := secondaryRequestAuthorization(ctx, f.identity, route); !errors.Is(err, ErrAuthorizationDenied) || secondaryAuthorizationError(err) != ErrRepositoryAuthorization {
		t.Fatalf("a refused trigger decision was not a denial: %v", err)
	}
	if secondaryAuthorizationError(authorization.ErrConflict) != ErrRepositoryConflict || secondaryAuthorizationError(authorization.ErrUnavailable) != ErrRepositoryUnavailable || secondaryAuthorizationError(nil) != nil {
		t.Fatal("second decision errors were not mapped")
	}
}

// A run on a finding carries the attestation of the requester's decision for
// that finding; the run is not sent when that decision is refused.
func TestSecurityAgentRunAttestsItsTrigger(t *testing.T) {
	f := newSecondaryFixture(t)
	i := f.identity
	const agent, run, trigger = "pid_20000001-0000-4000-8000-000000000001", "pid_30000004-0000-4000-8000-000000000004", "pid_30000005-0000-4000-8000-000000000005"
	const audit, correlation, receipt = "pid_30000001-0000-4000-8000-000000000001", "pid_30000002-0000-4000-8000-000000000002", "pid_30000003-0000-4000-8000-000000000003"
	payload := `{"family":"finding","result":{"id":"` + run + `","agent_id":"` + agent + `","state":"queued","evidence_ids":["` + trigger + `"],"definition_version":3,"version":1,"audit_id":"` + audit + `","correlation_id":"` + correlation + `","receipt_id":"` + receipt + `","replayed":false}}`
	request := SecurityAgentRunRequest{DefinitionID: agent, IdempotencyKey: "idempotency-key-0001", ExpectedVersion: 3, RunID: run, TriggerKind: "finding", TriggerID: trigger, AuditID: audit, CorrelationID: correlation, ReceiptID: receipt}
	route := RoutedOperation{OperationID: "runSecurityAgent", PathParameters: map[string]string{"id": agent}}

	for kind, operation := range map[string]string{"finding": "getFinding", "attack_path": "getAttackPath"} {
		t.Run(kind, func(t *testing.T) {
			database, tx, _ := f.database(t, payload)
			repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true, currentAuthorization: true}
			request := request
			request.TriggerKind = kind
			if _, err := repository.runSecurityAgentCurrent(f.request(t, route), i, request); err != nil {
				t.Fatalf("run: %v", err)
			}
			if len(tx.statements) != 1 || tx.statements[0] != currentSecurityAgentRunSQL || len(tx.arguments[0]) != 7 {
				t.Fatalf("statements=%v arguments=%d", tx.statements, len(tx.arguments[0]))
			}
			envelope, ok := tx.arguments[0][6].(string)
			if !ok {
				t.Fatalf("trigger attestation was %T", tx.arguments[0][6])
			}
			body := attestedBody(t, envelope)
			var attested struct {
				Operation string            `json:"operation_id"`
				Path      map[string]string `json:"path_parameters"`
				Principal string            `json:"principal_id"`
				Allowed   []struct {
					Kind string `json:"kind"`
					ID   string `json:"id"`
				} `json:"allowed"`
			}
			raw, _ := json.Marshal(body)
			if json.Unmarshal(raw, &attested) != nil || attested.Operation != operation || attested.Path["id"] != trigger || attested.Principal != i.PrincipalID.String() || len(attested.Allowed) != 1 || attested.Allowed[0].Kind != kind || attested.Allowed[0].ID != trigger {
				t.Fatalf("trigger attestation names %s", raw)
			}
		})
	}
	t.Run("refused trigger", func(t *testing.T) {
		f.denied["finding"] = true
		defer delete(f.denied, "finding")
		database, tx, driver := f.database(t, payload)
		repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true, currentAuthorization: true}
		if _, err := repository.runSecurityAgentCurrent(f.request(t, route), i, request); !errors.Is(err, ErrRepositoryAuthorization) {
			t.Fatalf("run on a finding the requester may not view: %v", err)
		}
		if len(tx.steps) != 0 || len(driver.direct) != 0 {
			t.Fatalf("a statement was sent: steps=%v direct=%v", tx.steps, driver.direct)
		}
	})
	t.Run("session trigger carries no attestation", func(t *testing.T) {
		database, tx, _ := f.database(t, payload)
		repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion, securityAgentExecution: true, currentAuthorization: true}
		request := request
		request.TriggerKind = "session"
		before := len(f.resolved)
		if _, err := repository.runSecurityAgentCurrent(f.request(t, route), i, request); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(tx.arguments) != 1 || tx.arguments[0][6] != nil {
			t.Fatalf("session trigger arguments=%v", tx.arguments)
		}
		if got := f.resolved[before:]; len(got) != 1 || got[0] != "product:runSecurityAgent" {
			t.Fatalf("resolutions=%v", got)
		}
	})
}

// The Security Agent counts of the home summary come from the Security Agent
// database under a proof whose targets that database resolved.
func TestSecurityAgentHomeCountsUseTheirOwnProof(t *testing.T) {
	f := newSecondaryFixture(t)
	counts := `{"pending_approvals":2,"oldest_approval_age_seconds":90,"needs_human_runs":1,"failed_runs":0,"inconclusive_runs":0,"recent_contained":3,"recent_remediated":4}`
	database, tx, driver := f.database(t, counts)
	reader := &securityAgentHomeReader{database: database}
	product := HomeSummary{AgentCount: 5, Healthy: true}

	ctx := f.request(t, RoutedOperation{OperationID: "getHomeSummary"})
	before := len(f.resolved)
	summary, err := reader.apply(ctx, f.identity, product)
	if err != nil {
		t.Fatal(err)
	}
	if summary.AgentCount != 5 || summary.PendingApprovals != 2 || summary.OldestApprovalAgeSeconds != 90 || summary.NeedsHumanRuns != 1 || summary.RecentContained != 3 || summary.RecentRemediated != 4 || summary.Healthy || !summary.AttentionRequired {
		t.Fatalf("summary=%+v", summary)
	}
	if !slices.Equal(tx.steps, []string{"fence", "effect"}) || len(tx.statements) != 1 || tx.statements[0] != currentSecurityAgentHomeSummarySQL || len(driver.direct) != 0 {
		t.Fatalf("steps=%v statements=%v direct=%v", tx.steps, tx.statements, driver.direct)
	}
	// Every resolution of the second proof was made for the Security Agent
	// database: the collection and the Environment of its view decision.
	if got := f.resolved[before:]; !slices.Equal(got, []string{"security-agent:getHomeSummary", "security-agent:getEnvironment"}) {
		t.Fatalf("second proof resolutions=%v", got)
	}

	// A request that was not authorized keeps the summary it has.
	if unchanged, err := reader.apply(context.Background(), f.identity, product); err != nil || unchanged != product {
		t.Fatalf("unchecked request: %+v %v", unchanged, err)
	}
	if unchanged, err := (*securityAgentHomeReader)(nil).apply(ctx, f.identity, product); err != nil || unchanged != product {
		t.Fatalf("no reader: %+v %v", unchanged, err)
	}
	// Another operation's request cannot borrow the statement.
	other := f.request(t, RoutedOperation{OperationID: "globalSearch"})
	if _, err := database.QueryJSON(other, currentSecurityAgentHomeSummarySQL, f.identity.Scope.OrganizationID().String(), f.identity.Scope.WorkspaceID().String(), f.identity.Scope.EnvironmentID().String()); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("search request executed the home statement: %v", err)
	}
	// A malformed or negative answer is refused.
	for _, payload := range []string{`{"pending_approvals":1}`, `{"pending_approvals":-1,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0}`, counts[:len(counts)-1] + `,"healthy":true}`} {
		broken, _, _ := f.database(t, payload)
		if _, err := (&securityAgentHomeReader{database: broken}).apply(ctx, f.identity, product); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatalf("payload %s: %v", payload, err)
		}
	}
}

func TestMergeSecurityAgentHomeCounts(t *testing.T) {
	quiet := securityAgentHomeCounts{RecentContained: 1}
	summary, err := mergeSecurityAgentHomeCounts(HomeSummary{PendingApprovals: 9, FailedRuns: 9, AttentionRequired: true}, quiet)
	if err != nil || summary.PendingApprovals != 0 || summary.FailedRuns != 0 || summary.RecentContained != 1 || !summary.Healthy || summary.AttentionRequired {
		t.Fatalf("counts were not replaced: %+v %v", summary, err)
	}
	summary, err = mergeSecurityAgentHomeCounts(HomeSummary{HighRiskPaths: 1, AttentionRequired: true}, quiet)
	if err != nil || summary.Healthy || !summary.AttentionRequired {
		t.Fatalf("a high-risk path was forgotten: %+v %v", summary, err)
	}
	// Environment health the requester may not see stays unknown.
	unknown := HomeSummary{environmentHealthUnavailable: true}
	summary, err = mergeSecurityAgentHomeCounts(unknown, securityAgentHomeCounts{FailedRuns: 2})
	if err != nil || summary.Healthy || summary.AttentionRequired || !summary.environmentHealthUnavailable || summary.FailedRuns != 2 {
		t.Fatalf("restricted counts became environment health: %+v %v", summary, err)
	}
}
