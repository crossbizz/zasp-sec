package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

// Only a provider answer that proves the request was refused before any
// generation is a definite rejection. Everything else stays unknown.
func TestClassifyPlannerProviderRejection(t *testing.T) {
	const credits = `{"error":{"message":"Insufficient credits. This account never purchased credits.","code":402,"metadata":{"limit_source":"openrouter_credits"}}}`
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"insufficient credits": {402, credits},
		"invalid credentials":  {401, `{"error":{"message":"No auth credentials found","code":401}}`},
		"rate limited":         {429, `{"error":{"message":"Rate limit exceeded","code":429,"metadata":{"headers":{}}},"user_id":"user_1"}`},
	} {
		rejection := classifyPlannerProviderRejection(tc.status, []byte(tc.body))
		if rejection == nil || rejection.Status != tc.status || string(rejection.Body) != tc.body {
			t.Fatalf("%s was not a definite rejection: %+v", name, rejection)
		}
		payload, err := json.Marshal(rejection.payload())
		want, _ := json.Marshal(map[string]any{"rejected": map[string]any{"status": tc.status, "raw": tc.body}})
		if err != nil || string(payload) != string(want) {
			t.Fatalf("%s payload = %s", name, payload)
		}
	}
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"a moderation block":             {403, `{"error":{"message":"flagged","code":403,"metadata":{"reasons":["x"]}}}`},
		"a bad request":                  {400, `{"error":{"message":"bad","code":400}}`},
		"a timeout":                      {408, `{"error":{"message":"timeout","code":408}}`},
		"a model failure":                {502, `{"error":{"message":"down","code":502}}`},
		"no provider":                    {503, `{"error":{"message":"none","code":503}}`},
		"a success status":               {200, credits},
		"another code than the status":   {402, `{"error":{"message":"x","code":429}}`},
		"a code as text":                 {402, `{"error":{"message":"x","code":"402"}}`},
		"no code":                        {402, `{"error":{"message":"x"}}`},
		"no error":                       {402, `{"message":"x","code":402}`},
		"an error that is not an object": {402, `{"error":"Insufficient credits"}`},
		"usage":                          {402, `{"error":{"code":402},"usage":{"total_tokens":10}}`},
		"choices":                        {402, `{"error":{"code":402},"choices":[]}`},
		"a response identifier":          {402, `{"error":{"code":402},"id":"gen-1"}`},
		"a repeated key":                 {402, `{"error":{"code":402},"error":{"code":402}}`},
		"not JSON":                       {402, `<html>Payment Required</html>`},
		"JSON null":                      {402, `null`},
		"an array":                       {402, `[{"error":{"code":402}}]`},
		"an empty body":                  {402, ``},
		"invalid text":                   {402, "{\"error\":{\"code\":402,\"message\":\"\xff\"}}"},
		"a body that is too large":       {402, `{"error":{"code":402,"message":"` + strings.Repeat("x", securityAgentPlannerRejectionLimit) + `"}}`},
	} {
		if rejection := classifyPlannerProviderRejection(tc.status, []byte(tc.body)); rejection != nil {
			t.Fatalf("%s was classified as a definite rejection", name)
		}
	}
}

func TestPlannerRejectionFromSendError(t *testing.T) {
	rejection := classifyPlannerProviderRejection(402, []byte(`{"error":{"code":402}}`))
	if rejection == nil || plannerRejectionFrom(rejection) != rejection || plannerRejectionFrom(errors.Join(errWorkerExecution, rejection)) != rejection {
		t.Fatal("a definite rejection was not recognised")
	}
	if plannerRejectionFrom(errWorkerExecution) != nil || plannerRejectionFrom(nil) != nil || plannerRejectionFrom((*plannerProviderRejection)(nil)) != nil {
		t.Fatal("an unknown outcome was read as a rejection")
	}
	// The planning database refuses evidence that does not prove a rejection
	// before it asks PostgreSQL anything.
	database := &workerFindingPlanningDatabase{}
	if err := database.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), &plannerProviderRejection{Status: 403, Body: []byte(`{"error":{"code":403}}`)}); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("unproven evidence: err=%v", err)
	}
	if err := database.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), nil); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("no evidence: err=%v", err)
	}
	ordered := &workerFindingPlanningDatabase{family: workerPlanningOrdered68}
	if err := ordered.RecoverRejectedPlanning(context.Background(), json.RawMessage(`{}`), rejection); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("ordered release: err=%v", err)
	}
}

// A step is decided again only for a pending projection or a moved revision.
func TestRetryWorkerAuthorization(t *testing.T) {
	calls := 0
	if err := retryWorkerAuthorization(context.Background(), func() error {
		calls++
		if calls < 3 {
			return authorization.ErrPending
		}
		return nil
	}); err != nil || calls != 3 {
		t.Fatalf("pending step: err=%v calls=%d", err, calls)
	}
	calls = 0
	if err := retryWorkerAuthorization(context.Background(), func() error { calls++; return authorization.ErrDenied }); !errors.Is(err, authorization.ErrDenied) || calls != 1 {
		t.Fatalf("denied step: err=%v calls=%d", err, calls)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if err := retryWorkerAuthorization(cancelled, func() error { calls++; return authorization.ErrConflict }); !errors.Is(err, authorization.ErrConflict) || calls != 1 {
		t.Fatalf("cancelled step: err=%v calls=%d", err, calls)
	}
}

func TestPlannerProviderRejectionError(t *testing.T) {
	var err error = &plannerProviderRejection{Status: 402, Body: []byte(`{"error":{"code":402}}`)}
	// The message never carries the provider's body.
	if err.Error() != "planner provider rejected the request" || strings.Contains(err.Error(), "402") {
		t.Fatalf("message = %q", err.Error())
	}
}

const plannerRejectionTestBody = `{"error":{"message":"It's over: no credits","code":402}}`

// plannerRejectionMetadata is a native recovery answer for the fixture run.
func plannerRejectionMetadata(t *testing.T, start orchestration.StartRequest, state string, usageKnown, hasResponse bool) json.RawMessage {
	t.Helper()
	scope, err := temporalScope(start)
	if err != nil {
		t.Fatal(err)
	}
	reservation, _ := apiserver.CanonicalDiscoveryID(scope, "security_agent_planning_reservation", start.Ref.RunID)
	raw, _ := json.Marshal(map[string]any{"run_id": start.Ref.RunID, "state": state, "reservation_id": reservation, "request_digest": "sha256:" + strings.Repeat("a", 64), "credential_digest": "sha256:" + strings.Repeat("b", 64), "usage_known": usageKnown, "has_response": hasResponse})
	return raw
}

func plannerRejectionIdentity(start orchestration.StartRequest, changes map[string]any) json.RawMessage {
	fields := temporalStartFields(start)
	delete(fields, "input_digest")
	for key, value := range changes {
		if value == nil {
			delete(fields, key)
			continue
		}
		fields[key] = value
	}
	raw, _ := json.Marshal(fields)
	return raw
}

// plannerRejectionScript answers the compensation role's native entries of a
// planning family over the fake wire.
type plannerRejectionScript struct {
	family                      string // "78" or "74"
	prior, terminal             json.RawMessage
	sourceCode                  map[string]string // phase -> SQLSTATE of the source read
	recoveryCode, reconcileCode string
}

func (s *plannerRejectionScript) handle(statement workerWireStatement) workerWireReply {
	switch {
	case strings.Contains(statement.SQL, "zasp_authorization80_worker.planning"+s.family+"_source("):
		if len(statement.Args) == 2 && s.sourceCode[statement.Args[0]] != "" {
			return workerWireReply{Code: s.sourceCode[statement.Args[0]]}
		}
		return workerWireReply{Row: json.RawMessage(`{"session_user":"zasp_compensation"}`)}
	case strings.Contains(statement.SQL, "zasp_authorization80_worker.planning"+s.family+"_recovery("):
		if s.recoveryCode != "" {
			return workerWireReply{Code: s.recoveryCode}
		}
		return workerWireReply{Row: s.prior}
	case strings.Contains(statement.SQL, "zasp_temporal"+s.family+".plan("):
		if s.reconcileCode != "" {
			return workerWireReply{Code: s.reconcileCode}
		}
		return workerWireReply{Row: s.terminal}
	}
	return workerWireReply{Code: "XX000"}
}

func plannerRejectionCompensation(t *testing.T, script *plannerRejectionScript) (*authorization.WorkerExecutor, *workerWireServer) {
	t.Helper()
	pool, server := newWorkerWirePool(t, script.handle)
	key, err := authorization.NewWorkerKey(authorization.CapturedCompensation, []byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := authorization.NewWorkerExecutor(pool, nil, "", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return executor, server
}

// plannerRejectionTrace reduces the wire statements to their route: the
// source phase read, the operation the signed proof names, and the native
// entry executed. It returns the requests the source reads carried.
func plannerRejectionTrace(t *testing.T, statements []workerWireStatement) ([]string, []map[string]any) {
	t.Helper()
	var trace []string
	var requests []map[string]any
	for _, statement := range statements {
		switch {
		case strings.Contains(statement.SQL, "_source("):
			if len(statement.Args) != 2 {
				t.Fatalf("source arguments: %q", statement.Args)
			}
			var request map[string]any
			if err := json.Unmarshal([]byte(statement.Args[1]), &request); err != nil {
				t.Fatalf("source request %q: %v", statement.Args[1], err)
			}
			trace = append(trace, "source:"+statement.Args[0])
			requests = append(requests, request)
		case strings.Contains(statement.SQL, "set_config("):
			var envelope struct {
				Body []byte `json:"body"`
			}
			var body struct {
				Operation string          `json:"operation"`
				Request   json.RawMessage `json:"request"`
			}
			if len(statement.Args) != 2 || json.Unmarshal([]byte(statement.Args[1]), &envelope) != nil || json.Unmarshal(envelope.Body, &body) != nil {
				t.Fatalf("proof: %q", statement.Args)
			}
			trace = append(trace, "proof:"+body.Operation)
		default:
			name := statement.SQL[len("SELECT "):strings.IndexByte(statement.SQL, '(')]
			trace = append(trace, "exec:"+name)
		}
	}
	return trace, requests
}

func TestRecoverRejectedPlanningRecordsTheRefusal(t *testing.T) {
	start := workerPlanningStartFixture()
	rejection := classifyPlannerProviderRejection(402, []byte(plannerRejectionTestBody))
	if rejection == nil {
		t.Fatal("fixture is not a definite rejection")
	}
	for _, tc := range []struct {
		name, family, prefix string
		selector             workerPlanningFamily
		recovery, plan       string
	}{
		{"finding", "78", "finding.planning.", workerPlanningFinding, "zasp_authorization80_worker.planning78_recovery", "zasp_temporal78.plan"},
		{"test74", "74", "test74.planning.", workerPlanningTest74, "zasp_authorization80_worker.planning74_recovery", "zasp_temporal74.plan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := &plannerRejectionScript{family: tc.family, prior: plannerRejectionMetadata(t, start, "started", false, false), terminal: plannerRejectionMetadata(t, start, "needs_human", false, false)}
			compensation, server := plannerRejectionCompensation(t, script)
			d := &workerFindingPlanningDatabase{compensation: compensation, start: start, family: tc.selector}
			if err := d.RecoverRejectedPlanning(context.Background(), plannerRejectionIdentity(start, nil), rejection); err != nil {
				t.Fatalf("recovery of a definite rejection: %v", err)
			}
			trace, requests := plannerRejectionTrace(t, server.Statements())
			want := []string{"source:recovery", "source:recovery", "proof:" + tc.prefix + "recovery", "exec:" + tc.recovery, "source:reconcile", "source:reconcile", "proof:" + tc.prefix + "reconcile", "exec:" + tc.plan}
			if !reflect.DeepEqual(trace, want) {
				t.Fatalf("trace = %q, want %q", trace, want)
			}
			identity := map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "run_id": start.Ref.RunID, "definition_version": float64(start.DefinitionVersion)}
			recovery := map[string]any{"operation": "recovery"}
			reconcile := map[string]any{"operation": "reconcile", "payload": map[string]any{"rejected": map[string]any{"status": float64(402), "raw": plannerRejectionTestBody}}}
			for key, value := range identity {
				recovery[key], reconcile[key] = value, value
			}
			if !reflect.DeepEqual(requests, []map[string]any{recovery, recovery, reconcile, reconcile}) {
				t.Fatalf("requests = %v", requests)
			}
			// The native entry receives exactly the authorized request.
			for _, statement := range server.Statements() {
				if strings.Contains(statement.SQL, tc.plan+"(") {
					var executed map[string]any
					if len(statement.Args) != 1 || json.Unmarshal([]byte(statement.Args[0]), &executed) != nil || !reflect.DeepEqual(executed, reconcile) {
						t.Fatalf("reconcile executed with %q", statement.Args)
					}
				}
			}
		})
	}
}

func TestRecoverRejectedPlanningRefusesInputsBeforeAuthorization(t *testing.T) {
	start := workerPlanningStartFixture()
	rejection := classifyPlannerProviderRejection(402, []byte(plannerRejectionTestBody))
	script := &plannerRejectionScript{family: "78"}
	compensation, server := plannerRejectionCompensation(t, script)
	valid := plannerRejectionIdentity(start, nil)
	for name, tc := range map[string]struct {
		d         *workerFindingPlanningDatabase
		identity  json.RawMessage
		rejection *plannerProviderRejection
	}{
		"nil database":           {nil, valid, rejection},
		"unsupported family":     {&workerFindingPlanningDatabase{compensation: compensation, start: start, family: workerPlanningFamily(255)}, valid, rejection},
		"ordered release":        {&workerFindingPlanningDatabase{compensation: compensation, start: start, family: workerPlanningOrdered68}, valid, rejection},
		"no compensation":        {&workerFindingPlanningDatabase{start: start}, valid, rejection},
		"no rejection":           {&workerFindingPlanningDatabase{compensation: compensation, start: start}, valid, nil},
		"moderation status":      {&workerFindingPlanningDatabase{compensation: compensation, start: start}, valid, &plannerProviderRejection{Status: 403, Body: []byte(`{"error":{"code":403}}`)}},
		"forged body":            {&workerFindingPlanningDatabase{compensation: compensation, start: start}, valid, &plannerProviderRejection{Status: 402, Body: []byte(`{"error":{"code":402},"usage":{}}`)}},
		"status and code differ": {&workerFindingPlanningDatabase{compensation: compensation, start: start}, valid, &plannerProviderRejection{Status: 401, Body: []byte(`{"error":{"code":402}}`)}},
		"malformed identity":     {&workerFindingPlanningDatabase{compensation: compensation, start: start}, json.RawMessage(`{`), rejection},
		"foreign run":            {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"run_id": start.Ref.EnvironmentID}), rejection},
		"foreign organization":   {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"organization_id": start.Ref.WorkspaceID}), rejection},
		"another version":        {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"definition_version": 8}), rejection},
		"version as text":        {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"definition_version": "7"}), rejection},
		"missing field":          {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"workspace_id": nil}), rejection},
		"extra input digest":     {&workerFindingPlanningDatabase{compensation: compensation, start: start}, plannerRejectionIdentity(start, map[string]any{"input_digest": start.InputDigest}), rejection},
		"null field":             {&workerFindingPlanningDatabase{compensation: compensation, start: start}, json.RawMessage(`{"organization_id":null,"workspace_id":"x","environment_id":"x","run_id":"x","definition_version":7}`), rejection},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.d.RecoverRejectedPlanning(context.Background(), tc.identity, tc.rejection); !errors.Is(err, authorization.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if statements := server.Statements(); len(statements) != 0 {
		t.Fatalf("refused input reached the compensation role: %q", statements)
	}
}

func TestRecoverRejectedPlanningPropagatesAuthorityErrors(t *testing.T) {
	start := workerPlanningStartFixture()
	rejection := classifyPlannerProviderRejection(429, []byte(`{"error":{"message":"Rate limit exceeded","code":429}}`))
	identity := plannerRejectionIdentity(start, nil)
	// An executor without a key or pool refuses the authorization.
	if err := (&workerFindingPlanningDatabase{compensation: &authorization.WorkerExecutor{}, start: start}).RecoverRejectedPlanning(context.Background(), identity, rejection); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("unconfigured compensation: err=%v", err)
	}
	for name, tc := range map[string]struct {
		script *plannerRejectionScript
		want   error
		trace  []string
	}{
		"recovery authorization denied":   {&plannerRejectionScript{sourceCode: map[string]string{"recovery": "42501"}}, authorization.ErrDenied, []string{"source:recovery"}},
		"recovery execution denied":       {&plannerRejectionScript{recoveryCode: "42501"}, authorization.ErrDenied, []string{"source:recovery", "source:recovery", "proof:finding.planning.recovery", "exec:zasp_authorization80_worker.planning78_recovery"}},
		"recovery unavailable":            {&plannerRejectionScript{recoveryCode: "08006"}, authorization.ErrUnavailable, nil},
		"reconcile authorization invalid": {&plannerRejectionScript{sourceCode: map[string]string{"reconcile": "22023"}}, authorization.ErrInvalid, []string{"source:recovery", "source:recovery", "proof:finding.planning.recovery", "exec:zasp_authorization80_worker.planning78_recovery", "source:reconcile"}},
		"reconcile execution conflict":    {&plannerRejectionScript{reconcileCode: "40001"}, authorization.ErrConflict, nil},
	} {
		t.Run(name, func(t *testing.T) {
			tc.script.family = "78"
			tc.script.prior = plannerRejectionMetadata(t, start, "started", false, false)
			tc.script.terminal = plannerRejectionMetadata(t, start, "needs_human", false, false)
			compensation, server := plannerRejectionCompensation(t, tc.script)
			err := (&workerFindingPlanningDatabase{compensation: compensation, start: start}).RecoverRejectedPlanning(context.Background(), identity, rejection)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.trace != nil {
				if trace, _ := plannerRejectionTrace(t, server.Statements()); !reflect.DeepEqual(trace, tc.trace) {
					t.Fatalf("trace = %q", trace)
				}
			}
		})
	}
}

func TestRecoverRejectedPlanningRefusesAnotherState(t *testing.T) {
	start := workerPlanningStartFixture()
	rejection := classifyPlannerProviderRejection(401, []byte(`{"error":{"message":"No auth credentials found","code":401}}`))
	started := plannerRejectionMetadata(t, start, "started", false, false)
	needsHuman := plannerRejectionMetadata(t, start, "needs_human", false, false)
	foreign := json.RawMessage(strings.Replace(string(needsHuman), start.Ref.RunID, start.Ref.EnvironmentID, 1))
	for name, tc := range map[string]struct {
		prior, terminal json.RawMessage
		reconciled      bool
	}{
		// The evidence belongs to a started intent with no response only.
		"prepared intent":           {plannerRejectionMetadata(t, start, "prepared", false, false), needsHuman, false},
		"captured response":         {plannerRejectionMetadata(t, start, "completed", true, true), needsHuman, false},
		"already terminal":          {needsHuman, needsHuman, false},
		"unverifiable prior":        {foreign, needsHuman, false},
		"reconciled to settled":     {started, plannerRejectionMetadata(t, start, "settled", true, true), true},
		"terminal with a response":  {started, plannerRejectionMetadata(t, start, "needs_human", false, true), true},
		"terminal with usage known": {started, plannerRejectionMetadata(t, start, "needs_human", true, true), true},
		"unverifiable terminal":     {started, foreign, true},
		"terminal still started":    {started, started, true},
	} {
		t.Run(name, func(t *testing.T) {
			script := &plannerRejectionScript{family: "78", prior: tc.prior, terminal: tc.terminal}
			compensation, server := plannerRejectionCompensation(t, script)
			err := (&workerFindingPlanningDatabase{compensation: compensation, start: start}).RecoverRejectedPlanning(context.Background(), plannerRejectionIdentity(start, nil), rejection)
			if !errors.Is(err, authorization.ErrConflict) {
				t.Fatalf("err = %v", err)
			}
			trace, _ := plannerRejectionTrace(t, server.Statements())
			if reconciled := len(trace) == 8 && trace[7] == "exec:zasp_temporal78.plan"; reconciled != tc.reconciled || !tc.reconciled && len(trace) != 4 {
				t.Fatalf("trace = %q", trace)
			}
		})
	}
}

// planUnavailableCall is one QueryJSON the product made, with its decoded
// argument.
type planUnavailableCall struct {
	statement string
	argument  map[string]any
}

type planUnavailableDatabase struct {
	t     *testing.T
	calls []planUnavailableCall
	reply func(statement string, argument map[string]any) (json.RawMessage, error)
}

func (d *planUnavailableDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	if len(args) != 1 {
		d.t.Fatalf("%s called with %d arguments", statement, len(args))
	}
	raw, ok := args[0].([]byte)
	var argument map[string]any
	if !ok || json.Unmarshal(raw, &argument) != nil {
		d.t.Fatalf("%s argument %#v", statement, args[0])
	}
	d.calls = append(d.calls, planUnavailableCall{statement, argument})
	return d.reply(statement, argument)
}

func (d *planUnavailableDatabase) Exec(context.Context, string, ...any) error {
	d.t.Fatal("unexpected Exec")
	return nil
}

func (d *planUnavailableDatabase) SchemaVersion(context.Context) (string, error) {
	d.t.Fatal("unexpected SchemaVersion")
	return "", nil
}

// planUnavailableRecoveringDatabase also settles a captured intent itself.
type planUnavailableRecoveringDatabase struct {
	*planUnavailableDatabase
	identity json.RawMessage
	body     []byte
	recovers int
	err      error
}

func (d *planUnavailableRecoveringDatabase) RecoverCapturedPlanning(_ context.Context, identity json.RawMessage, body []byte) error {
	d.recovers++
	d.identity, d.body = identity, body
	return d.err
}

const (
	planUnavailableStateSQL = `SELECT zasp_temporal78.planning_state($1::jsonb)`
	planUnavailablePlanSQL  = `SELECT zasp_temporal78.plan($1::jsonb)`
)

func planUnavailableIdentity(start orchestration.StartRequest, extra map[string]any) map[string]any {
	q := map[string]any{"organization_id": start.Ref.OrganizationID, "workspace_id": start.Ref.WorkspaceID, "environment_id": start.Ref.EnvironmentID, "run_id": start.Ref.RunID, "definition_version": float64(start.DefinitionVersion)}
	for key, value := range extra {
		q[key] = value
	}
	return q
}

func TestPlanUnavailableRefusesMissingDependencies(t *testing.T) {
	start := workerPlanningStartFixture()
	for name, product := range map[string]*temporalFindingResponseProduct{
		"nil product":          nil,
		"no shared product":    {},
		"no executor":          {shared: &temporalSecurityAgentProduct{}},
		"typed nil executor":   {shared: &temporalSecurityAgentProduct{executor: singleDeliveryDatabaseFunc(nil)}},
		"nil pointer executor": {shared: &temporalSecurityAgentProduct{executor: (*planUnavailableDatabase)(nil)}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := product.planUnavailable(context.Background(), start); !errors.Is(err, orchestration.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPlanUnavailableLoadsAndReconcilesUnsent(t *testing.T) {
	start := workerPlanningStartFixture()
	identity := planUnavailableIdentity(start, nil)
	load := planUnavailableIdentity(start, map[string]any{"operation": "load"})
	reconcile := planUnavailableIdentity(start, map[string]any{"operation": "reconcile", "payload": map[string]any{}})
	for name, tc := range map[string]struct {
		state string
		want  []planUnavailableCall
	}{
		// No intent yet: the run is captured first.
		"no intent":        {"null", []planUnavailableCall{{planUnavailableStateSQL, identity}, {planUnavailablePlanSQL, load}, {planUnavailablePlanSQL, reconcile}}},
		"no intent spaced": {" null\n", []planUnavailableCall{{planUnavailableStateSQL, identity}, {planUnavailablePlanSQL, load}, {planUnavailablePlanSQL, reconcile}}},
		"captured intent":  {`{"state":"loaded"}`, []planUnavailableCall{{planUnavailableStateSQL, identity}, {planUnavailablePlanSQL, reconcile}}},
		"terminal intent":  {`{"state":"needs_human"}`, []planUnavailableCall{{planUnavailableStateSQL, identity}, {planUnavailablePlanSQL, reconcile}}},
	} {
		t.Run(name, func(t *testing.T) {
			db := &planUnavailableDatabase{t: t, reply: func(statement string, argument map[string]any) (json.RawMessage, error) {
				switch {
				case statement == planUnavailableStateSQL:
					return json.RawMessage(tc.state), nil
				case argument["operation"] == "load":
					return json.RawMessage(`{"state":"loaded"}`), nil
				default:
					return json.RawMessage(`{"state":"needs_human","reason":"planner_not_sent"}`), nil
				}
			}}
			product := &temporalFindingResponseProduct{shared: &temporalSecurityAgentProduct{executor: db}}
			if err := product.planUnavailable(context.Background(), start); err != nil {
				t.Fatalf("err = %v", err)
			}
			if !reflect.DeepEqual(db.calls, tc.want) {
				t.Fatalf("calls = %v\nwant %v", db.calls, tc.want)
			}
		})
	}
}

func TestPlanUnavailableRefusesANonTerminalOutcome(t *testing.T) {
	start := workerPlanningStartFixture()
	for name, terminal := range map[string]string{
		"settled":       `{"state":"settled"}`,
		"still loaded":  `{"state":"loaded"}`,
		"no state":      `{}`,
		"not an object": `"needs_human"`,
		"malformed":     `{`,
	} {
		t.Run(name, func(t *testing.T) {
			db := &planUnavailableDatabase{t: t, reply: func(statement string, _ map[string]any) (json.RawMessage, error) {
				if statement == planUnavailableStateSQL {
					return json.RawMessage(`{"state":"loaded"}`), nil
				}
				return json.RawMessage(terminal), nil
			}}
			if err := (&temporalFindingResponseProduct{shared: &temporalSecurityAgentProduct{executor: db}}).planUnavailable(context.Background(), start); !errors.Is(err, orchestration.ErrConflict) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestPlanUnavailablePropagatesQueryErrors(t *testing.T) {
	start := workerPlanningStartFixture()
	failure := errors.New("scripted query failure")
	for name, tc := range map[string]struct {
		failing string // "state", "load" or "reconcile"
		calls   int
	}{
		"state":     {"state", 1},
		"load":      {"load", 2},
		"reconcile": {"reconcile", 3},
	} {
		t.Run(name, func(t *testing.T) {
			db := &planUnavailableDatabase{t: t, reply: func(statement string, argument map[string]any) (json.RawMessage, error) {
				phase := "state"
				if statement != planUnavailableStateSQL {
					phase, _ = argument["operation"].(string)
				}
				if phase == tc.failing {
					return nil, failure
				}
				if phase == "state" {
					return json.RawMessage(`null`), nil
				}
				return json.RawMessage(`{"state":"needs_human"}`), nil
			}}
			if err := (&temporalFindingResponseProduct{shared: &temporalSecurityAgentProduct{executor: db}}).planUnavailable(context.Background(), start); !errors.Is(err, failure) || len(db.calls) != tc.calls {
				t.Fatalf("err = %v after %d calls", err, len(db.calls))
			}
		})
	}
}

// A planning database that settles captured intents itself reconciles the
// unsent intent through that recovery, never through a forward plan call.
func TestPlanUnavailableUsesCapturedRecovery(t *testing.T) {
	start := workerPlanningStartFixture()
	for name, recoverErr := range map[string]error{"settled": nil, "refused": authorization.ErrConflict} {
		t.Run(name, func(t *testing.T) {
			db := &planUnavailableRecoveringDatabase{err: recoverErr, planUnavailableDatabase: &planUnavailableDatabase{t: t, reply: func(statement string, _ map[string]any) (json.RawMessage, error) {
				if statement == planUnavailableStateSQL {
					return json.RawMessage(`null`), nil
				}
				return json.RawMessage(`{"state":"loaded"}`), nil
			}}}
			err := (&temporalFindingResponseProduct{shared: &temporalSecurityAgentProduct{executor: db}}).planUnavailable(context.Background(), start)
			if !errors.Is(err, recoverErr) || recoverErr == nil && err != nil {
				t.Fatalf("err = %v", err)
			}
			var identity map[string]any
			if db.recovers != 1 || db.body != nil || json.Unmarshal(db.identity, &identity) != nil || !reflect.DeepEqual(identity, planUnavailableIdentity(start, nil)) {
				t.Fatalf("recovery: count=%d identity=%s body=%q", db.recovers, db.identity, db.body)
			}
			if len(db.calls) != 2 || db.calls[1].argument["operation"] != "load" {
				t.Fatalf("calls = %v", db.calls)
			}
		})
	}
}

// With the worker authorization split, the run is prepared by the forward
// role before any planning statement, and a refused preparation stops it.
func TestPlanUnavailablePreparesTheFindingFirst(t *testing.T) {
	start := workerPlanningStartFixture()
	untouched := &planUnavailableDatabase{t: t, reply: func(string, map[string]any) (json.RawMessage, error) {
		t.Fatal("the base database was used directly")
		return nil, nil
	}}
	product := &temporalFindingResponseProduct{shared: &temporalSecurityAgentProduct{executor: untouched, workerForward: &authorization.WorkerExecutor{}}}
	if err := product.planUnavailable(context.Background(), start); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatalf("unconfigured forward role: err=%v", err)
	}

	// A prepared run reads its planning state through the authorized
	// planning database, so a denial there is returned as is.
	pool, server := newWorkerWirePool(t, func(statement workerWireStatement) workerWireReply {
		if strings.Contains(statement.SQL, "prepare_finding(") {
			return workerWireReply{Row: json.RawMessage(`""`)}
		}
		return workerWireReply{Code: "42501"}
	})
	key, err := authorization.NewWorkerKey(authorization.WorkerForward, []byte(strings.Repeat("f", 32)))
	if err != nil {
		t.Fatal(err)
	}
	checker := &plannerTimezoneNoChecks{}
	forward, err := authorization.NewWorkerExecutor(pool, checker, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", key)
	if err != nil {
		t.Fatal(err)
	}
	product.shared.workerForward = forward
	if err := product.planUnavailable(context.Background(), start); !errors.Is(err, authorization.ErrDenied) {
		t.Fatalf("denied planning state: err=%v", err)
	}
	statements := server.Statements()
	if len(statements) != 3 || !strings.Contains(statements[0].SQL, "zasp_authorization80_worker.prepare_finding(") || !strings.Contains(statements[1].SQL, "zasp_authorization80_worker.revision(") || !strings.Contains(statements[2].SQL, "zasp_authorization80_worker.planning78_source(") || checker.calls != 0 {
		t.Fatalf("statements = %q checks=%d", statements, checker.calls)
	}
	var prepared map[string]any
	if len(statements[0].Args) != 1 || json.Unmarshal([]byte(statements[0].Args[0]), &prepared) != nil || !reflect.DeepEqual(prepared, planUnavailableIdentity(start, map[string]any{"input_digest": start.InputDigest})) {
		t.Fatalf("prepared request %q", statements[0].Args)
	}
	var state map[string]any
	if len(statements[2].Args) != 2 || statements[2].Args[0] != "state" || json.Unmarshal([]byte(statements[2].Args[1]), &state) != nil || !reflect.DeepEqual(state, planUnavailableIdentity(start, nil)) {
		t.Fatalf("planning state request %q", statements[2].Args)
	}
}
