package orchestration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

var testRef = RunRef{"pid_6a000001-0000-4000-8000-000000000001", "pid_6a000002-0000-4000-8000-000000000002", "pid_6a000003-0000-4000-8000-000000000003", "pid_8e190001-0000-4000-8000-000000000001"}

func request() StartRequest { return StartRequest{testRef, 2, strings.Repeat("a", 64)} }

type boundaryClient struct {
	client.Client
	starts   []client.StartWorkflowOptions
	inputs   []StartRequest
	startErr error
	original StartRequest
	signal   Message
	deadline bool
}

func (c *boundaryClient) ExecuteWorkflow(ctx context.Context, o client.StartWorkflowOptions, _ interface{}, args ...interface{}) (client.WorkflowRun, error) {
	c.starts = append(c.starts, o)
	c.inputs = append(c.inputs, args[0].(StartRequest))
	_, c.deadline = ctx.Deadline()
	return nil, c.startErr
}
func (c *boundaryClient) SignalWorkflow(ctx context.Context, id, run, signal string, arg interface{}) error {
	if id == "" || run != "" || signal != "product-decision" {
		return errors.New("wrong signal mapping")
	}
	c.signal = arg.(Message)
	return nil
}
func (c *boundaryClient) GetWorkflowHistory(ctx context.Context, id, run string, long bool, filter enumspb.HistoryEventFilterType) client.HistoryEventIterator {
	p, _ := converter.GetDefaultDataConverter().ToPayloads(c.original)
	return &oneEvent{event: &historypb.HistoryEvent{Attributes: &historypb.HistoryEvent_WorkflowExecutionStartedEventAttributes{WorkflowExecutionStartedEventAttributes: &historypb.WorkflowExecutionStartedEventAttributes{Input: p}}}}
}

type oneEvent struct{ event *historypb.HistoryEvent }

func (i *oneEvent) HasNext() bool { return i.event != nil }
func (i *oneEvent) Next() (*historypb.HistoryEvent, error) {
	e := i.event
	i.event = nil
	return e, nil
}

// Catch random workflow IDs, permissive reuse, unbounded RPCs, and treating a
// conflicting prior start as success. The fake is only the external SDK boundary.
func TestStartMappingAndConflict(t *testing.T) {
	c := &boundaryClient{}
	engine, err := NewTemporalEngine(c, "security-agents", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = engine.Start(context.Background(), request()); err != nil {
			t.Fatal(err)
		}
	}
	want := "security-agent/v1/" + testRef.OrganizationID + "/" + testRef.WorkspaceID + "/" + testRef.EnvironmentID + "/" + testRef.RunID
	if len(c.starts) != 2 || c.starts[0].ID != want || c.starts[1].ID != want || !c.deadline || c.starts[0].TaskQueue != "security-agents" || c.starts[0].WorkflowIDReusePolicy != enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE || c.starts[0].WorkflowIDConflictPolicy != enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL || !c.starts[0].WorkflowExecutionErrorWhenAlreadyStarted {
		t.Fatal("unsafe start mapping", c.starts)
	}
	c.startErr = serviceerror.NewWorkflowExecutionAlreadyStarted("existing", "request", "execution")
	c.original = request()
	if err = engine.Start(context.Background(), request()); err != nil {
		t.Fatal("identical replay refused", err)
	}
	c.original.InputDigest = strings.Repeat("b", 64)
	if err = engine.Start(context.Background(), request()); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting digest accepted", err)
	}
}

type memoryStore struct {
	command Command
	acks    int
}

type deadlineStore struct{ Store }

func (s deadlineStore) Pending(ctx context.Context) ([]Command, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second {
		return nil, ErrInvalid
	}
	return nil, nil
}
func TestRelayBoundsWholeBatch(t *testing.T) {
	relay := Relay{Store: deadlineStore{}, Engine: &boundaryEngine{}}
	if err := relay.RunOnce(context.Background()); err != nil {
		t.Fatal("batch has no finite deadline", err)
	}
}

func TestNotifyMappingAndValidation(t *testing.T) {
	c := &boundaryClient{}
	engine, err := NewTemporalEngine(c, "security-agents", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{Ref: testRef, EventID: testRef.RunID, Kind: "approval", DecisionID: testRef.RunID}
	for i := 0; i < 2; i++ {
		if err = engine.Notify(context.Background(), message); err != nil {
			t.Fatal(err)
		}
	}
	if c.signal != message {
		t.Fatal("signal changed committed decision identity")
	}
	message.DecisionID = "uncommitted"
	if err = engine.Notify(context.Background(), message); !errors.Is(err, ErrInvalid) {
		t.Fatal("uncommitted decision accepted", err)
	}
}

func (s *memoryStore) Pending(context.Context) ([]Command, error) { return []Command{s.command}, nil }
func (s *memoryStore) Attempt(_ context.Context, c Command) error {
	if c != s.command {
		return ErrInvalid
	}
	return nil
}
func (s *memoryStore) Ack(_ context.Context, c Command) error {
	if c != s.command {
		return ErrInvalid
	}
	s.acks++
	return nil
}

type boundaryEngine struct {
	err     error
	start   int
	message Message
}

func (e *boundaryEngine) Start(context.Context, StartRequest) error { e.start++; return e.err }
func (e *boundaryEngine) Notify(_ context.Context, m Message) error { e.message = m; return e.err }
func TestRelayAcceptanceBeforeAckAndScope(t *testing.T) {
	c := Command{Ref: testRef, EventID: testRef.RunID, Kind: "start", DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64), ExecutionOwner: "temporal"}
	store := &memoryStore{command: c}
	engine := &boundaryEngine{err: errors.New("offline")}
	relay := Relay{Store: store, Engine: engine}
	if err := relay.RunOnce(context.Background()); err == nil || store.acks != 0 {
		t.Fatal("unaccepted command acknowledged")
	}
	engine.err = nil
	for i := 0; i < 2; i++ {
		if err := relay.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if store.acks != 2 || engine.start != 3 {
		t.Fatal("relay recovery did not deliver")
	}
	store.command.ExecutionOwner = "legacy"
	if err := relay.RunOnce(context.Background()); err == nil || engine.start != 3 {
		t.Fatal("legacy owned command dispatched")
	}
	store.command = c
	store.command.Ref.OrganizationID = ""
	if err := relay.RunOnce(context.Background()); err == nil || engine.start != 3 {
		t.Fatal("invalid tenant dispatched")
	}
	store.command = c
	store.command.Kind = "approval"
	store.command.DecisionID = testRef.RunID
	if err := relay.RunOnce(context.Background()); err != nil || engine.message.DecisionID != testRef.RunID {
		t.Fatal("decision lost", err)
	}
}

type rotatingStore struct {
	commands  []Command
	next      int
	attempted []string
	acked     []string
	refuse    bool
}

func (s *rotatingStore) Pending(context.Context) ([]Command, error) { return s.commands[s.next:], nil }
func (s *rotatingStore) Attempt(_ context.Context, c Command) error {
	if s.refuse {
		return ErrUnavailable
	}
	s.attempted = append(s.attempted, c.EventID)
	s.next++
	return nil
}
func (s *rotatingStore) Ack(_ context.Context, c Command) error {
	s.acked = append(s.acked, c.EventID)
	return nil
}

type deadlineEngine struct {
	store          *rotatingStore
	calls          int
	missingAttempt bool
}

func (e *deadlineEngine) Start(ctx context.Context, r StartRequest) error {
	e.calls++
	if len(e.store.attempted) < e.calls {
		e.missingAttempt = true
	}
	if r.Ref.OrganizationID == testRef.OrganizationID {
		<-ctx.Done()
		return ErrUnavailable
	}
	return nil
}
func (e *deadlineEngine) Notify(context.Context, Message) error { return ErrInvalid }

// Catch recording the polling turn after a timed-out RPC, which cannot commit
// its cursor anymore and leaves the same slow prefix first on every poll.
func TestRelayAdvancesBeforeDeadline(t *testing.T) {
	first := Command{Ref: testRef, EventID: testRef.RunID, Kind: "start", DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64), ExecutionOwner: "temporal"}
	second := first
	second.Ref.OrganizationID = "pid_6a000009-0000-4000-8000-000000000009"
	second.EventID = second.Ref.OrganizationID
	store := &rotatingStore{commands: []Command{first, second}}
	engine := &deadlineEngine{store: store}
	relay := Relay{Store: store, Engine: engine}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := relay.RunOnce(ctx); err == nil {
		t.Fatal("deadline reported acceptance")
	}
	if engine.missingAttempt || len(store.attempted) != 1 || len(store.acked) != 0 {
		t.Fatal("attempt not recorded before deadline; failed delivery must stay unacknowledged")
	}
	if err := relay.RunOnce(context.Background()); err != nil || len(store.acked) != 1 || store.acked[0] != second.EventID {
		t.Fatal("next poll did not reach healthy tenant", err)
	}
}
func TestRelayAttemptFailurePreventsDispatch(t *testing.T) {
	c := Command{Ref: testRef, EventID: testRef.RunID, Kind: "start", DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64), ExecutionOwner: "temporal"}
	store := &rotatingStore{commands: []Command{c}, refuse: true}
	engine := &boundaryEngine{}
	relay := Relay{Store: store, Engine: engine}
	if err := relay.RunOnce(context.Background()); err == nil || engine.start != 0 || len(store.acked) != 0 {
		t.Fatal("dispatch bypassed failed durable attempt", err)
	}
}
