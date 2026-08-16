package producttelemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type fakeDriver struct {
	mu        sync.Mutex
	calls     []DriverRecord
	captureFn func(context.Context, DriverRecord) (DriverCaptured, error)
}

type valueDriver struct{}

func (valueDriver) Capture(_ context.Context, record DriverRecord) (DriverCaptured, error) {
	return capturedFromRecord(record), nil
}

func (driver *fakeDriver) Capture(ctx context.Context, record DriverRecord) (DriverCaptured, error) {
	driver.mu.Lock()
	driver.calls = append(driver.calls, record)
	captureFn := driver.captureFn
	driver.mu.Unlock()
	if captureFn == nil {
		return capturedFromRecord(record), nil
	}
	return captureFn(ctx, record)
}

func (driver *fakeDriver) callCount() int {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return len(driver.calls)
}

func (driver *fakeDriver) call(index int) DriverRecord {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.calls[index]
}

func TestAllowlistSerializerBuildsExactCanonicalRecord(t *testing.T) {
	scope := telemetryTestScope(t)
	serializer := NewAllowlistSerializer()
	var contract EventSerializer = serializer
	want := expectedRecord(scope, "m1-19", true)

	for _, fields := range [][]Field{
		{TextField("source", "m1-19"), BooleanField("success", true)},
		{BooleanField("success", true), TextField("source", "m1-19")},
	} {
		record, err := contract.Serialize(scope, Event{Name: EventProofCompleted, Fields: fields})
		if err != nil {
			t.Fatalf("Serialize returned error: %v", err)
		}
		if record != want {
			t.Fatalf("record = %#v, want %#v", record, want)
		}
	}
}

func TestAllowlistSerializerRejectsUnknownAndProhibitedFields(t *testing.T) {
	serializer := NewAllowlistSerializer()
	prohibited := []string{
		"prompt", "secret", "ip", "ip_address", "raw_evidence", "evidence",
		"context", "person", "person_profile", "feature_flag", "distinct_id",
		"$process_person_profile", "api_key", "properties",
	}
	for _, name := range append(prohibited, "unknown") {
		t.Run(name, func(t *testing.T) {
			event := exactEvent(true)
			event.Fields = append(event.Fields, TextField(name, "seeded-provider-sensitive-value"))
			record, err := serializer.Serialize(telemetryTestScope(t), event)
			if !errors.Is(err, ErrEvent) || record != (DriverRecord{}) {
				t.Fatalf("Serialize = %#v, %v; want zero, ErrEvent", record, err)
			}
		})
	}
}

func TestAllowlistSerializerRejectsEveryMalformedCatalogRepresentation(t *testing.T) {
	valid := exactEvent(true)
	tests := map[string]Event{
		"zero event":               {},
		"unknown event":            {Name: EventName("capture")},
		"missing source":           {Name: EventProofCompleted, Fields: []Field{BooleanField("success", true)}},
		"missing success":          {Name: EventProofCompleted, Fields: []Field{TextField("source", "m1-19")}},
		"no fields":                {Name: EventProofCompleted},
		"duplicate source":         {Name: EventProofCompleted, Fields: []Field{TextField("source", "m1-19"), TextField("source", "other")}},
		"duplicate success":        {Name: EventProofCompleted, Fields: []Field{BooleanField("success", true), BooleanField("success", false)}},
		"source wrong kind":        {Name: EventProofCompleted, Fields: []Field{BooleanField("source", true), BooleanField("success", true)}},
		"success wrong kind":       {Name: EventProofCompleted, Fields: []Field{TextField("source", "m1-19"), TextField("success", "true")}},
		"zero field":               {Name: EventProofCompleted, Fields: []Field{{}, BooleanField("success", true)}},
		"forged text boolean":      {Name: EventProofCompleted, Fields: []Field{{name: "source", kind: fieldText, text: "m1-19", boolean: true}, BooleanField("success", true)}},
		"forged boolean text":      {Name: EventProofCompleted, Fields: []Field{TextField("source", "m1-19"), {name: "success", kind: fieldBoolean, text: "true", boolean: true}}},
		"forged field kind":        {Name: EventProofCompleted, Fields: []Field{{name: "source", kind: fieldKind(99), text: "m1-19"}, BooleanField("success", true)}},
		"source constructor empty": {Name: EventProofCompleted, Fields: []Field{TextField("source", ""), BooleanField("success", true)}},
	}
	for name, event := range tests {
		t.Run(name, func(t *testing.T) {
			record, err := NewAllowlistSerializer().Serialize(telemetryTestScope(t), event)
			if !errors.Is(err, ErrEvent) || record != (DriverRecord{}) {
				t.Fatalf("Serialize = %#v, %v; want zero, ErrEvent", record, err)
			}
		})
	}

	record, err := NewAllowlistSerializer().Serialize(domain.Scope{}, valid)
	if !errors.Is(err, ErrEvent) || record != (DriverRecord{}) {
		t.Fatalf("zero-scope Serialize = %#v, %v; want zero, ErrEvent", record, err)
	}
}

func TestAllowlistSerializerEnforcesSourceGrammar(t *testing.T) {
	valid := []string{"a", "m1-19", "proof.completed", "product_source2", strings.Repeat("a", 63)}
	for _, source := range valid {
		t.Run("valid-"+source[:min(len(source), 16)], func(t *testing.T) {
			record, err := NewAllowlistSerializer().Serialize(telemetryTestScope(t), Event{
				Name:   EventProofCompleted,
				Fields: []Field{TextField("source", source), BooleanField("success", false)},
			})
			if err != nil || record.Source != source {
				t.Fatalf("Serialize = %#v, %v; want source %q", record, err, source)
			}
		})
	}

	invalid := []string{
		"", "A", ".source", "source.", "two..parts", "two__parts", "two--parts",
		"m1/19", "m1 19", "m1\n19", "söurce", strings.Repeat("a", 64),
	}
	for index, source := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			record, err := NewAllowlistSerializer().Serialize(telemetryTestScope(t), Event{
				Name:   EventProofCompleted,
				Fields: []Field{TextField("source", source), BooleanField("success", false)},
			})
			if !errors.Is(err, ErrEvent) || record != (DriverRecord{}) {
				t.Fatalf("Serialize = %#v, %v; want zero, ErrEvent", record, err)
			}
		})
	}
}

func TestTelemetryTracksOneExactSerializedEvent(t *testing.T) {
	scope := telemetryTestScope(t)
	driver := &fakeDriver{}
	telemetry, err := New(driver, Config{OperationTimeout: time.Second})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	var contract ProductTelemetry = telemetry
	if err := contract.Track(context.Background(), scope, exactEvent(true)); err != nil {
		t.Fatalf("Track returned error: %v", err)
	}
	if driver.callCount() != 1 {
		t.Fatalf("driver calls = %d, want 1", driver.callCount())
	}
	want := expectedRecord(scope, "m1-19", true)
	if got := driver.call(0); got != want {
		t.Fatalf("driver record = %#v, want %#v", got, want)
	}
}

func TestTelemetryRejectsInvalidConstruction(t *testing.T) {
	validDriver := &fakeDriver{}
	var typedNil *fakeDriver
	for name, test := range map[string]struct {
		driver Driver
		config Config
	}{
		"nil driver":         {config: Config{OperationTimeout: time.Second}},
		"typed nil driver":   {driver: typedNil, config: Config{OperationTimeout: time.Second}},
		"zero timeout":       {driver: validDriver},
		"negative timeout":   {driver: validDriver, config: Config{OperationTimeout: -time.Nanosecond}},
		"timeout over limit": {driver: validDriver, config: Config{OperationTimeout: 30*time.Second + time.Nanosecond}},
	} {
		t.Run(name, func(t *testing.T) {
			telemetry, err := New(test.driver, test.config)
			if !errors.Is(err, ErrConfiguration) || telemetry != nil {
				t.Fatalf("New = %#v, %v; want nil, ErrConfiguration", telemetry, err)
			}
		})
	}
	if telemetry, err := New(valueDriver{}, Config{OperationTimeout: 30 * time.Second}); err != nil || telemetry == nil {
		t.Fatalf("exact-limit New = %#v, %v; want telemetry", telemetry, err)
	}
}

func TestTelemetryRejectsInvalidEventsBeforeDriverIO(t *testing.T) {
	driver := &fakeDriver{}
	telemetry := mustTelemetry(t, driver, Config{OperationTimeout: time.Second})
	tests := map[string]struct {
		ctx   context.Context
		scope domain.Scope
		event Event
	}{
		"nil context":   {scope: telemetryTestScope(t), event: exactEvent(true)},
		"zero scope":    {ctx: context.Background(), event: exactEvent(true)},
		"unknown field": {ctx: context.Background(), scope: telemetryTestScope(t), event: Event{Name: EventProofCompleted, Fields: []Field{TextField("source", "m1-19"), BooleanField("success", true), TextField("prompt", "seeded")}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := telemetry.Track(test.ctx, test.scope, test.event)
			if !errors.Is(err, ErrEvent) {
				t.Fatalf("Track error = %v, want ErrEvent", err)
			}
		})
	}
	if driver.callCount() != 0 {
		t.Fatalf("driver calls = %d, want 0", driver.callCount())
	}
}

func TestTelemetryReturnsFixedCaptureErrorForUnavailableOrMalformedDriver(t *testing.T) {
	scope := telemetryTestScope(t)
	base := capturedFromRecord(expectedRecord(scope, "m1-19", true))
	providerError := errors.New("provider endpoint credential-shaped-value")
	tests := map[string]func(context.Context, DriverRecord) (DriverCaptured, error){
		"provider error":     func(context.Context, DriverRecord) (DriverCaptured, error) { return DriverCaptured{}, providerError },
		"provider panic":     func(context.Context, DriverRecord) (DriverCaptured, error) { panic("provider secret-shaped-value") },
		"empty success":      func(context.Context, DriverRecord) (DriverCaptured, error) { return DriverCaptured{}, nil },
		"organization drift": mutateCaptured(base, func(value *DriverCaptured) { value.OrganizationID = telemetryTestID(t, 9).String() }),
		"workspace drift":    mutateCaptured(base, func(value *DriverCaptured) { value.WorkspaceID = telemetryTestID(t, 9).String() }),
		"environment drift":  mutateCaptured(base, func(value *DriverCaptured) { value.EnvironmentID = telemetryTestID(t, 9).String() }),
		"distinct ID drift":  mutateCaptured(base, func(value *DriverCaptured) { value.DistinctID += "-other" }),
		"event drift":        mutateCaptured(base, func(value *DriverCaptured) { value.Event = "other" }),
		"profile missing":    mutateCaptured(base, func(value *DriverCaptured) { value.ProcessPersonProfile = nil }),
		"profile drift":      mutateCaptured(base, func(value *DriverCaptured) { value.ProcessPersonProfile = boolPointer(true) }),
		"source drift":       mutateCaptured(base, func(value *DriverCaptured) { value.Source = "other" }),
		"success missing":    mutateCaptured(base, func(value *DriverCaptured) { value.Success = nil }),
		"success drift":      mutateCaptured(base, func(value *DriverCaptured) { value.Success = boolPointer(false) }),
	}
	for name, captureFn := range tests {
		t.Run(name, func(t *testing.T) {
			driver := &fakeDriver{captureFn: captureFn}
			telemetry := mustTelemetry(t, driver, Config{OperationTimeout: time.Second})
			err := telemetry.Track(context.Background(), scope, exactEvent(true))
			if !errors.Is(err, ErrCapture) || errors.Is(err, providerError) {
				t.Fatalf("Track error = %v, want fixed ErrCapture", err)
			}
			if driver.callCount() != 1 {
				t.Fatalf("driver calls = %d, want 1", driver.callCount())
			}
		})
	}
}

func TestTelemetryBoundsCancellationAndDeadlineWithoutRetry(t *testing.T) {
	scope := telemetryTestScope(t)
	preCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	preDriver := &fakeDriver{}
	preTelemetry := mustTelemetry(t, preDriver, Config{OperationTimeout: time.Second})
	if err := preTelemetry.Track(preCancelled, scope, exactEvent(true)); !errors.Is(err, ErrCapture) {
		t.Fatalf("pre-cancelled Track error = %v, want ErrCapture", err)
	}
	if preDriver.callCount() != 0 {
		t.Fatalf("pre-cancelled calls = %d, want 0", preDriver.callCount())
	}

	deadlineDriver := &fakeDriver{captureFn: func(ctx context.Context, _ DriverRecord) (DriverCaptured, error) {
		<-ctx.Done()
		return DriverCaptured{}, ctx.Err()
	}}
	deadlineTelemetry := mustTelemetry(t, deadlineDriver, Config{OperationTimeout: time.Millisecond})
	if err := deadlineTelemetry.Track(context.Background(), scope, exactEvent(true)); !errors.Is(err, ErrCapture) {
		t.Fatalf("deadline Track error = %v, want ErrCapture", err)
	}
	if deadlineDriver.callCount() != 1 {
		t.Fatalf("deadline calls = %d, want 1", deadlineDriver.callCount())
	}
}

func TestTelemetryRejectsUnusableReceiver(t *testing.T) {
	var telemetry *Telemetry
	if err := telemetry.Track(context.Background(), telemetryTestScope(t), exactEvent(true)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("nil-receiver Track error = %v, want ErrConfiguration", err)
	}

	driver := &fakeDriver{}
	telemetry = mustTelemetry(t, driver, Config{OperationTimeout: time.Second})
	telemetry.config.OperationTimeout = 0
	if err := telemetry.Track(context.Background(), telemetryTestScope(t), exactEvent(true)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("mutated-config Track error = %v, want ErrConfiguration", err)
	}
	if driver.callCount() != 0 {
		t.Fatalf("mutated-config calls = %d, want 0", driver.callCount())
	}
}

func TestTelemetryIsConcurrentAndDoesNotRetainCallerFields(t *testing.T) {
	driver := &fakeDriver{}
	telemetry := mustTelemetry(t, driver, Config{OperationTimeout: time.Second})
	scope := telemetryTestScope(t)
	const count = 64
	errorsByCall := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			event := Event{Name: EventProofCompleted, Fields: []Field{
				BooleanField("success", index%2 == 0),
				TextField("source", fmt.Sprintf("worker-%d", index)),
			}}
			errorsByCall <- telemetry.Track(context.Background(), scope, event)
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	if driver.callCount() != count {
		t.Fatalf("driver calls = %d, want %d", driver.callCount(), count)
	}
	for index := 0; index < count; index++ {
		record := driver.call(index)
		if record.OrganizationID != scope.OrganizationID().String() || record.WorkspaceID != scope.WorkspaceID().String() || record.EnvironmentID != scope.EnvironmentID().String() {
			t.Fatalf("record %d has scope drift: %#v", index, record)
		}
	}
}

func exactEvent(success bool) Event {
	return Event{
		Name: EventProofCompleted,
		Fields: []Field{
			TextField("source", "m1-19"),
			BooleanField("success", success),
		},
	}
}

func expectedRecord(scope domain.Scope, source string, success bool) DriverRecord {
	organizationID := scope.OrganizationID().String()
	return DriverRecord{
		OrganizationID:       organizationID,
		WorkspaceID:          scope.WorkspaceID().String(),
		EnvironmentID:        scope.EnvironmentID().String(),
		DistinctID:           organizationID + ":analytics",
		Event:                string(EventProofCompleted),
		ProcessPersonProfile: false,
		Source:               source,
		Success:              success,
	}
}

func capturedFromRecord(record DriverRecord) DriverCaptured {
	return DriverCaptured{
		OrganizationID:       record.OrganizationID,
		WorkspaceID:          record.WorkspaceID,
		EnvironmentID:        record.EnvironmentID,
		DistinctID:           record.DistinctID,
		Event:                record.Event,
		ProcessPersonProfile: boolPointer(record.ProcessPersonProfile),
		Source:               record.Source,
		Success:              boolPointer(record.Success),
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func mutateCaptured(base DriverCaptured, mutate func(*DriverCaptured)) func(context.Context, DriverRecord) (DriverCaptured, error) {
	return func(context.Context, DriverRecord) (DriverCaptured, error) {
		captured := base
		mutate(&captured)
		return captured, nil
	}
}

func mustTelemetry(t *testing.T, driver Driver, config Config) *Telemetry {
	t.Helper()
	telemetry, err := New(driver, config)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return telemetry
}

func telemetryTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(telemetryTestID(t, 1), telemetryTestID(t, 2), telemetryTestID(t, 3))
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	return scope
}

func telemetryTestID(t *testing.T, suffix byte) domain.ProductID {
	t.Helper()
	text := fmt.Sprintf("pid_00000000-0000-4000-8000-%012x", suffix)
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q) returned error: %v", text, err)
	}
	return id
}
