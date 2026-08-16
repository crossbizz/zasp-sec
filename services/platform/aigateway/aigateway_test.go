package aigateway

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const operationTimeout = 250 * time.Millisecond

type fakeDriver struct {
	mu       sync.Mutex
	requests []DriverRequest
	result   DriverResult
	err      error
	generate func(context.Context, DriverRequest) (DriverResult, error)
}

type valueDriver struct {
	result DriverResult
}

func (driver valueDriver) Generate(context.Context, DriverRequest) (DriverResult, error) {
	return driver.result, nil
}

func (driver *fakeDriver) Generate(ctx context.Context, request DriverRequest) (DriverResult, error) {
	driver.mu.Lock()
	driver.requests = append(driver.requests, request)
	generate := driver.generate
	result := driver.result
	err := driver.err
	driver.mu.Unlock()
	if generate != nil {
		return generate(ctx, request)
	}
	return result, err
}

func (driver *fakeDriver) count() int {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return len(driver.requests)
}

func (driver *fakeDriver) request(index int) DriverRequest {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.requests[index]
}

func TestGatewayGenerateExactContract(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{result: fixture.driverResult}
	gateway, err := New(Config{Driver: driver, OperationTimeout: operationTimeout})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var contract AIGateway = gateway

	result, err := contract.Generate(context.Background(), fixture.scope, fixture.request)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if result != fixture.result {
		t.Fatalf("Generate() result = %#v, want %#v", result, fixture.result)
	}
	if driver.count() != 1 {
		t.Fatalf("driver calls = %d, want 1", driver.count())
	}
	if got := driver.request(0); got != fixture.driverRequest {
		t.Fatalf("driver request = %#v, want %#v", got, fixture.driverRequest)
	}
}

func TestGatewayRejectsUnapprovedPurposeBeforeIO(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Request)
	}{
		{name: "zero", mutate: func(request *Request) { request.Purpose = "" }},
		{name: "security plan", mutate: func(request *Request) { request.Purpose = Purpose("security_plan") }},
		{name: "chat", mutate: func(request *Request) { request.Purpose = Purpose("chat") }},
		{name: "code generation", mutate: func(request *Request) { request.Purpose = Purpose("code_generation") }},
		{name: "case alias", mutate: func(request *Request) { request.Purpose = Purpose("Finding_Explanation") }},
		{name: "policy mismatch", mutate: func(request *Request) { request.DataPolicy.ApprovedPurpose = Purpose("security_plan") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{result: fixture.driverResult}
			gateway := mustGateway(t, driver, operationTimeout)
			request := fixture.request
			test.mutate(&request)
			_, err := gateway.Generate(context.Background(), fixture.scope, request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Generate() error = %v, want ErrInvalidRequest", err)
			}
			if driver.count() != 0 {
				t.Fatalf("driver calls = %d, want 0", driver.count())
			}
		})
	}
}

func TestGatewayRejectsIncompleteDataPolicyBeforeIO(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*DataPolicyMetadata)
	}{
		{name: "zero", mutate: func(policy *DataPolicyMetadata) { *policy = DataPolicyMetadata{} }},
		{name: "missing version", mutate: func(policy *DataPolicyMetadata) { policy.Version = "" }},
		{name: "bad version", mutate: func(policy *DataPolicyMetadata) { policy.Version = "Policy.V1" }},
		{name: "leading digit", mutate: func(policy *DataPolicyMetadata) { policy.Version = "1policy" }},
		{name: "repeated separator", mutate: func(policy *DataPolicyMetadata) { policy.Version = "policy..v1" }},
		{name: "trailing separator", mutate: func(policy *DataPolicyMetadata) { policy.Version = "policy." }},
		{name: "invalid character", mutate: func(policy *DataPolicyMetadata) { policy.Version = "policy/v1" }},
		{name: "oversized version", mutate: func(policy *DataPolicyMetadata) { policy.Version = "p" + strings.Repeat("a", 63) }},
		{name: "unknown content", mutate: func(policy *DataPolicyMetadata) { policy.ContentMode = ContentMode("raw_prompt") }},
		{name: "egress unapproved", mutate: func(policy *DataPolicyMetadata) { policy.EgressApproved = false }},
		{name: "secret present", mutate: func(policy *DataPolicyMetadata) { policy.SecretsExcluded = false }},
		{name: "pii present", mutate: func(policy *DataPolicyMetadata) { policy.PIIExcluded = false }},
		{name: "phi present", mutate: func(policy *DataPolicyMetadata) { policy.PHIExcluded = false }},
		{name: "raw evidence present", mutate: func(policy *DataPolicyMetadata) { policy.RawEvidenceExcluded = false }},
		{name: "unknown retention", mutate: func(policy *DataPolicyMetadata) { policy.RetentionMode = RetentionMode("provider_default") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{result: fixture.driverResult}
			gateway := mustGateway(t, driver, operationTimeout)
			request := fixture.request
			test.mutate(&request.DataPolicy)
			_, err := gateway.Generate(context.Background(), fixture.scope, request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Generate() error = %v, want ErrInvalidRequest", err)
			}
			if driver.count() != 0 {
				t.Fatalf("driver calls = %d, want 0", driver.count())
			}
		})
	}
}

func TestGatewayRejectsMalformedRequestBeforeIO(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, test := range []struct {
		name    string
		ctx     context.Context
		scope   domain.Scope
		request Request
	}{
		{name: "nil context", ctx: nil, scope: fixture.scope, request: fixture.request},
		{name: "zero scope", ctx: context.Background(), request: fixture.request},
		{name: "zero subject", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, fixture.request.RedactedSummary)},
		{name: "empty summary", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, "")},
		{name: "leading whitespace", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, " safe summary")},
		{name: "trailing whitespace", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, "safe summary ")},
		{name: "control", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, "safe\nsummary")},
		{name: "invalid utf8", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, string([]byte{0xff}))},
		{name: "oversized", ctx: context.Background(), scope: fixture.scope, request: withSummary(fixture.request, strings.Repeat("a", 2049))},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{result: fixture.driverResult}
			gateway := mustGateway(t, driver, operationTimeout)
			request := test.request
			if test.name == "zero subject" {
				request.SubjectID = domain.ProductID{}
			}
			_, err := gateway.Generate(test.ctx, test.scope, request)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Generate() error = %v, want ErrInvalidRequest", err)
			}
			if driver.count() != 0 {
				t.Fatalf("driver calls = %d, want 0", driver.count())
			}
		})
	}
}

func TestGatewayConfigurationBoundaries(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, test := range []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "nil driver", config: Config{OperationTimeout: operationTimeout}, wantErr: true},
		{name: "zero timeout", config: Config{Driver: &fakeDriver{result: fixture.driverResult}}, wantErr: true},
		{name: "negative timeout", config: Config{Driver: &fakeDriver{result: fixture.driverResult}, OperationTimeout: -time.Second}, wantErr: true},
		{name: "over maximum", config: Config{Driver: &fakeDriver{result: fixture.driverResult}, OperationTimeout: 30*time.Second + time.Nanosecond}, wantErr: true},
		{name: "maximum", config: Config{Driver: &fakeDriver{result: fixture.driverResult}, OperationTimeout: 30 * time.Second}},
		{name: "value driver", config: Config{Driver: valueDriver{result: fixture.driverResult}, OperationTimeout: operationTimeout}},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway, err := New(test.config)
			if test.wantErr {
				if gateway != nil || !errors.Is(err, ErrInvalidConfiguration) {
					t.Fatalf("New() = (%#v, %v), want nil ErrInvalidConfiguration", gateway, err)
				}
				return
			}
			if gateway == nil || err != nil {
				t.Fatalf("New() = (%#v, %v), want gateway nil", gateway, err)
			}
		})
	}

	var gateway *Gateway
	_, err := gateway.Generate(context.Background(), fixture.scope, fixture.request)
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil Gateway.Generate() error = %v, want ErrInvalidConfiguration", err)
	}
	var typedNil *fakeDriver
	gateway, err = New(Config{Driver: typedNil, OperationTimeout: operationTimeout})
	if gateway != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed-nil New() = (%#v, %v), want nil ErrInvalidConfiguration", gateway, err)
	}
}

func TestGatewayContainsDriverFailuresAndValidatesResult(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, test := range []struct {
		name   string
		result DriverResult
		err    error
		panic  bool
	}{
		{name: "driver error", result: fixture.driverResult, err: errors.New("sensitive provider error")},
		{name: "driver panic", result: fixture.driverResult, panic: true},
		{name: "zero result"},
		{name: "purpose drift", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Purpose = Purpose("security_plan") })},
		{name: "subject drift", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.SubjectID = fixture.otherID })},
		{name: "schema drift", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.SchemaVersion = "2" })},
		{name: "empty explanation", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Explanation = "" })},
		{name: "oversized explanation", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Explanation = strings.Repeat("a", 2049) })},
		{name: "control explanation", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Explanation = "unsafe\ntext" })},
		{name: "empty recommendation", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Recommendation = "" })},
		{name: "whitespace recommendation", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.Recommendation = " review" })},
		{name: "policy drift", result: mutateResult(fixture.driverResult, func(result *DriverResult) { result.DataPolicyVersion = "policy.v2" })},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &fakeDriver{result: test.result, err: test.err}
			if test.panic {
				driver.generate = func(context.Context, DriverRequest) (DriverResult, error) { panic("sensitive panic") }
			}
			gateway := mustGateway(t, driver, operationTimeout)
			result, err := gateway.Generate(context.Background(), fixture.scope, fixture.request)
			if result != (Result{}) || !errors.Is(err, ErrGeneration) {
				t.Fatalf("Generate() = (%#v, %v), want zero ErrGeneration", result, err)
			}
			if err.Error() != ErrGeneration.Error() {
				t.Fatalf("error text = %q, want fixed %q", err, ErrGeneration)
			}
			if driver.count() != 1 {
				t.Fatalf("driver calls = %d, want 1", driver.count())
			}
		})
	}
}

func TestGatewayCancellationAndTimeoutAreOneAttempt(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	driver := &fakeDriver{result: fixture.driverResult}
	_, err := mustGateway(t, driver, operationTimeout).Generate(canceled, fixture.scope, fixture.request)
	if !errors.Is(err, ErrGeneration) || driver.count() != 0 {
		t.Fatalf("canceled Generate() = (%v, calls=%d), want ErrGeneration and zero calls", err, driver.count())
	}

	timedDriver := &fakeDriver{generate: func(ctx context.Context, _ DriverRequest) (DriverResult, error) {
		<-ctx.Done()
		return DriverResult{}, ctx.Err()
	}}
	_, err = mustGateway(t, timedDriver, time.Millisecond).Generate(context.Background(), fixture.scope, fixture.request)
	if !errors.Is(err, ErrGeneration) || timedDriver.count() != 1 {
		t.Fatalf("timed Generate() = (%v, calls=%d), want ErrGeneration and one call", err, timedDriver.count())
	}
}

func TestGatewayConcurrentCallsAreIndependent(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	driver := &fakeDriver{generate: func(_ context.Context, request DriverRequest) (DriverResult, error) {
		return DriverResult{
			Purpose:           request.Purpose,
			SubjectID:         request.SubjectID,
			SchemaVersion:     "1",
			Explanation:       "Bounded product explanation.",
			Recommendation:    "Review the scoped finding.",
			DataPolicyVersion: request.DataPolicy.Version,
		}, nil
	}}
	gateway := mustGateway(t, driver, operationTimeout)

	const calls = 32
	start := make(chan struct{})
	errorsByCall := make(chan error, calls)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := gateway.Generate(context.Background(), fixture.scope, fixture.request)
			if err == nil && result != fixture.result {
				err = errors.New("result drift")
			}
			errorsByCall <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent Generate() error = %v", err)
		}
	}
	if driver.count() != calls {
		t.Fatalf("driver calls = %d, want %d", driver.count(), calls)
	}
}

type fixture struct {
	scope         domain.Scope
	request       Request
	driverRequest DriverRequest
	driverResult  DriverResult
	result        Result
	otherID       domain.ProductID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	organizationID := mustProductID(t, "pid_11111111-1111-4111-8111-111111111111")
	workspaceID := mustProductID(t, "pid_22222222-2222-4222-8222-222222222222")
	environmentID := mustProductID(t, "pid_33333333-3333-4333-8333-333333333333")
	subjectID := mustProductID(t, "pid_44444444-4444-4444-8444-444444444444")
	otherID := mustProductID(t, "pid_55555555-5555-4555-8555-555555555555")
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	policy := DataPolicyMetadata{
		Version:             "policy.v1",
		ApprovedPurpose:     PurposeFindingExplanation,
		ContentMode:         ContentModeRedactedSummary,
		EgressApproved:      true,
		SecretsExcluded:     true,
		PIIExcluded:         true,
		PHIExcluded:         true,
		RawEvidenceExcluded: true,
		RetentionMode:       RetentionModeNoProviderStorage,
	}
	request := Request{
		Purpose:         PurposeFindingExplanation,
		SubjectID:       subjectID,
		RedactedSummary: "A bounded product-generated finding summary.",
		DataPolicy:      policy,
	}
	driverRequest := DriverRequest{
		OrganizationID:  organizationID,
		WorkspaceID:     workspaceID,
		EnvironmentID:   environmentID,
		Purpose:         PurposeFindingExplanation,
		SubjectID:       subjectID,
		RedactedSummary: request.RedactedSummary,
		DataPolicy:      policy,
	}
	driverResult := DriverResult{
		Purpose:           PurposeFindingExplanation,
		SubjectID:         subjectID,
		SchemaVersion:     "1",
		Explanation:       "Bounded product explanation.",
		Recommendation:    "Review the scoped finding.",
		DataPolicyVersion: policy.Version,
	}
	return fixture{
		scope:         scope,
		request:       request,
		driverRequest: driverRequest,
		driverResult:  driverResult,
		result: Result{
			Purpose:           driverResult.Purpose,
			SubjectID:         driverResult.SubjectID,
			SchemaVersion:     driverResult.SchemaVersion,
			Explanation:       driverResult.Explanation,
			Recommendation:    driverResult.Recommendation,
			DataPolicyVersion: driverResult.DataPolicyVersion,
		},
		otherID: otherID,
	}
}

func mustGateway(t *testing.T, driver Driver, timeout time.Duration) *Gateway {
	t.Helper()
	gateway, err := New(Config{Driver: driver, OperationTimeout: timeout})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return gateway
}

func mustProductID(t *testing.T, text string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q) error = %v", text, err)
	}
	return id
}

func withSummary(request Request, summary string) Request {
	request.RedactedSummary = summary
	return request
}

func mutateResult(result DriverResult, mutate func(*DriverResult)) DriverResult {
	mutate(&result)
	return result
}
