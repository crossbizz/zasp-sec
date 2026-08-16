package health

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestComponentConstructionAndValidation(t *testing.T) {
	lastSuccess := healthTestTime()
	tests := []struct {
		name        string
		requirement Requirement
		status      Status
		reason      string
		lastSuccess time.Time
	}{
		{name: "required-healthy", requirement: RequirementRequired, status: StatusHealthy, lastSuccess: lastSuccess},
		{name: "optional-healthy", requirement: RequirementOptional, status: StatusHealthy, lastSuccess: lastSuccess},
		{name: "required-degraded", requirement: RequirementRequired, status: StatusDegraded, reason: "stale", lastSuccess: lastSuccess},
		{name: "optional-unavailable-never-succeeded", requirement: RequirementOptional, status: StatusUnavailable, reason: "dependency_unreachable"},
		{name: "required-unavailable", requirement: RequirementRequired, status: StatusUnavailable, reason: "dependency_error2", lastSuccess: lastSuccess},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			component, err := NewComponent(test.name, test.requirement, test.status, test.reason, test.lastSuccess)
			if err != nil {
				t.Fatalf("NewComponent returned error: %v", err)
			}
			want := Component{
				Name: test.name, Requirement: test.requirement, Status: test.status,
				Reason: test.reason, LastSuccess: test.lastSuccess,
			}
			if component != want {
				t.Fatalf("component = %#v, want %#v", component, want)
			}
			if err := component.Validate(); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}
		})
	}
}

func TestComponentRejectsInvalidState(t *testing.T) {
	valid := Component{
		Name: "agentsec-api", Requirement: RequirementRequired, Status: StatusHealthy,
		LastSuccess: healthTestTime(),
	}
	monotonicUTC := healthTestMonotonicUTC(t)
	invalid := map[string]Component{
		"zero":                     {},
		"empty name":               mutateComponent(valid, func(value *Component) { value.Name = "" }),
		"uppercase name":           mutateComponent(valid, func(value *Component) { value.Name = "Agentsec" }),
		"double-hyphen name":       mutateComponent(valid, func(value *Component) { value.Name = "agent--sec" }),
		"unknown requirement":      mutateComponent(valid, func(value *Component) { value.Requirement = Requirement("critical") }),
		"zero requirement":         mutateComponent(valid, func(value *Component) { value.Requirement = "" }),
		"unknown status":           mutateComponent(valid, func(value *Component) { value.Status = Status("stale") }),
		"zero status":              mutateComponent(valid, func(value *Component) { value.Status = "" }),
		"healthy reason":           mutateComponent(valid, func(value *Component) { value.Reason = "unexpected" }),
		"healthy zero time":        mutateComponent(valid, func(value *Component) { value.LastSuccess = time.Time{} }),
		"degraded empty reason":    mutateComponent(valid, func(value *Component) { value.Status = StatusDegraded }),
		"unavailable empty reason": mutateComponent(valid, func(value *Component) { value.Status = StatusUnavailable }),
		"reason too long": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, strings.Repeat("a", 65)
		}),
		"reason uppercase": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "Dependency_error"
		}),
		"reason leading underscore": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "_stale"
		}),
		"reason trailing underscore": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "stale_"
		}),
		"reason double underscore": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "dependency__error"
		}),
		"reason hyphen": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "dependency-error"
		}),
		"reason space": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "dependency error"
		}),
		"reason control": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "dependency\nerror"
		}),
		"reason non-ascii": mutateComponent(valid, func(value *Component) {
			value.Status, value.Reason = StatusDegraded, "dépendance"
		}),
		"local time": mutateComponent(valid, func(value *Component) {
			value.LastSuccess = value.LastSuccess.In(time.Local)
		}),
		"fixed-offset time": mutateComponent(valid, func(value *Component) {
			value.LastSuccess = value.LastSuccess.In(time.FixedZone("offset", 3600))
		}),
		"sub-millisecond time": mutateComponent(valid, func(value *Component) {
			value.LastSuccess = value.LastSuccess.Add(time.Nanosecond)
		}),
		"monotonic UTC time": mutateComponent(valid, func(value *Component) {
			value.LastSuccess = monotonicUTC
		}),
		"non-four-digit year": mutateComponent(valid, func(value *Component) {
			value.LastSuccess = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}),
	}

	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidComponent) || err != ErrInvalidComponent {
				t.Fatalf("Validate error = %v, want exact ErrInvalidComponent", err)
			}
			created, err := NewComponent(
				candidate.Name,
				candidate.Requirement,
				candidate.Status,
				candidate.Reason,
				candidate.LastSuccess,
			)
			if created != (Component{}) || !errors.Is(err, ErrInvalidComponent) || err != ErrInvalidComponent {
				t.Fatalf("NewComponent = %#v, %v; want zero, exact ErrInvalidComponent", created, err)
			}
		})
	}

	for _, status := range []Status{StatusDegraded, StatusUnavailable} {
		candidate := valid
		candidate.Status = status
		candidate.Reason = "never_succeeded"
		candidate.LastSuccess = time.Time{}
		if err := candidate.Validate(); err != nil {
			t.Fatalf("%s zero LastSuccess rejected: %v", status, err)
		}
	}

	if ErrInvalidComponent.Error() != "invalid health component" {
		t.Fatalf("ErrInvalidComponent text = %q", ErrInvalidComponent)
	}
}

func TestComponentIsComparableAndConcurrent(t *testing.T) {
	component, err := NewComponent(
		"neon", RequirementRequired, StatusDegraded, "stale", healthTestTime(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := map[Component]string{component: "present"}[component]; got != "present" {
		t.Fatalf("comparable component lookup = %q", got)
	}

	const workers = 32
	const iterations = 200
	errorsChannel := make(chan error, workers*iterations)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				if err := component.Validate(); err != nil {
					errorsChannel <- fmt.Errorf("Validate iteration %d: %w", iteration, err)
				}
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func TestAggregateRequiredOptionalPrecedence(t *testing.T) {
	healthyRequired := mustHealthComponent(t, "neon", RequirementRequired, StatusHealthy, "", healthTestTime())
	healthyOptional := mustHealthComponent(t, "posthog", RequirementOptional, StatusHealthy, "", healthTestTime())
	requiredDegraded := mustHealthComponent(t, "neon", RequirementRequired, StatusDegraded, "stale", healthTestTime())
	optionalDegraded := mustHealthComponent(t, "posthog", RequirementOptional, StatusDegraded, "stale", healthTestTime())
	optionalUnavailable := mustHealthComponent(t, "posthog", RequirementOptional, StatusUnavailable, "dependency_unreachable", healthTestTime())
	requiredUnavailable := mustHealthComponent(t, "neon", RequirementRequired, StatusUnavailable, "dependency_unreachable", healthTestTime())

	tests := []struct {
		name       string
		components []Component
		want       Status
	}{
		{name: "all healthy", components: []Component{healthyRequired, healthyOptional}, want: StatusHealthy},
		{name: "required degraded", components: []Component{requiredDegraded, healthyOptional}, want: StatusDegraded},
		{name: "optional degraded", components: []Component{healthyRequired, optionalDegraded}, want: StatusDegraded},
		{name: "optional unavailable", components: []Component{healthyRequired, optionalUnavailable}, want: StatusDegraded},
		{name: "required unavailable", components: []Component{requiredUnavailable, healthyOptional}, want: StatusUnavailable},
		{name: "required unavailable wins first", components: []Component{requiredUnavailable, optionalDegraded}, want: StatusUnavailable},
		{name: "required unavailable wins last", components: []Component{optionalDegraded, requiredUnavailable}, want: StatusUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Aggregate(test.components)
			if err != nil || got != test.want {
				t.Fatalf("Aggregate = %q, %v; want %q, nil", got, err, test.want)
			}
		})
	}
}

func TestAggregateRejectsInvalidSets(t *testing.T) {
	healthyRequired := mustHealthComponent(t, "neon", RequirementRequired, StatusHealthy, "", healthTestTime())
	healthyOptional := mustHealthComponent(t, "posthog", RequirementOptional, StatusHealthy, "", healthTestTime())
	invalidStatus := healthyRequired
	invalidStatus.Status = "unknown"
	invalidReason := healthyRequired
	invalidReason.Status = StatusDegraded

	tests := map[string][]Component{
		"nil":                   nil,
		"empty":                 {},
		"only optional":         {healthyOptional},
		"duplicate adjacent":    {healthyRequired, healthyRequired},
		"duplicate separated":   {healthyRequired, healthyOptional, healthyRequired},
		"invalid direct status": {invalidStatus},
		"invalid direct reason": {invalidReason},
	}
	for name, components := range tests {
		t.Run(name, func(t *testing.T) {
			status, err := Aggregate(components)
			if status != "" || !errors.Is(err, ErrInvalidAggregation) || err != ErrInvalidAggregation {
				t.Fatalf("Aggregate = %q, %v; want zero, exact ErrInvalidAggregation", status, err)
			}
		})
	}
	if ErrInvalidAggregation.Error() != "invalid health aggregation" {
		t.Fatalf("ErrInvalidAggregation text = %q", ErrInvalidAggregation)
	}
}

func TestAggregateDoesNotMutateInputAndIsConcurrent(t *testing.T) {
	components := []Component{
		mustHealthComponent(t, "neon", RequirementRequired, StatusHealthy, "", healthTestTime()),
		mustHealthComponent(t, "posthog", RequirementOptional, StatusUnavailable, "never_succeeded", time.Time{}),
		mustHealthComponent(t, "runtime-gateway", RequirementRequired, StatusHealthy, "", healthTestTime()),
	}
	original := slices.Clone(components)

	const workers = 32
	const iterations = 200
	errorsChannel := make(chan error, workers*iterations)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				status, err := Aggregate(components)
				if err != nil || status != StatusDegraded {
					errorsChannel <- fmt.Errorf("Aggregate iteration %d = %q, %v", iteration, status, err)
				}
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if !slices.Equal(components, original) {
		t.Fatalf("Aggregate mutated input: got %#v, want %#v", components, original)
	}
}

func healthTestTime() time.Time {
	return time.Date(2026, 8, 16, 15, 0, 0, 123*int(time.Millisecond), time.UTC)
}

func healthTestMonotonicUTC(t *testing.T) time.Time {
	t.Helper()
	originalLocal := time.Local
	time.Local = time.UTC
	value := time.Now()
	time.Local = originalLocal
	value = value.Add(-time.Duration(value.Nanosecond() % int(time.Millisecond)))
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value.Format("2006-01-02T15:04:05.000Z"))
	if err != nil || value.Location() != time.UTC || !value.Equal(parsed) || value == parsed {
		t.Fatalf("monotonic UTC fixture was not retained: value=%#v parsed=%#v err=%v", value, parsed, err)
	}
	return value
}

func mutateComponent(source Component, mutate func(*Component)) Component {
	mutate(&source)
	return source
}

func mustHealthComponent(
	t *testing.T,
	name string,
	requirement Requirement,
	status Status,
	reason string,
	lastSuccess time.Time,
) Component {
	t.Helper()
	component, err := NewComponent(name, requirement, status, reason, lastSuccess)
	if err != nil {
		t.Fatalf("NewComponent(%q) returned error: %v", name, err)
	}
	return component
}
