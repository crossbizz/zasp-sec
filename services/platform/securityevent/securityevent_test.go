package securityevent

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/observability"
)

func TestSecurityEventBuildsExactVersionOneEnvelope(t *testing.T) {
	scope := securityEventTestScope(t)
	evidence := securityEventTestEvidence(t, 4)
	correlation := securityEventTestCorrelation(t, 5)
	eventTime := time.Date(2026, 8, 16, 9, 30, 0, 123*int(time.Millisecond), time.UTC)

	event, err := New(Version1, scope, SourceOTLP, eventTime, evidence, correlation)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	want := SecurityEvent{
		Version: Version1, Scope: scope, Source: SourceOTLP, Time: eventTime,
		Evidence: evidence, Correlation: correlation,
	}
	if event != want {
		t.Fatalf("event = %#v, want %#v", event, want)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestSecurityEventAcceptsOnlyTheInitialSourceCatalog(t *testing.T) {
	for _, source := range []Source{SourceRuntimeGateway, SourceOTLP, SourceTetragon, SourceAttackLab} {
		t.Run(string(source), func(t *testing.T) {
			event, err := New(
				Version1,
				securityEventTestScope(t),
				source,
				time.Date(2026, 8, 16, 9, 30, 0, 123*int(time.Millisecond), time.UTC),
				securityEventTestEvidence(t, 4),
				securityEventTestCorrelation(t, 5),
			)
			if err != nil || event.Source != source {
				t.Fatalf("New = %#v, %v", event, err)
			}
		})
	}
}

func TestSecurityEventRejectsInvalidConstruction(t *testing.T) {
	valid := securityEventTestValue(t)
	monotonicUTC := securityEventMonotonicUTC(t)
	tests := map[string]SecurityEvent{
		"zero":                 {},
		"zero version":         mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Version = 0 }),
		"unknown version":      mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Version = Version(2) }),
		"zero scope":           mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Scope = domain.Scope{} }),
		"zero source":          mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Source = "" }),
		"unknown source":       mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Source = Source("provider_payload") }),
		"zero time":            mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = time.Time{} }),
		"local time":           mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = event.Time.In(time.Local) }),
		"fixed offset time":    mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = event.Time.In(time.FixedZone("offset", 3600)) }),
		"sub millisecond time": mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = event.Time.Add(time.Nanosecond) }),
		"monotonic UTC time":   mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = monotonicUTC }),
		"non four-digit year":  mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }),
		"zero evidence":        mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Evidence = domain.EvidenceRef{} }),
		"zero correlation":     mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Correlation = observability.Correlation{} }),
	}

	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			created, err := New(
				candidate.Version,
				candidate.Scope,
				candidate.Source,
				candidate.Time,
				candidate.Evidence,
				candidate.Correlation,
			)
			if !errors.Is(err, ErrEvent) || created != (SecurityEvent{}) {
				t.Fatalf("New = %#v, %v; want zero, ErrEvent", created, err)
			}
		})
	}
}

func TestSecurityEventRejectsEveryInvalidDirectState(t *testing.T) {
	valid := securityEventTestValue(t)
	tests := map[string]SecurityEvent{
		"zero":        {},
		"version":     mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Version = 9 }),
		"scope":       mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Scope = domain.Scope{} }),
		"source":      mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Source = "raw_customer_event" }),
		"time":        mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Time = time.Time{} }),
		"evidence":    mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Evidence = domain.EvidenceRef{} }),
		"correlation": mutateSecurityEvent(valid, func(event *SecurityEvent) { event.Correlation = observability.Correlation{} }),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if err := candidate.Validate(); !errors.Is(err, ErrEvent) {
				t.Fatalf("Validate error = %v, want ErrEvent", err)
			}
		})
	}
	if ErrEvent.Error() != "security event rejected" {
		t.Fatalf("ErrEvent text = %q", ErrEvent)
	}
}

func TestSecurityEventIsComparableImmutableAndConcurrent(t *testing.T) {
	valid := securityEventTestValue(t)
	if got := map[SecurityEvent]string{valid: "present"}[valid]; got != "present" {
		t.Fatalf("comparable lookup = %q", got)
	}

	const workers = 64
	errorsByWorker := make(chan error, workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			candidate := valid
			if index%2 == 1 {
				candidate.Source = SourceTetragon
			}
			if err := candidate.Validate(); err != nil {
				errorsByWorker <- fmt.Errorf("worker %d: %w", index, err)
				return
			}
			if valid.Source != SourceOTLP {
				errorsByWorker <- fmt.Errorf("worker %d mutated retained event", index)
				return
			}
			errorsByWorker <- nil
		}()
	}
	for range workers {
		if err := <-errorsByWorker; err != nil {
			t.Fatal(err)
		}
	}
}

func securityEventTestValue(t *testing.T) SecurityEvent {
	t.Helper()
	event, err := New(
		Version1,
		securityEventTestScope(t),
		SourceOTLP,
		time.Date(2026, 8, 16, 9, 30, 0, 123*int(time.Millisecond), time.UTC),
		securityEventTestEvidence(t, 4),
		securityEventTestCorrelation(t, 5),
	)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func mutateSecurityEvent(source SecurityEvent, mutate func(*SecurityEvent)) SecurityEvent {
	mutate(&source)
	return source
}

func securityEventMonotonicUTC(t *testing.T) time.Time {
	t.Helper()
	originalLocal := time.Local
	time.Local = time.UTC
	value := time.Now()
	time.Local = originalLocal
	value = value.Add(-time.Duration(value.Nanosecond() % int(time.Millisecond)))
	parsed, err := time.Parse(timestampLayout, value.Format(timestampLayout))
	if err != nil || value.Location() != time.UTC || !value.Equal(parsed) || value == parsed {
		t.Fatalf("monotonic UTC fixture was not retained: value=%#v parsed=%#v err=%v", value, parsed, err)
	}
	return value
}

func securityEventTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		securityEventTestProductID(t, 1),
		securityEventTestProductID(t, 2),
		securityEventTestProductID(t, 3),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func securityEventTestEvidence(t *testing.T, suffix int) domain.EvidenceRef {
	t.Helper()
	evidence, err := domain.NewEvidenceRef(securityEventTestProductID(t, suffix))
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func securityEventTestCorrelation(t *testing.T, suffix int) observability.Correlation {
	t.Helper()
	correlationID, err := domain.NewCorrelationID(securityEventTestProductID(t, suffix))
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := observability.NewCorrelation(
		correlationID,
		"0123456789abcdef0123456789abcdef",
		"0123456789abcdef",
	)
	if err != nil {
		t.Fatal(err)
	}
	return correlation
}

func securityEventTestProductID(t *testing.T, suffix int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID("pid_10000000-0000-4000-8000-00000000000" + string(rune('0'+suffix)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
