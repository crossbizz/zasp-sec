package securityevent

import (
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/observability"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

var ErrEvent = errors.New("security event rejected")

type Version uint8

const Version1 Version = 1

type Source string

const (
	SourceRuntimeGateway Source = "runtime_gateway"
	SourceOTLP           Source = "otlp"
	SourceTetragon       Source = "tetragon"
	SourceAttackLab      Source = "attack_lab"
)

type SecurityEvent struct {
	Version     Version
	Scope       domain.Scope
	Source      Source
	Time        time.Time
	Evidence    domain.EvidenceRef
	Correlation observability.Correlation
}

func New(
	version Version,
	scope domain.Scope,
	source Source,
	eventTime time.Time,
	evidence domain.EvidenceRef,
	correlation observability.Correlation,
) (SecurityEvent, error) {
	event := SecurityEvent{
		Version: version, Scope: scope, Source: source, Time: eventTime,
		Evidence: evidence, Correlation: correlation,
	}
	if event.Validate() != nil {
		return SecurityEvent{}, ErrEvent
	}
	return event, nil
}

func (event SecurityEvent) Validate() error {
	if event.Version != Version1 || event.Scope.Validate() != nil || !validSource(event.Source) ||
		!validTime(event.Time) || event.Evidence.Validate() != nil || event.Correlation.Validate() != nil {
		return ErrEvent
	}
	return nil
}

func validSource(source Source) bool {
	switch source {
	case SourceRuntimeGateway, SourceOTLP, SourceTetragon, SourceAttackLab:
		return true
	default:
		return false
	}
}

func validTime(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	parsed, err := time.Parse(timestampLayout, value.Format(timestampLayout))
	return err == nil && parsed == value
}
