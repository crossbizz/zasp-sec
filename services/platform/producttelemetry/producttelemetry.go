package producttelemetry

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumSourceBytes      = 63
)

var (
	ErrConfiguration = errors.New("product telemetry configuration rejected")
	ErrEvent         = errors.New("product telemetry event rejected")
	ErrCapture       = errors.New("product telemetry capture failed")
)

type Config struct {
	OperationTimeout time.Duration
}

type EventName string

const EventProofCompleted EventName = "proof_completed"

type fieldKind uint8

const (
	fieldText fieldKind = iota + 1
	fieldBoolean
)

type Field struct {
	name    string
	kind    fieldKind
	text    string
	boolean bool
}

func TextField(name, value string) Field {
	return Field{name: name, kind: fieldText, text: value}
}

func BooleanField(name string, value bool) Field {
	return Field{name: name, kind: fieldBoolean, boolean: value}
}

type Event struct {
	Name   EventName
	Fields []Field
}

type DriverRecord struct {
	OrganizationID       string
	WorkspaceID          string
	EnvironmentID        string
	DistinctID           string
	Event                string
	ProcessPersonProfile bool
	Source               string
	Success              bool
}

type DriverCaptured struct {
	OrganizationID       string
	WorkspaceID          string
	EnvironmentID        string
	DistinctID           string
	Event                string
	ProcessPersonProfile bool
	Source               string
	Success              bool
}

type EventSerializer interface {
	Serialize(domain.Scope, Event) (DriverRecord, error)
}

type Driver interface {
	Capture(context.Context, DriverRecord) (DriverCaptured, error)
}

type ProductTelemetry interface {
	Track(context.Context, domain.Scope, Event) error
}

type allowlistSerializer struct{}

func NewAllowlistSerializer() EventSerializer {
	return allowlistSerializer{}
}

func (allowlistSerializer) Serialize(scope domain.Scope, event Event) (DriverRecord, error) {
	if scope.Validate() != nil || event.Name != EventProofCompleted || len(event.Fields) != 2 {
		return DriverRecord{}, ErrEvent
	}

	var source string
	var success bool
	sourceSeen := false
	successSeen := false
	for _, field := range event.Fields {
		switch field.name {
		case "source":
			if sourceSeen || field.kind != fieldText || field.boolean || !validSource(field.text) {
				return DriverRecord{}, ErrEvent
			}
			sourceSeen = true
			source = field.text
		case "success":
			if successSeen || field.kind != fieldBoolean || field.text != "" {
				return DriverRecord{}, ErrEvent
			}
			successSeen = true
			success = field.boolean
		default:
			return DriverRecord{}, ErrEvent
		}
	}
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
	}, nil
}

type Telemetry struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Telemetry, error) {
	if nilInterface(driver) || !validConfig(config) {
		return nil, ErrConfiguration
	}
	return &Telemetry{driver: driver, config: config}, nil
}

func (telemetry *Telemetry) Track(ctx context.Context, scope domain.Scope, event Event) error {
	if telemetry == nil || nilInterface(telemetry.driver) || !validConfig(telemetry.config) {
		return ErrConfiguration
	}
	if ctx == nil {
		return ErrEvent
	}
	record, err := NewAllowlistSerializer().Serialize(scope, event)
	if err != nil {
		return ErrEvent
	}

	operationCtx, cancel := context.WithTimeout(ctx, telemetry.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrCapture
	}
	captured, err := captureDriver(telemetry.driver, operationCtx, record)
	if err != nil || operationCtx.Err() != nil || !exactCapture(record, captured) {
		return ErrCapture
	}
	return nil
}

func validConfig(config Config) bool {
	return config.OperationTimeout > 0 && config.OperationTimeout <= maximumOperationTimeout
}

func validSource(source string) bool {
	if len(source) == 0 || len(source) > maximumSourceBytes || source[0] < 'a' || source[0] > 'z' {
		return false
	}
	separator := false
	for index := 1; index < len(source); index++ {
		character := source[index]
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			separator = false
		case character == '.', character == '_', character == '-':
			if separator || index == len(source)-1 {
				return false
			}
			separator = true
		default:
			return false
		}
	}
	return true
}

func captureDriver(driver Driver, ctx context.Context, record DriverRecord) (captured DriverCaptured, err error) {
	defer func() {
		if recover() != nil {
			captured = DriverCaptured{}
			err = ErrCapture
		}
	}()
	return driver.Capture(ctx, record)
}

func exactCapture(record DriverRecord, captured DriverCaptured) bool {
	return captured.OrganizationID == record.OrganizationID &&
		captured.WorkspaceID == record.WorkspaceID &&
		captured.EnvironmentID == record.EnvironmentID &&
		captured.DistinctID == record.DistinctID &&
		captured.Event == record.Event &&
		captured.ProcessPersonProfile == record.ProcessPersonProfile &&
		captured.Source == record.Source &&
		captured.Success == record.Success
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
