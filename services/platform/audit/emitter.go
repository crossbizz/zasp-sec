package audit

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumActionBytes      = 127
)

var (
	ErrConfiguration = errors.New("audit emitter configuration rejected")
	ErrMutation      = errors.New("audit mutation rejected")
	ErrEmit          = errors.New("audit emission failed")
)

type Config struct {
	OperationTimeout time.Duration
}

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeDenied    Outcome = "denied"
)

type Mutation struct {
	Actor   domain.ProductID
	Action  string
	Target  domain.ProductID
	Outcome Outcome
}

type DriverMutation struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	Actor          string
	Action         string
	Target         string
	Outcome        string
}

type DriverAppended struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	Actor          string
	Action         string
	Target         string
	Outcome        string
}

type Driver interface {
	Append(context.Context, DriverMutation) (DriverAppended, error)
}

type AuditEmitter interface {
	Emit(context.Context, domain.Scope, Mutation) error
}

type Emitter struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Emitter, error) {
	if nilInterface(driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout {
		return nil, ErrConfiguration
	}
	return &Emitter{driver: driver, config: config}, nil
}

func (emitter *Emitter) Emit(ctx context.Context, scope domain.Scope, mutation Mutation) error {
	if emitter == nil || nilInterface(emitter.driver) || ctx == nil {
		return ErrEmit
	}
	if scope.Validate() != nil || !validMutation(mutation) {
		return ErrMutation
	}
	record := DriverMutation{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		Actor:          mutation.Actor.String(),
		Action:         mutation.Action,
		Target:         mutation.Target.String(),
		Outcome:        string(mutation.Outcome),
	}
	operationCtx, cancel := context.WithTimeout(ctx, emitter.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrEmit
	}
	acknowledged, err := appendDriver(emitter.driver, operationCtx, record)
	if err != nil || operationCtx.Err() != nil || !exactAcknowledgement(record, acknowledged) {
		return ErrEmit
	}
	return nil
}

func validMutation(mutation Mutation) bool {
	return mutation.Actor.String() != "" && validAction(mutation.Action) &&
		mutation.Target.String() != "" && validOutcome(mutation.Outcome)
}

func validAction(action string) bool {
	if len(action) == 0 || len(action) > maximumActionBytes || action[0] < 'a' || action[0] > 'z' {
		return false
	}
	separator := false
	for index := 1; index < len(action); index++ {
		character := action[index]
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			separator = false
		case character == '.', character == '_', character == '-':
			if separator || index == len(action)-1 {
				return false
			}
			separator = true
		default:
			return false
		}
	}
	return true
}

func validOutcome(outcome Outcome) bool {
	switch outcome {
	case OutcomeSucceeded, OutcomeFailed, OutcomeDenied:
		return true
	default:
		return false
	}
}

func appendDriver(driver Driver, ctx context.Context, mutation DriverMutation) (appended DriverAppended, err error) {
	defer func() {
		if recover() != nil {
			appended = DriverAppended{}
			err = ErrEmit
		}
	}()
	return driver.Append(ctx, mutation)
}

func exactAcknowledgement(mutation DriverMutation, appended DriverAppended) bool {
	return appended.OrganizationID == mutation.OrganizationID &&
		appended.WorkspaceID == mutation.WorkspaceID &&
		appended.EnvironmentID == mutation.EnvironmentID &&
		appended.Actor == mutation.Actor &&
		appended.Action == mutation.Action &&
		appended.Target == mutation.Target &&
		appended.Outcome == mutation.Outcome
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
