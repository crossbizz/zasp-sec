package health

import (
	"errors"
	"time"
)

const componentTimestampLayout = "2006-01-02T15:04:05.000Z"

var ErrInvalidComponent = errors.New("invalid health component")
var ErrInvalidAggregation = errors.New("invalid health aggregation")

type Status string

const (
	StatusHealthy     Status = "healthy"
	StatusDegraded    Status = "degraded"
	StatusUnavailable Status = "unavailable"
)

type Requirement string

const (
	RequirementRequired Requirement = "required"
	RequirementOptional Requirement = "optional"
)

type Component struct {
	Name        string
	Requirement Requirement
	Status      Status
	Reason      string
	LastSuccess time.Time
}

func NewComponent(
	name string,
	requirement Requirement,
	status Status,
	reason string,
	lastSuccess time.Time,
) (Component, error) {
	component := Component{
		Name:        name,
		Requirement: requirement,
		Status:      status,
		Reason:      reason,
		LastSuccess: lastSuccess,
	}
	if component.Validate() != nil {
		return Component{}, ErrInvalidComponent
	}
	return component, nil
}

func (component Component) Validate() error {
	if !validService(component.Name) || !validRequirement(component.Requirement) || !validStatus(component.Status) {
		return ErrInvalidComponent
	}
	if component.Status == StatusHealthy {
		if component.Reason != "" || !validComponentTime(component.LastSuccess) {
			return ErrInvalidComponent
		}
		return nil
	}
	if !validReason(component.Reason) || !component.LastSuccess.IsZero() && !validComponentTime(component.LastSuccess) {
		return ErrInvalidComponent
	}
	return nil
}

func Aggregate(components []Component) (Status, error) {
	if len(components) == 0 {
		return "", ErrInvalidAggregation
	}

	names := make(map[string]struct{}, len(components))
	hasRequired := false
	hasRequiredUnavailable := false
	hasNonhealthy := false
	for _, component := range components {
		if component.Validate() != nil {
			return "", ErrInvalidAggregation
		}
		if _, exists := names[component.Name]; exists {
			return "", ErrInvalidAggregation
		}
		names[component.Name] = struct{}{}
		if component.Requirement == RequirementRequired {
			hasRequired = true
			if component.Status == StatusUnavailable {
				hasRequiredUnavailable = true
			}
		}
		if component.Status != StatusHealthy {
			hasNonhealthy = true
		}
	}
	if !hasRequired {
		return "", ErrInvalidAggregation
	}
	if hasRequiredUnavailable {
		return StatusUnavailable, nil
	}
	if hasNonhealthy {
		return StatusDegraded, nil
	}
	return StatusHealthy, nil
}

func validRequirement(requirement Requirement) bool {
	switch requirement {
	case RequirementRequired, RequirementOptional:
		return true
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case StatusHealthy, StatusDegraded, StatusUnavailable:
		return true
	default:
		return false
	}
}

func validReason(reason string) bool {
	if len(reason) == 0 || len(reason) > 64 || reason[0] == '_' || reason[len(reason)-1] == '_' {
		return false
	}
	previousUnderscore := false
	for index := 0; index < len(reason); index++ {
		character := reason[index]
		if character == '_' {
			if previousUnderscore {
				return false
			}
			previousUnderscore = true
			continue
		}
		if !asciiLowerAlphanumeric(character) {
			return false
		}
		previousUnderscore = false
	}
	return true
}

func validComponentTime(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	parsed, err := time.Parse(componentTimestampLayout, value.Format(componentTimestampLayout))
	return err == nil && parsed == value
}
