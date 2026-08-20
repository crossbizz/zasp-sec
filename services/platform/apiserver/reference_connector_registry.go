package apiserver

import (
	"context"
	"encoding/json"
	"regexp"
)

var (
	awsRoleARNPattern             = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	awsExternalIDReferencePattern = regexp.MustCompile(`^ref:aws/external-id/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	awsRegionPattern              = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]?$`)
	kubernetesReferencePattern    = regexp.MustCompile(`^ref:kubernetes/connection/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
)

type ReferenceAuthorizationTarget struct {
	Provider, IntegrationID, ConnectionReference string
	Configuration                                json.RawMessage
}

type ReferenceAuthorizationProbe interface {
	ProbeReferenceAuthorization(context.Context, ReferenceAuthorizationTarget) error
}

type ReferenceConnectorRegistry struct {
	probes map[string]ReferenceAuthorizationProbe
	checks map[string]ConnectorCapabilityCheck
}

func NewReferenceConnectorRegistry(probes map[string]ReferenceAuthorizationProbe, checks map[string]ConnectorCapabilityCheck) (*ReferenceConnectorRegistry, error) {
	if len(probes) < 1 || len(probes) > 2 || len(checks) != len(probes) {
		return nil, ErrRepositoryConfiguration
	}
	registry := &ReferenceConnectorRegistry{probes: make(map[string]ReferenceAuthorizationProbe, len(probes)), checks: make(map[string]ConnectorCapabilityCheck, len(checks))}
	for _, key := range []string{"aws", "kubernetes"} {
		probe, exists := probes[key]
		check, checked := checks[key]
		if exists != checked || exists && (nilInterface(probe) || check == nil) {
			return nil, ErrRepositoryConfiguration
		}
		if exists {
			registry.probes[key] = probe
			registry.checks[key] = check
		}
	}
	for key := range probes {
		if !stringIn(key, "aws", "kubernetes") {
			return nil, ErrRepositoryConfiguration
		}
	}
	return registry, nil
}

func (registry *ReferenceConnectorRegistry) Probe(ctx context.Context, target ReferenceAuthorizationTarget) error {
	if registry == nil || ctx == nil || ctx.Err() != nil || !validProductID(target.IntegrationID) || !stringIn(target.Provider, "aws", "kubernetes") {
		return ErrRepositoryOperation
	}
	canonical, reference, valid := parseReferenceAuthorizationConfiguration(target.Provider, target.Configuration)
	probe, exists := registry.probes[target.Provider]
	if !valid || reference != target.ConnectionReference || !exists || registry.checks[target.Provider](ctx) != nil {
		return ErrRepositoryUnavailable
	}
	target.Configuration = canonical
	if err := probe.ProbeReferenceAuthorization(ctx, target); err != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (registry *ReferenceConnectorRegistry) ConnectorAvailable(ctx context.Context, key string) bool {
	if registry == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	_, exists := registry.probes[key]
	return exists && registry.checks[key](ctx) == nil
}

func validAWSReferenceConfiguration(roleARN, externalIDReference, region string) bool {
	return awsRoleARNPattern.MatchString(roleARN) && awsExternalIDReferencePattern.MatchString(externalIDReference) && awsRegionPattern.MatchString(region)
}

func validKubernetesConnectionReference(value string) bool {
	return kubernetesReferencePattern.MatchString(value)
}

type CombinedConnectorCapabilities struct {
	OAuth     ConnectorCapabilities
	Reference ConnectorCapabilities
}

func (capabilities CombinedConnectorCapabilities) ConnectorAvailable(ctx context.Context, key string) bool {
	if stringIn(key, "aws", "kubernetes") {
		return !nilInterface(capabilities.Reference) && capabilities.Reference.ConnectorAvailable(ctx, key)
	}
	return !nilInterface(capabilities.OAuth) && capabilities.OAuth.ConnectorAvailable(ctx, key)
}
