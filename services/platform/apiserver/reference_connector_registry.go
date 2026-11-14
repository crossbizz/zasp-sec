package apiserver

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	awsRoleARNPattern             = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	awsExternalIDReferencePattern = regexp.MustCompile(`^ref:aws/external-id/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	awsRegionPattern              = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]?$`)
	kubernetesReferencePattern    = regexp.MustCompile(`^ref:kubernetes/connection/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	awsReferenceSubjectPattern    = regexp.MustCompile(`^[0-9]{12}$`)
	kubernetesSubjectPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}/[a-z0-9][a-z0-9._-]{0,127}$`)
	// Microsoft and Salesforce name one customer-supplied client secret by
	// reference, the way AWS names its external id.
	microsoftTenantPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	microsoftSecretReferencePattern  = regexp.MustCompile(`^ref:microsoft/client-secret/[a-z0-9][a-z0-9._-]{7,127}$`)
	microsoftDataverseURLPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}\.crm[0-9]{0,2}\.dynamics\.com$`)
	salesforceInstanceURLPattern     = regexp.MustCompile(`^https://[a-z0-9][a-z0-9-]{0,62}(\.[a-z0-9][a-z0-9-]{0,62}){0,3}\.my\.salesforce\.com$`)
	salesforceOrganizationPattern    = regexp.MustCompile(`^00D[A-Za-z0-9]{15}$`)
	salesforceClientIDPattern        = regexp.MustCompile(`^[!-~]{16,256}$`)
	salesforceSecretReferencePattern = regexp.MustCompile(`^ref:salesforce/client-secret/[a-z0-9][a-z0-9._-]{7,127}$`)
	// The generic saas provider names a Nango connection by reference. Its
	// subject is "<platform>/<tenant id>"; which platforms exist is decided
	// by the platform registry the probe and the catalog read, not here.
	saasPlatformPattern            = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
	saasTenantPattern              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,94}$`)
	saasSubjectPattern             = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}/[A-Za-z0-9][A-Za-z0-9._-]{0,94}$`)
	saasConnectionReferencePattern = regexp.MustCompile(`^ref:nango/connection/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// referenceAuthorizedProviders are authorized by a reference to customer
// material held outside the product database, not by a browser OAuth flow.
var referenceAuthorizedProviders = []string{"aws", "kubernetes", "microsoft", "salesforce", "saas"}

func isReferenceAuthorizedProvider(value string) bool {
	return stringIn(value, referenceAuthorizedProviders...)
}

// isDiscoveryProvider reports whether value is a provider discovery collects
// from. aws, kubernetes, github and okta are served by every deployment;
// microsoft, salesforce and saas (every SaaS platform read through the Nango
// proxy) where their collector is configured.
func isDiscoveryProvider(value string) bool {
	return stringIn(value, "aws", "kubernetes", "github", "okta", "microsoft", "salesforce", "saas")
}

type ReferenceAuthorizationTarget struct {
	Provider, IntegrationID, ConnectionReference string
	Configuration                                json.RawMessage
}

type ReferenceAuthorizationSubject struct {
	Kind string
	ID   string
}

type ReferenceAuthorizationProbe interface {
	ProbeReferenceAuthorization(context.Context, ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error)
}

type ReferenceConnectorRegistry struct {
	probes map[string]ReferenceAuthorizationProbe
	checks map[string]ConnectorCapabilityCheck
}

func NewReferenceConnectorRegistry(probes map[string]ReferenceAuthorizationProbe, checks map[string]ConnectorCapabilityCheck) (*ReferenceConnectorRegistry, error) {
	if len(probes) < 1 || len(probes) > len(referenceAuthorizedProviders) || len(checks) != len(probes) {
		return nil, ErrRepositoryConfiguration
	}
	registry := &ReferenceConnectorRegistry{probes: make(map[string]ReferenceAuthorizationProbe, len(probes)), checks: make(map[string]ConnectorCapabilityCheck, len(checks))}
	for _, key := range referenceAuthorizedProviders {
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
		if !isReferenceAuthorizedProvider(key) {
			return nil, ErrRepositoryConfiguration
		}
	}
	return registry, nil
}

func (registry *ReferenceConnectorRegistry) Probe(ctx context.Context, target ReferenceAuthorizationTarget) (ReferenceAuthorizationSubject, error) {
	if registry == nil || ctx == nil || ctx.Err() != nil || !validProductID(target.IntegrationID) || !isReferenceAuthorizedProvider(target.Provider) {
		return ReferenceAuthorizationSubject{}, ErrRepositoryOperation
	}
	canonical, reference, valid := parseReferenceAuthorizationConfiguration(target.Provider, target.Configuration)
	probe, exists := registry.probes[target.Provider]
	if !valid || reference != target.ConnectionReference || !exists || registry.checks[target.Provider](ctx) != nil {
		return ReferenceAuthorizationSubject{}, ErrRepositoryUnavailable
	}
	target.Configuration = canonical
	subject, err := probe.ProbeReferenceAuthorization(ctx, target)
	if err != nil || !validReferenceAuthorizationSubject(target.Provider, subject) {
		return ReferenceAuthorizationSubject{}, ErrRepositoryUnavailable
	}
	return subject, nil
}

func validReferenceAuthorizationSubject(provider string, subject ReferenceAuthorizationSubject) bool {
	switch provider {
	case "aws":
		return subject.Kind == "aws_account" && awsReferenceSubjectPattern.MatchString(subject.ID)
	case "kubernetes":
		return subject.Kind == "kubernetes_cluster" && kubernetesSubjectPattern.MatchString(subject.ID) && !strings.Contains(subject.ID, "..")
	case "microsoft":
		return subject.Kind == "microsoft_tenant" && microsoftTenantPattern.MatchString(subject.ID)
	case "salesforce":
		return subject.Kind == "salesforce_org" && salesforceOrganizationPattern.MatchString(subject.ID)
	case "saas":
		return subject.Kind == "saas_tenant" && saasSubjectPattern.MatchString(subject.ID) && !strings.Contains(subject.ID, "..")
	default:
		return false
	}
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

func validMicrosoftReferenceConfiguration(tenantID, clientID, clientSecretReference, dataverseURL string) bool {
	return microsoftTenantPattern.MatchString(tenantID) && microsoftTenantPattern.MatchString(clientID) && microsoftSecretReferencePattern.MatchString(clientSecretReference) &&
		(dataverseURL == "" || microsoftDataverseURLPattern.MatchString(dataverseURL))
}

func validSalesforceReferenceConfiguration(instanceURL, organizationID, clientID, clientSecretReference string) bool {
	return salesforceInstanceURLPattern.MatchString(instanceURL) && salesforceOrganizationPattern.MatchString(organizationID) && salesforceClientIDPattern.MatchString(clientID) && salesforceSecretReferencePattern.MatchString(clientSecretReference)
}

func validSaaSReferenceConfiguration(platform, tenantID, connectionReference string) bool {
	return saasPlatformPattern.MatchString(platform) && saasTenantPattern.MatchString(tenantID) && !strings.Contains(tenantID, "..") && saasConnectionReferencePattern.MatchString(connectionReference)
}

type CombinedConnectorCapabilities struct {
	OAuth     ConnectorCapabilities
	Reference ConnectorCapabilities
}

func (capabilities CombinedConnectorCapabilities) ConnectorAvailable(ctx context.Context, key string) bool {
	if isReferenceAuthorizedProvider(key) {
		return !nilInterface(capabilities.Reference) && capabilities.Reference.ConnectorAvailable(ctx, key)
	}
	return !nilInterface(capabilities.OAuth) && capabilities.OAuth.ConnectorAvailable(ctx, key)
}
