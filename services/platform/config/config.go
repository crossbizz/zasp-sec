package config

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	KeyStytchProjectID       = "AGENTSEC_STYTCH_PROJECT_ID"
	KeyStytchSecretRef       = "AGENTSEC_STYTCH_SECRET_REF"
	KeyNeonDSNSecretRef      = "AGENTSEC_NEON_DSN_SECRET_REF"
	KeyAWSRegion             = "AGENTSEC_AWS_REGION"
	KeyOTelCollectorEndpoint = "AGENTSEC_OTEL_COLLECTOR_ENDPOINT"
	KeyPostHogEndpoint       = "AGENTSEC_POSTHOG_ENDPOINT"
	KeyPostHogSecretRef      = "AGENTSEC_POSTHOG_SECRET_REF"
	KeyOpenRouterEndpoint    = "AGENTSEC_OPENROUTER_ENDPOINT"
	KeyOpenRouterSecretRef   = "AGENTSEC_OPENROUTER_SECRET_REF"
	KeyRemoteOTLPEndpoint    = "AGENTSEC_REMOTE_OTLP_ENDPOINT"
	KeyRemoteOTLPSecretRef   = "AGENTSEC_REMOTE_OTLP_SECRET_REF"
)

var (
	ErrInvalidSource                = errors.New("invalid configuration source")
	ErrMissingRequiredConfiguration = errors.New("missing required configuration")
	ErrPartialOptionalConfiguration = errors.New("partial optional configuration")
	ErrInvalidConfiguration         = errors.New("invalid configuration")
)

var allKeys = [...]string{
	KeyStytchProjectID,
	KeyStytchSecretRef,
	KeyNeonDSNSecretRef,
	KeyAWSRegion,
	KeyOTelCollectorEndpoint,
	KeyPostHogEndpoint,
	KeyPostHogSecretRef,
	KeyOpenRouterEndpoint,
	KeyOpenRouterSecretRef,
	KeyRemoteOTLPEndpoint,
	KeyRemoteOTLPSecretRef,
}

type StytchProjectID struct {
	value string
}

func ParseStytchProjectID(value string) (StytchProjectID, error) {
	parsed := StytchProjectID{value: value}
	if !parsed.valid() {
		return StytchProjectID{}, ErrInvalidConfiguration
	}
	return parsed, nil
}

func (value StytchProjectID) String() string {
	if !value.valid() {
		return ""
	}
	return value.value
}

func (value StytchProjectID) valid() bool {
	if len(value.value) == 0 || len(value.value) > 128 || !utf8.ValidString(value.value) {
		return false
	}
	for index := 0; index < len(value.value); index++ {
		character := value.value[index]
		alphanumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !alphanumeric && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return asciiAlphanumeric(value.value[0]) && asciiAlphanumeric(value.value[len(value.value)-1])
}

type AWSRegion struct {
	value string
}

func ParseAWSRegion(value string) (AWSRegion, error) {
	parsed := AWSRegion{value: value}
	if !parsed.valid() {
		return AWSRegion{}, ErrInvalidConfiguration
	}
	return parsed, nil
}

func (value AWSRegion) String() string {
	if !value.valid() {
		return ""
	}
	return value.value
}

func (value AWSRegion) valid() bool {
	if len(value.value) < 5 || len(value.value) > 32 || strings.Count(value.value, "-") < 2 {
		return false
	}
	if value.value[0] < 'a' || value.value[0] > 'z' || value.value[len(value.value)-1] < '0' || value.value[len(value.value)-1] > '9' {
		return false
	}
	previousHyphen := false
	for index := 0; index < len(value.value); index++ {
		character := value.value[index]
		if character == '-' {
			if previousHyphen {
				return false
			}
			previousHyphen = true
			continue
		}
		previousHyphen = false
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

type SecretReference struct {
	value string
}

func ParseSecretReference(value string) (SecretReference, error) {
	parsed := SecretReference{value: value}
	if !parsed.valid() {
		return SecretReference{}, ErrInvalidConfiguration
	}
	return parsed, nil
}

func (value SecretReference) String() string {
	if !value.valid() {
		return ""
	}
	return value.value
}

func (value SecretReference) valid() bool {
	if len(value.value) == 0 || len(value.value) > 768 || !utf8.ValidString(value.value) {
		return false
	}
	parts := strings.SplitN(value.value, ":", 7)
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "secretsmanager" || parts[5] != "secret" {
		return false
	}
	if parts[1] != "aws" && parts[1] != "aws-us-gov" && parts[1] != "aws-cn" {
		return false
	}
	if !(AWSRegion{value: parts[3]}).valid() || !validPartitionRegion(parts[1], parts[3]) || len(parts[4]) != 12 || !asciiDigits(parts[4]) {
		return false
	}
	if len(parts[6]) == 0 || len(parts[6]) > 512 {
		return false
	}
	for index := 0; index < len(parts[6]); index++ {
		character := parts[6][index]
		if asciiAlphanumeric(character) || strings.ContainsRune("/_+=.@-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

type DependencyEndpoint struct {
	value string
}

func ParseDependencyEndpoint(value string) (DependencyEndpoint, error) {
	parsed := DependencyEndpoint{value: value}
	if !parsed.valid() {
		return DependencyEndpoint{}, ErrInvalidConfiguration
	}
	return parsed, nil
}

func (value DependencyEndpoint) String() string {
	if !value.valid() {
		return ""
	}
	return value.value
}

func (value DependencyEndpoint) valid() bool {
	if len(value.value) == 0 || len(value.value) > 2048 || !utf8.ValidString(value.value) || strings.TrimSpace(value.value) != value.value {
		return false
	}
	parsed, err := url.ParseRequestURI(value.value)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || strings.ToLower(parsed.Host) != parsed.Host {
		return false
	}
	if strings.Contains(parsed.EscapedPath(), "%") {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || !validEndpointHostname(hostname) {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, conversionError := strconv.Atoi(port)
		if conversionError != nil || number < 1 || number > 65535 {
			return false
		}
	}
	for _, segment := range strings.Split(parsed.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return parsed.String() == value.value
}

func (value DependencyEndpoint) secure() bool {
	return value.valid() && strings.HasPrefix(value.value, "https://")
}

func (value DependencyEndpoint) secureOrInternal() bool {
	if !value.valid() {
		return false
	}
	parsed, err := url.ParseRequestURI(value.value)
	if err != nil || parsed.Scheme == "https" {
		return err == nil
	}
	hostname := parsed.Hostname()
	if address := net.ParseIP(hostname); address != nil {
		return address.IsLoopback() || address.IsPrivate()
	}
	return hostname == "localhost" ||
		strings.HasSuffix(hostname, ".localhost") ||
		!strings.Contains(hostname, ".") ||
		strings.HasSuffix(hostname, ".svc") ||
		strings.HasSuffix(hostname, ".svc.cluster.local")
}

type RequiredDependencies struct {
	stytchProjectID       StytchProjectID
	stytchSecretReference SecretReference
	neonDSNReference      SecretReference
	awsRegion             AWSRegion
	otelCollectorEndpoint DependencyEndpoint
}

func (dependencies RequiredDependencies) StytchProjectID() StytchProjectID {
	return dependencies.stytchProjectID
}

func (dependencies RequiredDependencies) StytchSecretReference() SecretReference {
	return dependencies.stytchSecretReference
}

func (dependencies RequiredDependencies) NeonDSNReference() SecretReference {
	return dependencies.neonDSNReference
}

func (dependencies RequiredDependencies) AWSRegion() AWSRegion {
	return dependencies.awsRegion
}

func (dependencies RequiredDependencies) OTelCollectorEndpoint() DependencyEndpoint {
	return dependencies.otelCollectorEndpoint
}

func (dependencies RequiredDependencies) valid() bool {
	return dependencies.stytchProjectID.valid() &&
		dependencies.stytchSecretReference.valid() &&
		dependencies.neonDSNReference.valid() &&
		dependencies.awsRegion.valid() &&
		dependencies.otelCollectorEndpoint.valid()
}

type OptionalDependency struct {
	endpoint           DependencyEndpoint
	secretReference    SecretReference
	hasSecretReference bool
}

func (dependency OptionalDependency) Endpoint() DependencyEndpoint {
	return dependency.endpoint
}

func (dependency OptionalDependency) SecretReference() (SecretReference, bool) {
	if !dependency.hasSecretReference || !dependency.secretReference.valid() {
		return SecretReference{}, false
	}
	return dependency.secretReference, true
}

func (dependency OptionalDependency) valid() bool {
	if !dependency.endpoint.valid() {
		return false
	}
	if dependency.hasSecretReference {
		return dependency.secretReference.valid()
	}
	return dependency.secretReference == (SecretReference{})
}

type OptionalDependencies struct {
	postHog       OptionalDependency
	hasPostHog    bool
	openRouter    OptionalDependency
	hasOpenRouter bool
	remoteOTLP    OptionalDependency
	hasRemoteOTLP bool
}

func (dependencies OptionalDependencies) PostHog() (OptionalDependency, bool) {
	return dependencies.optional(dependencies.postHog, dependencies.hasPostHog)
}

func (dependencies OptionalDependencies) OpenRouter() (OptionalDependency, bool) {
	return dependencies.optional(dependencies.openRouter, dependencies.hasOpenRouter)
}

func (dependencies OptionalDependencies) RemoteOTLP() (OptionalDependency, bool) {
	return dependencies.optional(dependencies.remoteOTLP, dependencies.hasRemoteOTLP)
}

func (dependencies OptionalDependencies) optional(value OptionalDependency, present bool) (OptionalDependency, bool) {
	if !present || !value.valid() {
		return OptionalDependency{}, false
	}
	return value, true
}

func (dependencies OptionalDependencies) valid() bool {
	return validOptional(dependencies.postHog, dependencies.hasPostHog) &&
		validOptional(dependencies.openRouter, dependencies.hasOpenRouter) &&
		validOptional(dependencies.remoteOTLP, dependencies.hasRemoteOTLP)
}

type Config struct {
	required RequiredDependencies
	optional OptionalDependencies
}

func Load(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, ErrInvalidSource
	}
	values := make(map[string]string, len(allKeys))
	present := make(map[string]bool, len(allKeys))
	for _, key := range allKeys {
		values[key], present[key] = lookup(key)
	}
	for _, key := range allKeys[:5] {
		if !present[key] || values[key] == "" {
			return Config{}, ErrMissingRequiredConfiguration
		}
	}

	stytchProjectID, err := ParseStytchProjectID(values[KeyStytchProjectID])
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	stytchSecretReference, err := ParseSecretReference(values[KeyStytchSecretRef])
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	neonDSNReference, err := ParseSecretReference(values[KeyNeonDSNSecretRef])
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	awsRegion, err := ParseAWSRegion(values[KeyAWSRegion])
	if err != nil {
		return Config{}, ErrInvalidConfiguration
	}
	otelCollectorEndpoint, err := ParseDependencyEndpoint(values[KeyOTelCollectorEndpoint])
	if err != nil || !otelCollectorEndpoint.secureOrInternal() {
		return Config{}, ErrInvalidConfiguration
	}

	optional, err := loadOptional(values, present)
	if err != nil {
		return Config{}, err
	}
	loaded := Config{
		required: RequiredDependencies{
			stytchProjectID:       stytchProjectID,
			stytchSecretReference: stytchSecretReference,
			neonDSNReference:      neonDSNReference,
			awsRegion:             awsRegion,
			otelCollectorEndpoint: otelCollectorEndpoint,
		},
		optional: optional,
	}
	if err := loaded.Validate(); err != nil {
		return Config{}, err
	}
	return loaded, nil
}

func (configuration Config) Required() RequiredDependencies {
	return configuration.required
}

func (configuration Config) Optional() OptionalDependencies {
	return configuration.optional
}

func (configuration Config) Validate() error {
	if !configuration.required.valid() || !configuration.optional.valid() {
		return ErrInvalidConfiguration
	}
	return nil
}

func loadOptional(values map[string]string, present map[string]bool) (OptionalDependencies, error) {
	postHog, hasPostHog, err := loadOptionalWithRequiredSecret(
		values[KeyPostHogEndpoint], present[KeyPostHogEndpoint],
		values[KeyPostHogSecretRef], present[KeyPostHogSecretRef],
	)
	if err != nil {
		return OptionalDependencies{}, err
	}
	openRouter, hasOpenRouter, err := loadOptionalWithRequiredSecret(
		values[KeyOpenRouterEndpoint], present[KeyOpenRouterEndpoint],
		values[KeyOpenRouterSecretRef], present[KeyOpenRouterSecretRef],
	)
	if err != nil {
		return OptionalDependencies{}, err
	}
	remoteOTLP, hasRemoteOTLP, err := loadOptionalWithOptionalSecret(
		values[KeyRemoteOTLPEndpoint], present[KeyRemoteOTLPEndpoint],
		values[KeyRemoteOTLPSecretRef], present[KeyRemoteOTLPSecretRef],
	)
	if err != nil {
		return OptionalDependencies{}, err
	}
	return OptionalDependencies{
		postHog:       postHog,
		hasPostHog:    hasPostHog,
		openRouter:    openRouter,
		hasOpenRouter: hasOpenRouter,
		remoteOTLP:    remoteOTLP,
		hasRemoteOTLP: hasRemoteOTLP,
	}, nil
}

func loadOptionalWithRequiredSecret(endpointValue string, endpointPresent bool, secretValue string, secretPresent bool) (OptionalDependency, bool, error) {
	if !endpointPresent && !secretPresent {
		return OptionalDependency{}, false, nil
	}
	if !endpointPresent || !secretPresent || endpointValue == "" || secretValue == "" {
		return OptionalDependency{}, false, ErrPartialOptionalConfiguration
	}
	endpoint, err := ParseDependencyEndpoint(endpointValue)
	if err != nil || !endpoint.secure() {
		return OptionalDependency{}, false, ErrInvalidConfiguration
	}
	secretReference, err := ParseSecretReference(secretValue)
	if err != nil {
		return OptionalDependency{}, false, ErrInvalidConfiguration
	}
	return OptionalDependency{endpoint: endpoint, secretReference: secretReference, hasSecretReference: true}, true, nil
}

func loadOptionalWithOptionalSecret(endpointValue string, endpointPresent bool, secretValue string, secretPresent bool) (OptionalDependency, bool, error) {
	if !endpointPresent && !secretPresent {
		return OptionalDependency{}, false, nil
	}
	if !endpointPresent || endpointValue == "" || secretPresent && secretValue == "" {
		return OptionalDependency{}, false, ErrPartialOptionalConfiguration
	}
	endpoint, err := ParseDependencyEndpoint(endpointValue)
	if err != nil || !endpoint.secure() {
		return OptionalDependency{}, false, ErrInvalidConfiguration
	}
	dependency := OptionalDependency{endpoint: endpoint}
	if secretPresent {
		dependency.secretReference, err = ParseSecretReference(secretValue)
		if err != nil {
			return OptionalDependency{}, false, ErrInvalidConfiguration
		}
		dependency.hasSecretReference = true
	}
	return dependency, true, nil
}

func validOptional(value OptionalDependency, present bool) bool {
	if present {
		return value.valid()
	}
	return value == (OptionalDependency{})
}

func asciiAlphanumeric(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9'
}

func asciiDigits(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validEndpointHostname(hostname string) bool {
	if net.ParseIP(hostname) != nil {
		return true
	}
	if len(hostname) > 253 || strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validPartitionRegion(partition string, region string) bool {
	switch partition {
	case "aws":
		return !strings.HasPrefix(region, "cn-") && !strings.HasPrefix(region, "us-gov-")
	case "aws-cn":
		return strings.HasPrefix(region, "cn-")
	case "aws-us-gov":
		return strings.HasPrefix(region, "us-gov-")
	default:
		return false
	}
}
