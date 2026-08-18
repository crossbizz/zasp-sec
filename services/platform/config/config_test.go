package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	testStytchSecret = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/stytch"
	testNeonSecret   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/neon-dsn"
	testPostHog      = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/posthog"
	testOpenRouter   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/openrouter"
	testRemoteOTLP   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/remote-otlp"
	testOrganization = "pid_00000000-0000-4000-8000-000000000001"
)

func validSource() map[string]string {
	return map[string]string{
		KeyDeploymentMode:        "saas",
		KeyStytchProjectID:       "project-live-platform",
		KeyStytchSecretRef:       testStytchSecret,
		KeyNeonDSNSecretRef:      testNeonSecret,
		KeyAWSRegion:             "us-east-1",
		KeyOTelCollectorEndpoint: "http://otel-collector.platform.svc:4317",
	}
}

func TestParseDeploymentMode(t *testing.T) {
	tests := []struct {
		text string
		want DeploymentMode
	}{
		{text: "saas", want: DeploymentModeSaaS},
		{text: "single_tenant", want: DeploymentModeSingleTenant},
	}
	for _, test := range tests {
		t.Run(test.text, func(t *testing.T) {
			parsed, err := ParseDeploymentMode(test.text)
			if err != nil {
				t.Fatalf("ParseDeploymentMode() error = %v", err)
			}
			if parsed != test.want || parsed.String() != test.text {
				t.Fatalf("ParseDeploymentMode() = (%v, %q), want (%v, %q)", parsed, parsed.String(), test.want, test.text)
			}
		})
	}

	for _, text := range []string{"", "SaaS", "single-tenant", " single_tenant", "single_tenant ", "unknown", "true", "0"} {
		t.Run("reject "+text, func(t *testing.T) {
			parsed, err := ParseDeploymentMode(text)
			if !errors.Is(err, ErrInvalidConfiguration) || parsed != DeploymentMode("") {
				t.Fatalf("ParseDeploymentMode(%q) = (%v, %v)", text, parsed, err)
			}
			if strings.Contains(err.Error(), text) && text != "" {
				t.Fatalf("error exposed rejected mode %q: %v", text, err)
			}
		})
	}

	for _, invalid := range []DeploymentMode{"", "invalid", "SAAS"} {
		if invalid.String() != "" {
			t.Fatalf("invalid DeploymentMode.String() = %q", invalid.String())
		}
	}
}

func TestLoadDeploymentModes(t *testing.T) {
	saas, err := Load(lookup(validSource()))
	if err != nil {
		t.Fatalf("Load(saas) error = %v", err)
	}
	if saas.Deployment().Mode() != DeploymentModeSaaS {
		t.Fatalf("Deployment().Mode() = %v", saas.Deployment().Mode())
	}
	if _, present := saas.Deployment().PinnedOrganizationID(); present {
		t.Fatal("SaaS exposed a pinned Organization")
	}

	source := validSource()
	source[KeyDeploymentMode] = "single_tenant"
	source[KeySingleTenantOrganizationID] = testOrganization
	singleTenant, err := Load(lookup(source))
	if err != nil {
		t.Fatalf("Load(single_tenant) error = %v", err)
	}
	if singleTenant.Deployment().Mode() != DeploymentModeSingleTenant {
		t.Fatalf("Deployment().Mode() = %v", singleTenant.Deployment().Mode())
	}
	organizationID, present := singleTenant.Deployment().PinnedOrganizationID()
	if !present || organizationID.String() != testOrganization {
		t.Fatalf("PinnedOrganizationID() = (%q, %v)", organizationID.String(), present)
	}
	parsedOrganization, err := domain.ParseProductID(testOrganization)
	if err != nil || organizationID != parsedOrganization {
		t.Fatalf("pinned Organization is not the canonical domain value: (%v, %v)", organizationID, err)
	}
	if err := singleTenant.Validate(); err != nil {
		t.Fatalf("Validate(single_tenant) error = %v", err)
	}
}

func TestLoadRejectsInvalidDeploymentCombinations(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		modeSet  bool
		pin      string
		pinSet   bool
		want     error
		rejected string
	}{
		{name: "missing mode", want: ErrMissingRequiredConfiguration},
		{name: "empty mode", modeSet: true, want: ErrMissingRequiredConfiguration},
		{name: "unknown mode", mode: "dedicated", modeSet: true, want: ErrInvalidConfiguration, rejected: "dedicated"},
		{name: "case drift", mode: "SaaS", modeSet: true, want: ErrInvalidConfiguration, rejected: "SaaS"},
		{name: "saas empty pin", mode: "saas", modeSet: true, pinSet: true, want: ErrInvalidConfiguration},
		{name: "saas canonical pin", mode: "saas", modeSet: true, pin: testOrganization, pinSet: true, want: ErrInvalidConfiguration, rejected: testOrganization},
		{name: "single tenant missing pin", mode: "single_tenant", modeSet: true, want: ErrMissingRequiredConfiguration},
		{name: "single tenant empty pin", mode: "single_tenant", modeSet: true, pinSet: true, want: ErrMissingRequiredConfiguration},
		{name: "single tenant raw uuid", mode: "single_tenant", modeSet: true, pin: "00000000-0000-4000-8000-000000000001", pinSet: true, want: ErrInvalidConfiguration, rejected: "00000000-0000-4000-8000-000000000001"},
		{name: "single tenant uppercase uuid", mode: "single_tenant", modeSet: true, pin: "pid_00000000-0000-4000-8000-00000000000A", pinSet: true, want: ErrInvalidConfiguration, rejected: "pid_00000000-0000-4000-8000-00000000000A"},
		{name: "single tenant zero payload", mode: "single_tenant", modeSet: true, pin: "pid_00000000-0000-4000-8000-000000000000", pinSet: true, want: ErrInvalidConfiguration, rejected: "pid_00000000-0000-4000-8000-000000000000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := validSource()
			delete(source, KeyDeploymentMode)
			if test.modeSet {
				source[KeyDeploymentMode] = test.mode
			}
			if test.pinSet {
				source[KeySingleTenantOrganizationID] = test.pin
			}
			_, err := Load(lookup(source))
			if !errors.Is(err, test.want) {
				t.Fatalf("Load() error = %v, want %v", err, test.want)
			}
			if test.rejected != "" && strings.Contains(err.Error(), test.rejected) {
				t.Fatalf("error exposed rejected value: %v", err)
			}
		})
	}
}

func lookup(source map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, present := source[key]
		return value, present
	}
}

func TestLoadRequiredDependencies(t *testing.T) {
	loaded, err := Load(lookup(validSource()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	required := loaded.Required()
	if required.StytchProjectID().String() != "project-live-platform" {
		t.Fatalf("StytchProjectID() = %q", required.StytchProjectID().String())
	}
	if required.StytchSecretReference().String() != testStytchSecret {
		t.Fatalf("StytchSecretReference() = %q", required.StytchSecretReference().String())
	}
	if required.NeonDSNReference().String() != testNeonSecret {
		t.Fatalf("NeonDSNReference() = %q", required.NeonDSNReference().String())
	}
	if required.AWSRegion().String() != "us-east-1" {
		t.Fatalf("AWSRegion() = %q", required.AWSRegion().String())
	}
	if required.OTelCollectorEndpoint().String() != "http://otel-collector.platform.svc:4317" {
		t.Fatalf("OTelCollectorEndpoint() = %q", required.OTelCollectorEndpoint().String())
	}

	optional := loaded.Optional()
	if _, configured := optional.PostHog(); configured {
		t.Fatal("PostHog() configured without source values")
	}
	if _, configured := optional.OpenRouter(); configured {
		t.Fatal("OpenRouter() configured without source values")
	}
	if _, configured := optional.RemoteOTLP(); configured {
		t.Fatal("RemoteOTLP() configured without source values")
	}
}

func TestLoadMissingRequiredConfiguration(t *testing.T) {
	for _, key := range []string{
		KeyDeploymentMode,
		KeyStytchProjectID,
		KeyStytchSecretRef,
		KeyNeonDSNSecretRef,
		KeyAWSRegion,
		KeyOTelCollectorEndpoint,
	} {
		t.Run(key, func(t *testing.T) {
			source := validSource()
			delete(source, key)
			_, err := Load(lookup(source))
			if !errors.Is(err, ErrMissingRequiredConfiguration) {
				t.Fatalf("Load() error = %v, want ErrMissingRequiredConfiguration", err)
			}
		})
	}

	source := validSource()
	source[KeyAWSRegion] = ""
	if _, err := Load(lookup(source)); !errors.Is(err, ErrMissingRequiredConfiguration) {
		t.Fatalf("Load(empty required) error = %v", err)
	}
}

func TestLoadOptionalDependencies(t *testing.T) {
	source := validSource()
	source[KeyPostHogEndpoint] = "https://analytics.example.test/capture"
	source[KeyPostHogSecretRef] = testPostHog
	source[KeyOpenRouterEndpoint] = "https://router.example.test/api/v1"
	source[KeyOpenRouterSecretRef] = testOpenRouter
	source[KeyRemoteOTLPEndpoint] = "https://telemetry.example.test/v1/traces"

	loaded, err := Load(lookup(source))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	postHog, configured := loaded.Optional().PostHog()
	if !configured || postHog.Endpoint().String() != source[KeyPostHogEndpoint] {
		t.Fatalf("PostHog() = (%v, %v)", postHog, configured)
	}
	if secret, present := postHog.SecretReference(); !present || secret.String() != testPostHog {
		t.Fatalf("PostHog SecretReference() = (%v, %v)", secret, present)
	}
	openRouter, configured := loaded.Optional().OpenRouter()
	if !configured || openRouter.Endpoint().String() != source[KeyOpenRouterEndpoint] {
		t.Fatalf("OpenRouter() = (%v, %v)", openRouter, configured)
	}
	remote, configured := loaded.Optional().RemoteOTLP()
	if !configured || remote.Endpoint().String() != source[KeyRemoteOTLPEndpoint] {
		t.Fatalf("RemoteOTLP() = (%v, %v)", remote, configured)
	}
	if _, present := remote.SecretReference(); present {
		t.Fatal("RemoteOTLP secret unexpectedly present")
	}

	source[KeyRemoteOTLPSecretRef] = testRemoteOTLP
	loaded, err = Load(lookup(source))
	if err != nil {
		t.Fatalf("Load(with remote secret) error = %v", err)
	}
	remote, _ = loaded.Optional().RemoteOTLP()
	if secret, present := remote.SecretReference(); !present || secret.String() != testRemoteOTLP {
		t.Fatalf("RemoteOTLP SecretReference() = (%v, %v)", secret, present)
	}
}

func TestLoadRejectsPartialOptionalConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "posthog endpoint only", key: KeyPostHogEndpoint, value: "https://analytics.example.test"},
		{name: "posthog secret only", key: KeyPostHogSecretRef, value: testPostHog},
		{name: "openrouter endpoint only", key: KeyOpenRouterEndpoint, value: "https://router.example.test"},
		{name: "openrouter secret only", key: KeyOpenRouterSecretRef, value: testOpenRouter},
		{name: "remote secret only", key: KeyRemoteOTLPSecretRef, value: testRemoteOTLP},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := validSource()
			source[test.key] = test.value
			_, err := Load(lookup(source))
			if !errors.Is(err, ErrPartialOptionalConfiguration) {
				t.Fatalf("Load() error = %v, want ErrPartialOptionalConfiguration", err)
			}
		})
	}

	source := validSource()
	source[KeyPostHogEndpoint] = ""
	source[KeyPostHogSecretRef] = testPostHog
	if _, err := Load(lookup(source)); !errors.Is(err, ErrPartialOptionalConfiguration) {
		t.Fatalf("Load(empty optional) error = %v", err)
	}
}

func TestLoadRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "stytch whitespace", key: KeyStytchProjectID, value: " project-live-platform"},
		{name: "stytch control", key: KeyStytchProjectID, value: "project\nlive"},
		{name: "raw stytch secret", key: KeyStytchSecretRef, value: "not-a-reference"},
		{name: "wrong secret service", key: KeyNeonDSNSecretRef, value: "arn:aws:ssm:us-east-1:000000000000:parameter/neon"},
		{name: "bad account", key: KeyNeonDSNSecretRef, value: "arn:aws:secretsmanager:us-east-1:123:secret:neon"},
		{name: "uppercase region", key: KeyAWSRegion, value: "US-east-1"},
		{name: "short region", key: KeyAWSRegion, value: "useast1"},
		{name: "userinfo endpoint", key: KeyOTelCollectorEndpoint, value: "https://user:pass@example.test"},
		{name: "query endpoint", key: KeyOTelCollectorEndpoint, value: "https://example.test?token=value"},
		{name: "fragment endpoint", key: KeyOTelCollectorEndpoint, value: "https://example.test/#fragment"},
		{name: "unsupported endpoint scheme", key: KeyOTelCollectorEndpoint, value: "grpc://collector.example.test:4317"},
		{name: "public plaintext collector", key: KeyOTelCollectorEndpoint, value: "http://collector.example.test:4317"},
		{name: "encoded traversal endpoint", key: KeyOTelCollectorEndpoint, value: "https://collector.example.test/%2e%2e/secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := validSource()
			source[test.key] = test.value
			_, err := Load(lookup(source))
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Load() error = %v, want ErrInvalidConfiguration", err)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("error exposed rejected value: %v", err)
			}
		})
	}

	source := validSource()
	source[KeyOpenRouterEndpoint] = "https://Router.example.test"
	source[KeyOpenRouterSecretRef] = testOpenRouter
	if _, err := Load(lookup(source)); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Load(malformed optional) error = %v", err)
	}
}

func TestLoadRejectsPartitionDriftAndPlaintextOptionalEgress(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		add   map[string]string
	}{
		{
			name:  "commercial partition with China region",
			key:   KeyStytchSecretRef,
			value: "arn:aws:secretsmanager:cn-north-1:000000000000:secret:platform/stytch",
		},
		{
			name:  "China partition with commercial region",
			key:   KeyStytchSecretRef,
			value: "arn:aws-cn:secretsmanager:us-east-1:000000000000:secret:platform/stytch",
		},
		{
			name:  "GovCloud partition with commercial region",
			key:   KeyStytchSecretRef,
			value: "arn:aws-us-gov:secretsmanager:us-east-1:000000000000:secret:platform/stytch",
		},
		{
			name:  "plaintext PostHog egress",
			key:   KeyPostHogEndpoint,
			value: "http://analytics.example.test",
			add:   map[string]string{KeyPostHogSecretRef: testPostHog},
		},
		{
			name:  "plaintext OpenRouter egress",
			key:   KeyOpenRouterEndpoint,
			value: "http://router.example.test/api/v1",
			add:   map[string]string{KeyOpenRouterSecretRef: testOpenRouter},
		},
		{
			name:  "plaintext remote OTLP egress",
			key:   KeyRemoteOTLPEndpoint,
			value: "http://telemetry.example.test/v1/traces",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := validSource()
			source[test.key] = test.value
			for key, value := range test.add {
				source[key] = value
			}
			if _, err := Load(lookup(source)); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Load() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func TestLoadReadsEachKnownKeyOnce(t *testing.T) {
	source := validSource()
	reads := map[string]int{}
	loaded, err := Load(func(key string) (string, bool) {
		reads[key]++
		value, present := source[key]
		return value, present
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for _, key := range allKeys {
		if reads[key] != 1 {
			t.Fatalf("reads[%q] = %d, want 1", key, reads[key])
		}
	}
}

func TestLoadRejectsNilSource(t *testing.T) {
	if _, err := Load(nil); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("Load(nil) error = %v", err)
	}
}

func TestConfigRejectsInvalidDirectState(t *testing.T) {
	valid, err := Load(lookup(validSource()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	organizationID, err := domain.ParseProductID(testOrganization)
	if err != nil {
		t.Fatalf("ParseProductID() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(Config) Config
	}{
		{name: "zero", mutate: func(Config) Config { return Config{} }},
		{name: "invalid deployment mode", mutate: func(value Config) Config {
			value.deployment.mode = DeploymentMode("forged")
			return value
		}},
		{name: "saas with Organization", mutate: func(value Config) Config {
			value.deployment.organizationID = organizationID
			value.deployment.hasOrganizationID = true
			return value
		}},
		{name: "single tenant without Organization", mutate: func(value Config) Config {
			value.deployment.mode = DeploymentModeSingleTenant
			return value
		}},
		{name: "single tenant Organization without presence", mutate: func(value Config) Config {
			value.deployment.mode = DeploymentModeSingleTenant
			value.deployment.organizationID = organizationID
			return value
		}},
		{name: "bad project", mutate: func(value Config) Config {
			value.required.stytchProjectID.value = " bad"
			return value
		}},
		{name: "bad secret", mutate: func(value Config) Config {
			value.required.neonDSNReference.value = "raw-secret"
			return value
		}},
		{name: "bad region", mutate: func(value Config) Config {
			value.required.awsRegion.value = "bad"
			return value
		}},
		{name: "bad endpoint", mutate: func(value Config) Config {
			value.required.otelCollectorEndpoint.value = "file:///tmp/socket"
			return value
		}},
		{name: "optional flag without value", mutate: func(value Config) Config {
			value.optional.hasPostHog = true
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := test.mutate(valid)
			if err := invalid.Validate(); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestDeploymentRejectsInvalidDirectState(t *testing.T) {
	organizationID, err := domain.ParseProductID(testOrganization)
	if err != nil {
		t.Fatalf("ParseProductID() error = %v", err)
	}
	invalid := []Deployment{
		{},
		{mode: DeploymentMode("forged")},
		{mode: DeploymentModeSaaS, organizationID: organizationID},
		{mode: DeploymentModeSaaS, organizationID: organizationID, hasOrganizationID: true},
		{mode: DeploymentModeSingleTenant},
		{mode: DeploymentModeSingleTenant, organizationID: organizationID},
		{mode: DeploymentModeSingleTenant, hasOrganizationID: true},
	}
	for index, deployment := range invalid {
		if deployment.valid() {
			t.Fatalf("invalid[%d] validates", index)
		}
		if deployment.Mode() != DeploymentMode("") {
			t.Fatalf("invalid[%d].Mode() = %q", index, deployment.Mode())
		}
		if organization, present := deployment.PinnedOrganizationID(); present || !organization.IsZero() {
			t.Fatalf("invalid[%d].PinnedOrganizationID() = (%q, %v)", index, organization.String(), present)
		}
	}
}

func TestConfigValuesAreComparable(t *testing.T) {
	first, err := Load(lookup(validSource()))
	if err != nil {
		t.Fatalf("Load(first) error = %v", err)
	}
	second, err := Load(lookup(validSource()))
	if err != nil {
		t.Fatalf("Load(second) error = %v", err)
	}
	if first != second {
		t.Fatalf("equal configuration values differ: %#v %#v", first, second)
	}
	set := map[Config]struct{}{first: {}}
	if _, found := set[second]; !found {
		t.Fatal("configuration value is not usable as a comparable key")
	}

	singleTenantSource := validSource()
	singleTenantSource[KeyDeploymentMode] = "single_tenant"
	singleTenantSource[KeySingleTenantOrganizationID] = testOrganization
	singleTenantFirst, err := Load(lookup(singleTenantSource))
	if err != nil {
		t.Fatalf("Load(singleTenantFirst) error = %v", err)
	}
	singleTenantSecond, err := Load(lookup(singleTenantSource))
	if err != nil {
		t.Fatalf("Load(singleTenantSecond) error = %v", err)
	}
	if singleTenantFirst != singleTenantSecond || singleTenantFirst == first {
		t.Fatalf("deployment comparison mismatch: %#v %#v %#v", first, singleTenantFirst, singleTenantSecond)
	}
	deploymentSet := map[Deployment]struct{}{singleTenantFirst.Deployment(): {}}
	if _, found := deploymentSet[singleTenantSecond.Deployment()]; !found {
		t.Fatal("Deployment is not usable as a comparable key")
	}
}
