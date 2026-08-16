package config

import (
	"errors"
	"strings"
	"testing"
)

const (
	testStytchSecret = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/stytch"
	testNeonSecret   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/neon-dsn"
	testPostHog      = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/posthog"
	testOpenRouter   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/openrouter"
	testRemoteOTLP   = "arn:aws:secretsmanager:us-east-1:000000000000:secret:platform/remote-otlp"
)

func validSource() map[string]string {
	return map[string]string{
		KeyStytchProjectID:       "project-live-platform",
		KeyStytchSecretRef:       testStytchSecret,
		KeyNeonDSNSecretRef:      testNeonSecret,
		KeyAWSRegion:             "us-east-1",
		KeyOTelCollectorEndpoint: "http://otel-collector.platform.svc:4317",
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
	tests := []struct {
		name   string
		mutate func(Config) Config
	}{
		{name: "zero", mutate: func(Config) Config { return Config{} }},
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
			if err := test.mutate(valid).Validate(); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
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
}
