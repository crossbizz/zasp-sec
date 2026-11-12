package localcloud

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestUnsetEndpointIsDisabledInEveryEnvironment(t *testing.T) {
	for _, environment := range []string{"production", "development", "test", ""} {
		settings, err := Load(env(map[string]string{EnvironmentVariable: environment}))
		if err != nil || settings.Enabled() {
			t.Fatalf("%q: settings = (%#v, %v)", environment, settings, err)
		}
		base := aws.Config{}
		settings.Apply(&base)
		options := s3.Options{}
		settings.S3(&options)
		if base.BaseEndpoint != nil || options.UsePathStyle || settings.AllowsEndpoint("http://127.0.0.1:4566") {
			t.Fatalf("%q: disabled settings changed a client", environment)
		}
	}
}

func TestProductionRefusesALocalCloudEndpoint(t *testing.T) {
	for _, environment := range []string{"production", "", "staging", "Development"} {
		if _, err := Load(env(map[string]string{EnvironmentVariable: environment, EndpointVariable: "http://127.0.0.1:4566"})); err != ErrConfiguration {
			t.Fatalf("%q accepted a local cloud endpoint: %v", environment, err)
		}
	}
}

func TestOnlyAPlaintextLoopbackOrPrivateEndpointIsAccepted(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:4566", "http://10.1.2.3:4566", "http://192.168.1.10:4566", "http://[::1]:4566"} {
		settings, err := Load(env(map[string]string{EnvironmentVariable: "development", EndpointVariable: endpoint}))
		if err != nil || settings.Endpoint() != endpoint {
			t.Fatalf("%s refused: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"https://127.0.0.1:4566", "http://127.0.0.1", "http://localhost:4566", "http://8.8.8.8:4566", "http://sts.amazonaws.com:80",
		"http://user@127.0.0.1:4566", "http://127.0.0.1:4566/", "http://127.0.0.1:4566/path", "http://127.0.0.1:4566?x=1", "127.0.0.1:4566",
	} {
		if _, err := Load(env(map[string]string{EnvironmentVariable: "test", EndpointVariable: endpoint})); err != ErrConfiguration {
			t.Fatalf("%s accepted: %v", endpoint, err)
		}
	}
}

func TestEnabledSettingsRedirectClientsAndAllowOnlyLocalServiceEndpoints(t *testing.T) {
	settings, err := Load(env(map[string]string{EnvironmentVariable: "test", EndpointVariable: "http://127.0.0.1:4566"}))
	if err != nil {
		t.Fatal(err)
	}
	base := aws.Config{}
	settings.Apply(&base)
	options := s3.Options{}
	settings.S3(&options)
	if base.BaseEndpoint == nil || *base.BaseEndpoint != "http://127.0.0.1:4566" || !options.UsePathStyle {
		t.Fatalf("clients not redirected: %#v %v", base.BaseEndpoint, options.UsePathStyle)
	}
	if !settings.AllowsEndpoint("http://127.0.0.1:9200") || settings.AllowsEndpoint("https://search-x.us-east-1.es.amazonaws.com") || settings.AllowsEndpoint("http://example.com:9200") {
		t.Fatal("service endpoint allowance is wrong")
	}
}
