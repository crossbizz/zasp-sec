package preflight

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStrictTargetAndCredentialBoundary(t *testing.T) {
	original := sdkContractConfig(t)
	for _, name := range []string{"cross-account-key", "cross-region-queue", "unknown-profile", "operator-with-token", "workload-fallback", "unknown-field", "duplicate-field", "null-config", "public-credentials", "expired-credentials"} {
		t.Run(name, func(t *testing.T) {
			config := original
			config.AWS.Buckets = append([]Bucket(nil), original.AWS.Buckets...)
			config.AWS.Queues = append([]Queue(nil), original.AWS.Queues...)
			switch name {
			case "cross-account-key":
				config.AWS.Buckets[0].KMSKeyARN = "arn:aws:kms:us-west-2:999999999999:key/11111111-1111-4111-8111-111111111111"
			case "cross-region-queue":
				config.AWS.Queues[0].URL = "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs"
			case "unknown-profile":
				config.Deployment.Profile = "caller-attested"
			case "operator-with-token":
				config.Credentials.TokenFile = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
			case "workload-fallback":
				config.Credentials.Kind = "workload_web_identity"
				config.Credentials.TokenFile = "/tmp/copied-token"
				config.Credentials.Namespace = "agentsec"
				config.Credentials.ServiceAccount = "index"
			case "public-credentials", "expired-credentials":
				path := filepath.Join(t.TempDir(), "credentials.json")
				mode := os.FileMode(0600)
				if name == "public-credentials" {
					mode = 0644
				}
				body := []byte(`{"access_key_id":"fixture-key-only","secret_access_key":"fixture-secret-only","expires_at":"2020-01-01T00:00:00Z"}`)
				if os.WriteFile(path, body, mode) != nil {
					t.Fatal("controlled credential fixture unavailable")
				}
				config.Credentials.Kind = "operator_file"
				config.Credentials.File = path
			}
			raw, _ := json.Marshal(config)
			switch name {
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(`,"iam_role":true}`)...)
			case "duplicate-field":
				raw = append(raw[:len(raw)-1], []byte(`,"schema":"agentsec-preflight-config-v1"}`)...)
			case "null-config":
				raw = []byte(`null`)
			}
			parsed, err := DecodeConfig(raw)
			if name == "public-credentials" || name == "expired-credentials" {
				if err != nil {
					t.Fatal("valid intended source rejected before private-file check")
				}
				tr := &sdkContractTransport{mode: "observed"}
				r := &Runner{config: parsed, http: &http.Client{Transport: tr, Timeout: time.Second}}
				report, err := r.Run(context.Background(), "before-install")
				if err == nil || len(tr.methods) != 0 || len(report.Checks) != 8 {
					t.Fatal("unsafe selected source fell back to ambient credentials or hid original roster")
				}
				return
			}
			if err == nil {
				t.Fatal("untrusted target or credential configuration accepted")
			}
		})
	}
}
func TestDisabledOptionalFeaturesStayExplicitAndNoAmbientFallback(t *testing.T) {
	config := sdkContractConfig(t)
	config.Features.AttackLab = "disabled"
	config.Features.SensorMode = "disabled"
	config.Credentials.Kind = "operator_file"
	config.Credentials.File = filepath.Join(t.TempDir(), "absent.json")
	tr := &sdkContractTransport{mode: "observed"}
	r := &Runner{config: config, http: &http.Client{Transport: tr, Timeout: time.Second}}
	report, err := r.Run(context.Background(), "installed")
	if err == nil || len(report.Checks) != 8 || len(tr.methods) != 0 || report.Ready {
		t.Fatal("missing selected credentials fell back or hid checks")
	}
	for _, i := range []int{4, 7} {
		c := report.Checks[i]
		if c.Required || c.Status != "warn" {
			t.Fatal("disabled feature became required or silently passing")
		}
		for _, o := range c.Observations {
			if o.Status != "disabled" {
				t.Fatal("disabled feature absent from report")
			}
		}
	}
}
