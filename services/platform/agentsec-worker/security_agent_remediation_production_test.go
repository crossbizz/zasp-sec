package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

func remediationProductionConfig() workerRuntimeConfig {
	return workerRuntimeConfig{
		AWSRegion: "us-east-1", LeaseDuration: 90 * time.Second,
		RemediationRoleARN:      "arn:aws:iam::123456789012:role/zasp-security-agent-remediation",
		RemediationTokenFile:    "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		RemediationSecretPrefix: "zasp/discovery",
	}
}

// Building the factory creates offline SDK clients only: no token is read and
// no provider is called until a claim is served.
func TestProductionRemediationClientFactoryConstruction(t *testing.T) {
	for name, tc := range map[string]struct {
		lease   time.Duration
		timeout time.Duration
	}{
		"long lease is capped": {10 * time.Minute, 20 * time.Second},
		"short lease":          {30 * time.Second, 10 * time.Second},
		"shortest lease":       {3 * time.Second, time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			config := remediationProductionConfig()
			config.LeaseDuration = tc.lease
			factory, err := newProductionRemediationClientFactory(config)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			t.Cleanup(func() { _ = factory.Close() })
			reader, ok := factory.secrets.(*discoverySecretsManagerReader)
			if factory.cloud == nil || !ok || reader.root != config.RemediationSecretPrefix || reader.timeout != tc.timeout || reader.client != factory.cloud.secrets {
				t.Fatalf("secrets reader = %#v", factory.secrets)
			}
			if assumeRole, ok := factory.assumeRole.(*sts.Client); !ok || assumeRole != factory.cloud.assumeRole || factory.cloud.base.Region != config.AWSRegion {
				t.Fatalf("assume role client = %#v", factory.assumeRole)
			}
			if client, ok := factory.cloud.base.HTTPClient.(*http.Client); !ok || client.Timeout != tc.timeout {
				t.Fatalf("provider HTTP client = %#v", factory.cloud.base.HTTPClient)
			}
			if now := factory.clock(); now.IsZero() || now.Location() != time.UTC {
				t.Fatalf("clock = %v", now)
			}
		})
	}
}

func TestProductionRemediationClientFactoryRefusesConfiguration(t *testing.T) {
	for name, change := range map[string]func(*workerRuntimeConfig){
		// A worker without remediation settings performs no remediation.
		"no remediation settings": func(c *workerRuntimeConfig) {
			c.RemediationRoleARN, c.RemediationTokenFile, c.RemediationSecretPrefix = "", "", ""
		},
		"partial settings":   func(c *workerRuntimeConfig) { c.RemediationSecretPrefix = "" },
		"no role":            func(c *workerRuntimeConfig) { c.RemediationRoleARN = "" },
		"malformed role":     func(c *workerRuntimeConfig) { c.RemediationRoleARN = "arn:aws:iam::123:role/x" },
		"another token file": func(c *workerRuntimeConfig) { c.RemediationTokenFile = "/tmp/token" },
		"traversing prefix":  func(c *workerRuntimeConfig) { c.RemediationSecretPrefix = "zasp/../discovery" },
		"oauth prefix":       func(c *workerRuntimeConfig) { c.RemediationSecretPrefix = "zasp/oauth" },
		"no Region":          func(c *workerRuntimeConfig) { c.AWSRegion = "" },
		"malformed Region":   func(c *workerRuntimeConfig) { c.AWSRegion = "US-EAST-1" },
		"lease below 3s":     func(c *workerRuntimeConfig) { c.LeaseDuration = 2 * time.Second },
		"no lease":           func(c *workerRuntimeConfig) { c.LeaseDuration = 0 },
		"negative lease":     func(c *workerRuntimeConfig) { c.LeaseDuration = -time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			config := remediationProductionConfig()
			change(&config)
			if factory, err := newProductionRemediationClientFactory(config); !errors.Is(err, errRuntimeUnavailable) || factory != nil {
				t.Fatalf("factory=%v err=%v", factory, err)
			}
		})
	}
}

func TestProductionRemediationClientFactoryClose(t *testing.T) {
	var absent *productionRemediationClientFactory
	if err := absent.Close(); err != nil {
		t.Fatalf("nil factory: %v", err)
	}
	if err := (&productionRemediationClientFactory{}).Close(); err != nil {
		t.Fatalf("factory without cloud: %v", err)
	}
	factory, err := newProductionRemediationClientFactory(remediationProductionConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Closing is idempotent.
	if err := factory.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := factory.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// remediationAssumeRoleRecorder records the AssumeRole request and the
// options the caller applies to it.
type remediationAssumeRoleRecorder struct {
	mu      sync.Mutex
	calls   int
	input   *sts.AssumeRoleInput
	retryer aws.Retryer
	out     *sts.AssumeRoleOutput
	err     error
}

func (r *remediationAssumeRoleRecorder) AssumeRole(_ context.Context, input *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	copied := *input
	r.input = &copied
	options := sts.Options{}
	for _, fn := range optFns {
		fn(&options)
	}
	r.retryer = options.Retryer
	return r.out, r.err
}

func remediationAssumedRole(expires time.Time) *sts.AssumeRoleOutput {
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{AccessKeyId: aws.String("ASIAREMEDIATION"), SecretAccessKey: aws.String("remediation-secret"), SessionToken: aws.String("remediation-session"), Expiration: aws.Time(expires)}}
}

// remediationProductionFactory is a production factory whose provider edges
// (the secret read and the role assumption) are scripted. The customer
// clients it builds are real SDK clients that are never called.
func remediationProductionFactory(t *testing.T, externalID []byte, assume *remediationAssumeRoleRecorder) (*productionRemediationClientFactory, *discoverySecretReaderStub) {
	t.Helper()
	factory, err := newProductionRemediationClientFactory(remediationProductionConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = factory.Close() })
	claim := remediationProductionClaim()
	secrets := &discoverySecretReaderStub{values: map[string][]byte{claim.ExternalIDReference: externalID}}
	factory.secrets, factory.assumeRole = secrets, assume
	return factory, secrets
}

func remediationProductionClaim() apiserver.ProviderRemediationClaim {
	return remediationTestClaim(securityagent.ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": remediationTestAdmin})
}

func TestProductionRemediationClientsAssumeTheClaimedRole(t *testing.T) {
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	assume := &remediationAssumeRoleRecorder{out: remediationAssumedRole(expires)}
	factory, secrets := remediationProductionFactory(t, []byte("external-id-0123456789"), assume)
	claim := remediationProductionClaim()
	clients, err := factory.RemediationClients(context.Background(), claim)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(secrets.calls) != 1 || secrets.calls[0] != claim.ExternalIDReference {
		t.Fatalf("secret reads = %q", secrets.calls)
	}
	digest := sha256.Sum256([]byte(claim.OrganizationID + "\x1f" + claim.WorkspaceID + "\x1f" + claim.EnvironmentID + "\x1f" + claim.RunID + "\x1f" + claim.StepID))
	input := assume.input
	if assume.calls != 1 || aws.ToString(input.RoleArn) != claim.RemediationRoleARN || aws.ToString(input.RoleSessionName) != "zasp-remediation-"+hex.EncodeToString(digest[:12]) || aws.ToString(input.ExternalId) != "external-id-0123456789" || aws.ToInt32(input.DurationSeconds) != 900 {
		t.Fatalf("AssumeRole input = %+v", input)
	}
	if _, ok := assume.retryer.(aws.NopRetryer); !ok {
		t.Fatalf("AssumeRole retryer = %#v", assume.retryer)
	}
	bedrock, ok := clients.Bedrock.(*bedrockagent.Client)
	if !ok {
		t.Fatalf("Bedrock client = %#v", clients.Bedrock)
	}
	identity, ok := clients.IAM.(*iam.Client)
	if !ok {
		t.Fatalf("IAM client = %#v", clients.IAM)
	}
	for name, options := range map[string]struct {
		region      string
		credentials aws.CredentialsProvider
	}{
		"bedrock": {bedrock.Options().Region, bedrock.Options().Credentials},
		"iam":     {identity.Options().Region, identity.Options().Credentials},
	} {
		if options.region != claim.Target.Region || options.credentials == nil {
			t.Fatalf("%s options: region=%q credentials=%v", name, options.region, options.credentials)
		}
		credentials, err := options.credentials.Retrieve(context.Background())
		if err != nil || credentials.AccessKeyID != "ASIAREMEDIATION" || credentials.SecretAccessKey != "remediation-secret" || credentials.SessionToken != "remediation-session" || !credentials.CanExpire || !credentials.Expires.Equal(expires) || credentials.Source != "zasp-remediation-role" {
			t.Fatalf("%s credentials = %+v err=%v", name, credentials, err)
		}
	}
}

func TestProductionRemediationClientsRefuseBeforeTheProvider(t *testing.T) {
	assume := &remediationAssumeRoleRecorder{out: remediationAssumedRole(time.Now().Add(time.Hour))}
	factory, secrets := remediationProductionFactory(t, []byte("external-id-0123456789"), assume)
	invalid := remediationProductionClaim()
	invalid.Attempt = 0
	foreignRole := remediationProductionClaim()
	foreignRole.RemediationRoleARN = "arn:aws:iam::210987654321:role/zasp-remediation"
	var nilContext context.Context
	for name, tc := range map[string]struct {
		factory *productionRemediationClientFactory
		ctx     context.Context
		claim   apiserver.ProviderRemediationClaim
	}{
		"nil factory":               {nil, context.Background(), remediationProductionClaim()},
		"no cloud":                  {&productionRemediationClientFactory{secrets: secrets, assumeRole: assume}, context.Background(), remediationProductionClaim()},
		"no secrets":                {&productionRemediationClientFactory{cloud: factory.cloud, assumeRole: assume}, context.Background(), remediationProductionClaim()},
		"no role assumer":           {&productionRemediationClientFactory{cloud: factory.cloud, secrets: secrets}, context.Background(), remediationProductionClaim()},
		"no context":                {factory, nilContext, remediationProductionClaim()},
		"invalid claim":             {factory, context.Background(), invalid},
		"role in a foreign account": {factory, context.Background(), foreignRole},
	} {
		t.Run(name, func(t *testing.T) {
			if clients, err := tc.factory.RemediationClients(tc.ctx, tc.claim); !errors.Is(err, errWorkerExecution) || clients.Bedrock != nil || clients.IAM != nil {
				t.Fatalf("clients=%#v err=%v", clients, err)
			}
		})
	}
	if len(secrets.calls) != 0 || assume.calls != 0 {
		t.Fatalf("a refused claim reached a provider: secrets=%q assume=%d", secrets.calls, assume.calls)
	}
}

func TestProductionRemediationClientsRefuseAnUnusableExternalID(t *testing.T) {
	for name, externalID := range map[string][]byte{
		"too short":    []byte("short-id"),
		"too long":     make([]byte, 257),
		"whitespace":   []byte("external id 0123456789"),
		"padded":       []byte(" external-id-0123456789"),
		"control":      []byte("external-id-0123456789\x00"),
		"invalid text": []byte("external-id-0123456789\xff"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "too long" {
				for i := range externalID {
					externalID[i] = 'x'
				}
			}
			assume := &remediationAssumeRoleRecorder{out: remediationAssumedRole(time.Now().Add(time.Hour))}
			factory, _ := remediationProductionFactory(t, externalID, assume)
			if _, err := factory.RemediationClients(context.Background(), remediationProductionClaim()); !errors.Is(err, errWorkerExecution) || assume.calls != 0 {
				t.Fatalf("err=%v assume=%d", err, assume.calls)
			}
		})
	}
	t.Run("unreadable secret", func(t *testing.T) {
		assume := &remediationAssumeRoleRecorder{out: remediationAssumedRole(time.Now().Add(time.Hour))}
		factory, secrets := remediationProductionFactory(t, nil, assume)
		secrets.err = errDiscoveryCredentialUnavailable
		if _, err := factory.RemediationClients(context.Background(), remediationProductionClaim()); !errors.Is(err, errWorkerExecution) || assume.calls != 0 {
			t.Fatalf("err=%v assume=%d", err, assume.calls)
		}
	})
}

func TestProductionRemediationClientsClassifyTheRoleAssumption(t *testing.T) {
	live := time.Now().Add(time.Hour)
	missing := func(change func(*ststypes.Credentials)) *sts.AssumeRoleOutput {
		out := remediationAssumedRole(live)
		change(out.Credentials)
		return out
	}
	for name, tc := range map[string]struct {
		out    *sts.AssumeRoleOutput
		err    error
		cancel bool
		want   error
	}{
		// Only the provider's own denial names the role as denied.
		"access denied":             {nil, remediationAPIError("AccessDenied"), false, errRemediationRoleDenied},
		"another provider error":    {nil, remediationAPIError("ExpiredToken"), false, errWorkerExecution},
		"transport error":           {nil, errors.New("connection reset"), false, errWorkerExecution},
		"denied after cancellation": {nil, remediationAPIError("AccessDenied"), true, errWorkerExecution},
		"answer after cancellation": {remediationAssumedRole(live), nil, true, errWorkerExecution},
		"no output":                 {nil, nil, false, errWorkerExecution},
		"no credentials":            {&sts.AssumeRoleOutput{}, nil, false, errWorkerExecution},
		"no access key":             {missing(func(c *ststypes.Credentials) { c.AccessKeyId = nil }), nil, false, errWorkerExecution},
		"no secret key":             {missing(func(c *ststypes.Credentials) { c.SecretAccessKey = nil }), nil, false, errWorkerExecution},
		"no session token":          {missing(func(c *ststypes.Credentials) { c.SessionToken = nil }), nil, false, errWorkerExecution},
		"no expiration":             {missing(func(c *ststypes.Credentials) { c.Expiration = nil }), nil, false, errWorkerExecution},
		"expired credentials":       {remediationAssumedRole(time.Now().Add(-time.Minute)), nil, false, errWorkerExecution},
		"empty access key":          {missing(func(c *ststypes.Credentials) { c.AccessKeyId = aws.String("") }), nil, false, errWorkerExecution},
	} {
		t.Run(name, func(t *testing.T) {
			assume := &remediationAssumeRoleRecorder{out: tc.out, err: tc.err}
			factory, _ := remediationProductionFactory(t, []byte("external-id-0123456789"), assume)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			clients, err := factory.RemediationClients(ctx, remediationProductionClaim())
			if err != tc.want || clients.Bedrock != nil || clients.IAM != nil || assume.calls != 1 {
				t.Fatalf("clients=%#v err=%v want=%v calls=%d", clients, err, tc.want, assume.calls)
			}
		})
	}
}
