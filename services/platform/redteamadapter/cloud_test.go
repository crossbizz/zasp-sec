package redteamadapter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type identityAPIStub struct {
	output *sts.GetCallerIdentityOutput
	calls  int
}

func (stub *identityAPIStub) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	stub.calls++
	return stub.output, nil
}

func TestCloudAuthorityReadinessBindsExactRoleIdentityAndSecretAccess(t *testing.T) {
	identity := &identityAPIStub{output: &sts.GetCallerIdentityOutput{Account: aws.String("123456789012"), Arn: aws.String("arn:aws:sts::123456789012:assumed-role/zasp-red-team-adapter/zasp-red-team-adapter")}}
	secrets := &secretsAPIStub{output: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte(strings.Repeat("r", 64))}}
	resolver, err := NewSecretsCredentialResolver(secrets, "zasp/red-team/targets", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := CloudConfig{Region: "us-west-2", RoleARN: "arn:aws:iam::123456789012:role/zasp-red-team-adapter", WebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", ReadinessCredentialReference: "ref:red-team/readiness-0001", Timeout: time.Second, Clock: func() time.Time { return time.Now().UTC() }}
	authority := &CloudAuthority{credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "A", SecretAccessKey: "B"}, nil
	}), identity: identity, resolver: resolver, config: config}
	if err := authority.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	if identity.calls != 1 || secrets.input == nil || *secrets.input.SecretId != "zasp/red-team/targets/readiness-0001" {
		t.Fatalf("identity calls=%d secret input=%#v", identity.calls, secrets.input)
	}
	identity.output.Arn = aws.String("arn:aws:sts::123456789012:assumed-role/administrator/zasp-red-team-adapter")
	if err := authority.Ready(context.Background()); err == nil {
		t.Fatal("role-drifted authority became ready")
	}
}

func TestCloudConfigurationRejectsAmbientOrBroadAuthority(t *testing.T) {
	valid := CloudConfig{Region: "us-west-2", RoleARN: "arn:aws:iam::123456789012:role/zasp-red-team-adapter", WebIdentityTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", ReadinessCredentialReference: "ref:red-team/readiness-0001", Timeout: time.Second, Clock: func() time.Time { return time.Now().UTC() }}
	if !validCloudConfig(valid) {
		t.Fatal("valid cloud configuration rejected")
	}
	for name, mutate := range map[string]func(*CloudConfig){
		"missing region":        func(value *CloudConfig) { value.Region = "" },
		"ambient role":          func(value *CloudConfig) { value.RoleARN = "" },
		"ambient token":         func(value *CloudConfig) { value.WebIdentityTokenFile = "" },
		"foreign secret":        func(value *CloudConfig) { value.ReadinessCredentialReference = "ref:github/installation/1" },
		"unbounded timeout":     func(value *CloudConfig) { value.Timeout = time.Minute },
		"nonproduction account": func(value *CloudConfig) { value.RoleARN = "arn:aws:iam::*:role/zasp-red-team-adapter" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if validCloudConfig(candidate) {
				t.Fatalf("configuration %#v accepted", candidate)
			}
		})
	}
}
