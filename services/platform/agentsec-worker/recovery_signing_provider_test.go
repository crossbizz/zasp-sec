package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
)

type checkedRecoveryVerifier struct {
	calls int
	err   error
}

func (v *checkedRecoveryVerifier) Verify(context.Context, string, []byte, []byte) error {
	v.calls++
	return v.err
}

func TestRecoveryVerifiesOnlyTheRecordedProvider(t *testing.T) {
	awsErr, baoErr := errors.New("KMS offline"), errors.New("Transit offline")
	old, active := &checkedRecoveryVerifier{err: awsErr}, &checkedRecoveryVerifier{err: baoErr}
	set := recoveryVerifierSet{kms: old, transit: active}
	ctx := context.Background()
	arn := "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555"
	ref := "openbao:transit/v2/7b43428c-21d3-4b7e-98b4-4cf7af921142"
	if set.Verify(ctx, arn, nil, nil) != awsErr || old.calls != 1 || active.calls != 0 {
		t.Fatal("AWS failure redirected")
	}
	if set.Verify(ctx, ref, nil, nil) != baoErr || old.calls != 1 || active.calls != 1 {
		t.Fatal("Transit failure redirected")
	}
	if err := set.Verify(ctx, "unknown", nil, nil); err == nil || old.calls != 1 || active.calls != 1 {
		t.Fatal("unknown reference reached provider")
	}
	if err := (recoveryVerifierSet{transit: active}).Verify(ctx, arn, nil, nil); err == nil || active.calls != 1 {
		t.Fatal("missing historical verifier silently substituted")
	}
}

func TestRecoverySigningSettingsRejectAuthorityMixups(t *testing.T) {
	const key = "7b43428c-21d3-4b7e-98b4-4cf7af921142"
	const arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555"
	base := workerRuntimeConfig{RecoveryOperationKind: "backup", AWSRegion: "us-east-1", EvidenceOwner: "123456789012", RecoverySigningKMSKeyARN: arn}
	bao := recoverySigningSettings{Provider: "openbao", Key: key, Connection: openbaoclient.Config{Address: "https://bao.example", TokenFile: "/run/bao/token"}}
	if !validRecoverySigningSettings(base) {
		t.Fatal("AWS default changed")
	}
	base.RecoverySigning = bao
	if validRecoverySigningSettings(base) {
		t.Fatal("backup worker accepted both write authorities")
	}
	base.RecoveryOperationKind = "restore"
	if !validRecoverySigningSettings(base) {
		t.Fatal("mixed historical restore rejected")
	}
	base.RecoverySigning.Provider = "aws-kms"
	if !validRecoverySigningSettings(base) {
		t.Fatal("rollback restore rejected")
	}
	base.RecoverySigning = bao
	base.RecoverySigningKMSKeyARN = ""
	base.RecoveryOperationKind = "backup"
	if !validRecoverySigningSettings(base) {
		t.Fatal("Transit backup rejected")
	}
	for name, mutate := range map[string]func(*workerRuntimeConfig){
		"wrong transport": func(c *workerRuntimeConfig) { c.RecoverySigning.Connection.Address = "http://bao.example" },
		"unscoped key":    func(c *workerRuntimeConfig) { c.RecoverySigning.Key = "../other" },
		"unknown":         func(c *workerRuntimeConfig) { c.RecoverySigning.Provider = "other" },
		"foreign historical authority": func(c *workerRuntimeConfig) {
			c.RecoveryOperationKind = "restore"
			c.RecoverySigningKMSKeyARN = arn
			c.AWSRegion = "us-west-1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if validRecoverySigningSettings(c) {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}
