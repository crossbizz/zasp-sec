package main

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery/transit"
)

type recoverySigningSettings struct {
	Provider   string
	Key        string
	Connection openbaoclient.Config
}

func readRecoverySigningSettings(getenv func(string) string) recoverySigningSettings {
	settings := recoverySigningSettings{Provider: getenv("ZASP_RECOVERY_SIGNING_PROVIDER"), Key: getenv("ZASP_OPENBAO_TRANSIT_KEY")}
	if settings.Key != "" || settings.Provider == "openbao" {
		settings.Connection = openbaoclient.FromEnvironment(getenv)
	}
	return settings
}

func validRecoverySigningSettings(config workerRuntimeConfig) bool {
	s := config.RecoverySigning
	if s.Provider != "" && s.Provider != "aws-kms" && s.Provider != "openbao" {
		return false
	}
	hasKMS := config.RecoverySigningKMSKeyARN != ""
	if hasKMS {
		parts := strings.Split(config.RecoverySigningKMSKeyARN, ":")
		if !workerKMSPattern.MatchString(config.RecoverySigningKMSKeyARN) || len(parts) != 6 || parts[3] != config.AWSRegion || parts[4] != config.EvidenceOwner || config.RecoverySigningKMSKeyARN == config.EvidenceKMSKeyARN {
			return false
		}
	}
	if s.Key != "" && (!transit.ValidKey(s.Key) || !s.Connection.Valid()) {
		return false
	}
	// A restore worker may retain a second, read-only verifier after cutover.
	// A backup worker only receives credentials for the selected writer.
	if s.Provider == "openbao" {
		return s.Key != "" && (!hasKMS || config.RecoveryOperationKind == "restore")
	}
	return hasKMS && (s.Key == "" || config.RecoveryOperationKind == "restore")
}

type recoveryVerifierSet struct {
	kms     recovery.ManifestVerifier
	transit recovery.ManifestVerifier
}

func (set recoveryVerifierSet) Verify(ctx context.Context, ref string, payload, sig []byte) error {
	if _, ok := recovery.EnvelopeKey(ref, ""); ok && set.kms != nil {
		return set.kms.Verify(ctx, ref, payload, sig)
	}
	if _, ok := recovery.EnvelopeKey("", ref); ok && set.transit != nil {
		return set.transit.Verify(ctx, ref, payload, sig)
	}
	return errRuntimeUnavailable
}

type recoveryAuthorities struct {
	signer   recovery.ManifestSigner
	verifier recoveryVerifierSet
	ready    func(context.Context) error
	close    func()
}

func newRecoveryAuthorities(config workerRuntimeConfig, client *kms.Client, timeout time.Duration) (recoveryAuthorities, error) {
	if !validRecoverySigningSettings(config) || client == nil {
		return recoveryAuthorities{}, errWorkerConfiguration
	}
	auth := recoveryAuthorities{close: func() {}}
	var checks []func(context.Context) error
	if arn := config.RecoverySigningKMSKeyARN; arn != "" {
		if config.RecoveryOperationKind == "backup" {
			signer, err := newRecoveryKMSSigner(client, arn, timeout)
			if err != nil {
				return recoveryAuthorities{}, err
			}
			auth.signer = signer
		} else {
			verifier, err := newRecoveryKMSVerifier(client, arn, timeout)
			if err != nil {
				return recoveryAuthorities{}, err
			}
			auth.verifier.kms = verifier
		}
		checks = append(checks, func(ctx context.Context) error {
			return readyProductionRecoverySigningKey(ctx, client, arn, config.EvidenceOwner)
		})
	}
	if key := config.RecoverySigning.Key; key != "" {
		bao, err := openbaoclient.New(config.RecoverySigning.Connection, timeout)
		if err != nil {
			return recoveryAuthorities{}, errRuntimeUnavailable
		}
		authority, err := transit.New(bao, key)
		if err != nil {
			bao.CloseIdleConnections()
			return recoveryAuthorities{}, errRuntimeUnavailable
		}
		auth.close = bao.CloseIdleConnections
		if config.RecoveryOperationKind == "backup" {
			auth.signer = authority
		} else {
			auth.verifier.transit = authority
		}
		checks = append(checks, authority.Ready)
	}
	auth.ready = func(ctx context.Context) error {
		for _, check := range checks {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
	return auth, nil
}
