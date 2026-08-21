package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

const gatewayEvidenceRecordInterval = 100 * time.Millisecond

type gatewayHTTPClient interface {
	Ready(context.Context) error
	Authority(context.Context, string) (gatewaycontrol.Authority, error)
	Policy(context.Context, string, uint64) (*policy.GatewayPolicyEnvelope, error)
	Record(context.Context, gatewaycontrol.DecisionEvent) error
	Close() error
}

type gatewayHTTPClientFactory func(gatewaycontrol.HTTPClientConfig) (gatewayHTTPClient, error)

type gatewayHTTPControl struct {
	next gatewayHTTPClient
}

func (control gatewayHTTPControl) Ready(ctx context.Context) error {
	if control.next == nil || control.next.Ready(ctx) != nil {
		return errGatewayRuntime
	}
	return nil
}

func (control gatewayHTTPControl) Authority(ctx context.Context, credentialID string) (gatewayAuthority, error) {
	if control.next == nil {
		return gatewayAuthority{}, errGatewayRuntime
	}
	value, err := control.next.Authority(ctx, credentialID)
	if err != nil {
		return gatewayAuthority{}, errGatewayRuntime
	}
	authority := gatewayAuthority{
		OrganizationID: value.OrganizationID,
		WorkspaceID:    value.WorkspaceID,
		EnvironmentID:  value.EnvironmentID,
		DeviceID:       value.DeviceID,
		CredentialID:   value.CredentialID,
		ReplayFloor:    value.ReplayFloor,
	}
	if !validGatewayAuthority(authority, credentialID) {
		return gatewayAuthority{}, errGatewayRuntime
	}
	return authority, nil
}

func (control gatewayHTTPControl) Policy(ctx context.Context, credentialID string, after uint64) (*policy.GatewayPolicyEnvelope, error) {
	if control.next == nil {
		return nil, errGatewayRuntime
	}
	value, err := control.next.Policy(ctx, credentialID, after)
	if err != nil {
		return nil, errGatewayRuntime
	}
	return value, nil
}

func (control gatewayHTTPControl) Record(ctx context.Context, event gatewayDecisionEvent) error {
	if control.next == nil {
		return errGatewayRuntime
	}
	value := gatewaycontrol.DecisionEvent{
		CredentialID: event.CredentialID, DeviceID: event.DeviceID, EventID: event.EventID,
		ExpectedFloor: event.ExpectedFloor, NextFloor: event.NextFloor, PolicyVersion: event.PolicyVersion,
		Decision: event.Decision, ActionKind: event.ActionKind, Classification: cloneGatewayStrings(event.Classification), OccurredAt: event.OccurredAt,
	}
	if err := control.next.Record(ctx, value); err != nil {
		if errors.Is(err, gatewaycontrol.ErrRecordExpired) {
			return errGatewayRecordExpired
		}
		return errGatewayRuntime
	}
	return nil
}

type boundGatewayControl struct {
	next     gatewayControlPlane
	expected gatewayAuthority
}

func (control boundGatewayControl) Ready(ctx context.Context) error {
	if control.next == nil {
		return errGatewayRuntime
	}
	return control.next.Ready(ctx)
}

func (control boundGatewayControl) Authority(ctx context.Context, credentialID string) (gatewayAuthority, error) {
	if control.next == nil || credentialID != control.expected.CredentialID {
		return gatewayAuthority{}, errGatewayRuntime
	}
	authority, err := control.next.Authority(ctx, credentialID)
	if err != nil || !sameGatewayAuthority(authority, control.expected) {
		return gatewayAuthority{}, errGatewayRuntime
	}
	return authority, nil
}

func (control boundGatewayControl) Policy(ctx context.Context, credentialID string, afterSequence uint64) (*policy.GatewayPolicyEnvelope, error) {
	if control.next == nil || credentialID != control.expected.CredentialID {
		return nil, errGatewayRuntime
	}
	return control.next.Policy(ctx, credentialID, afterSequence)
}

func (control boundGatewayControl) Record(ctx context.Context, event gatewayDecisionEvent) error {
	if control.next == nil || event.CredentialID != control.expected.CredentialID || event.DeviceID != control.expected.DeviceID {
		return errGatewayRuntime
	}
	return control.next.Record(ctx, event)
}

type productionGatewayDependencies struct {
	Handler               http.Handler
	Ready                 func(context.Context) error
	Metrics               func() string
	AcknowledgeQuarantine func(context.Context, gatewayQuarantineAcknowledgment) error
	Run                   func(context.Context) error
	Drain                 func(context.Context) error
	Close                 func() error
}

func buildProductionGatewayDependencies(ctx context.Context, config productionGatewayConfig) (productionGatewayDependencies, error) {
	return buildProductionGatewayDependenciesWithFactory(ctx, config, func(clientConfig gatewaycontrol.HTTPClientConfig) (gatewayHTTPClient, error) {
		return gatewaycontrol.NewHTTPClient(clientConfig)
	})
}

func buildProductionGatewayDependenciesWithFactory(ctx context.Context, config productionGatewayConfig, factory gatewayHTTPClientFactory) (productionGatewayDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validProductionGatewayConfig(config) {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	if factory == nil {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	credential, err := loadGatewayCredential(config.PrivateKeyFile, config.CredentialID)
	if err != nil {
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	client, err := factory(gatewaycontrol.HTTPClientConfig{
		BaseURL: config.ControlPlaneURL, OrganizationID: config.OrganizationID, WorkspaceID: config.WorkspaceID,
		EnvironmentID: config.EnvironmentID, DeviceID: config.DeviceID, CredentialID: config.CredentialID,
		KeyID: credential.KeyID, PrivateKey: credential.PrivateKey, OperationTimeout: config.OperationTimeout, Clock: gatewayUTCNow,
	})
	credential.Destroy()
	if err != nil || client == nil {
		if client != nil {
			_ = client.Close()
		}
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	failClient := func() (productionGatewayDependencies, error) {
		_ = client.Close()
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	keys, err := loadGatewayPolicyKeys(config.PolicyKeysFile)
	if err != nil {
		return failClient()
	}
	expected := gatewayAuthority{OrganizationID: config.OrganizationID, WorkspaceID: config.WorkspaceID, EnvironmentID: config.EnvironmentID, DeviceID: config.DeviceID, CredentialID: config.CredentialID}
	cache, err := policy.NewGatewayPolicyDiskCache(config.PolicyCacheFile, keys, expected.Binding(), gatewayUTCNow)
	if err != nil {
		return failClient()
	}
	failCache := func() (productionGatewayDependencies, error) {
		_ = cache.Close()
		_ = client.Close()
		return productionGatewayDependencies{}, errRuntimeUnavailable
	}
	evidence, err := newGatewayEvidenceDiskStore(config.EvidenceStoreDirectory, expected, config.MaximumPendingEvents, config.EvidenceMaximumBytes)
	if err != nil {
		return failCache()
	}
	failEvidence := func() (productionGatewayDependencies, error) {
		_ = evidence.Close()
		return failCache()
	}
	control := boundGatewayControl{next: gatewayHTTPControl{next: client}, expected: expected}
	runtime, err := newGatewayRuntime(gatewayRuntimeConfig{
		Control: control, Cache: cache, Evidence: evidence, ExpectedAuthority: expected, CredentialID: config.CredentialID, BootstrapFailureMode: config.BootstrapFailureMode,
		MaximumPendingEvents: config.MaximumPendingEvents, Now: gatewayUTCNow,
	})
	if err != nil {
		return failEvidence()
	}
	// A cold control plane must not prevent deterministic local failure-mode
	// enforcement. A successful refresh is required only to emit durable events.
	_ = runtime.SyncOnce(ctx)
	handler, err := newGatewayHandler(runtime, config.MaximumRequestBytes)
	if err != nil {
		return failEvidence()
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			if err := evidence.Close(); err != nil {
				closeErr = errRuntimeUnavailable
			}
			if err := cache.Close(); err != nil {
				closeErr = errRuntimeUnavailable
			}
			if err := client.Close(); err != nil {
				closeErr = errRuntimeUnavailable
			}
		})
		return closeErr
	}
	return productionGatewayDependencies{
		Handler:               handler,
		Ready:                 runtime.Ready,
		Metrics:               runtime.Metrics,
		AcknowledgeQuarantine: runtime.AcknowledgeQuarantine,
		Run: func(runCtx context.Context) error {
			return runtime.Run(runCtx, config.SyncInterval, gatewayEvidenceRecordInterval)
		},
		Drain: runtime.Drain,
		Close: closeDependencies,
	}, nil
}

func gatewayUTCNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

var _ gatewayControlPlane = boundGatewayControl{}
var _ gatewayControlPlane = gatewayHTTPControl{}
