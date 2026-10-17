package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type installationControlFixture struct {
	authority gatewaycontrol.Authority
	send      func(context.Context, []byte) (wire.Receipt, error)
}

func (c *installationControlFixture) InstallationAuthority(context.Context, string) (gatewaycontrol.Authority, error) {
	return c.authority, nil
}
func (c *installationControlFixture) RecordInstallation(ctx context.Context, _ string, raw []byte) (wire.Receipt, error) {
	return c.send(ctx, raw)
}
func installationWorkerFixture(t *testing.T) (*policy.GatewayPolicyCache, *installationControlFixture, *gatewayInstallationWorker, policy.GatewayPolicyEnvelope) {
	t.Helper()
	now := gatewayRuntimeTime()
	expected := gatewayRuntimeAuthority()
	private := gatewayPrivateKeyFixture()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"gateway-key-1": private.Public().(ed25519.PublicKey)})
	cache, err := policy.NewGatewayPolicyInstallationDiskCache(filepath.Join(t.TempDir(), "policy.json"), keys, expected.Binding(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cache.Close() })
	envelope := signedGatewayRuntimeEnvelope(t, private, expected, now, "closed")
	if cache.StoreInstallation(envelope, expected.CredentialID, 7) != nil {
		t.Fatal("store installation")
	}
	control := &installationControlFixture{authority: gatewaycontrol.Authority{OrganizationID: expected.OrganizationID, WorkspaceID: expected.WorkspaceID, EnvironmentID: expected.EnvironmentID, DeviceID: expected.DeviceID, CredentialID: expected.CredentialID, CredentialGeneration: 7, ExpiresAt: now.Add(time.Hour)}}
	worker, err := newGatewayInstallationWorker(cache, control, expected, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return cache, control, worker, envelope
}
func installationFixtureReceipt(t *testing.T, raw []byte, authority gatewaycontrol.Authority) wire.Receipt {
	t.Helper()
	var o wire.Observation
	var err error
	o, err = wire.ParseObservation(raw)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: wire.Digest(raw), OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, CredentialID: authority.CredentialID, CredentialGeneration: authority.CredentialGeneration, Disposition: "recorded", RepresentativeSHA256: wire.Digest(raw), RepresentativeSequence: o.Sequence, RepresentativeInstalledObservedAt: o.InstalledObservedAt, RepresentativeRecordedAt: o.InstalledObservedAt}
}
func TestGatewayInstallationWorkerRetriesOriginalBodyAndPersistsConfirmation(t *testing.T) {
	cache, control, worker, _ := installationWorkerFixture(t)
	var bodies [][]byte
	control.send = func(_ context.Context, raw []byte) (wire.Receipt, error) {
		bodies = append(bodies, append([]byte(nil), raw...))
		if len(bodies) == 1 {
			return wire.Receipt{}, errors.New("unknown remote commit")
		}
		return installationFixtureReceipt(t, raw, control.authority), nil
	}
	if worker.SyncOnce(context.Background()) == nil {
		t.Fatal("unknown send reported success")
	}
	if worker.SyncOnce(context.Background()) != nil {
		t.Fatal("confirmed retry failed")
	}
	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("retry changed original testimony")
	}
	raw, err := cache.PendingInstallation(control.authority.CredentialID, 7)
	if err != nil || len(raw) != 0 {
		t.Fatal("confirmed receipt not durable", err)
	}
}
func TestGatewayInstallationWorkerUnknownOldResponseCannotClearNewer(t *testing.T) {
	cache, control, worker, envelope := installationWorkerFixture(t)
	control.send = func(_ context.Context, raw []byte) (wire.Receipt, error) {
		input := policy.GatewayPolicySigningInput{KeyID: envelope.KeyID, Binding: gatewayRuntimeAuthority().Binding(), Sequence: envelope.Sequence + 1, PolicyVersion: envelope.PolicyVersion + 1, Now: gatewayRuntimeTime(), IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt, FailureMode: envelope.FailureMode, Policies: envelope.Policies}
		next, err := policy.SignGatewayPolicyEnvelope(input, gatewayPrivateKeyFixture())
		if err != nil {
			t.Fatal(err)
		}
		// Exercise the actual selected refresh composition while delivery of the
		// previous immutable body is unresolved, not a parallel cache-only surrogate.
		expected := gatewayRuntimeAuthority()
		connected := &installationRuntimeControlFixture{gatewayControlStub: &gatewayControlStub{authority: expected, envelope: &next}, selected: control}
		runtime, err := newGatewayRuntime(gatewayRuntimeConfig{InstallationACKEnabled: true, Control: connected, Cache: cache, ExpectedAuthority: expected, CredentialID: expected.CredentialID, BootstrapFailureMode: "closed", MaximumPendingEvents: 8, Now: gatewayRuntimeTime})
		if err != nil || runtime.SyncOnce(context.Background()) != nil {
			t.Fatal("actual selected policy refresh blocked by unresolved ACK", err)
		}
		return installationFixtureReceipt(t, raw, control.authority), nil
	}
	_ = worker.SyncOnce(context.Background())
	raw, err := cache.PendingInstallation(control.authority.CredentialID, 7)
	if err != nil || len(raw) == 0 {
		t.Fatal("older response cleared new source", err)
	}
}
func TestGatewayInstallationWorkerCurrentAuthorityAndReceiptScope(t *testing.T) {
	cache, control, worker, _ := installationWorkerFixture(t)
	sent := 0
	control.send = func(_ context.Context, raw []byte) (wire.Receipt, error) {
		sent++
		receipt := installationFixtureReceipt(t, raw, control.authority)
		receipt.DeviceID = gatewayRuntimeID(9)
		return receipt, nil
	}
	if worker.SyncOnce(context.Background()) == nil {
		t.Fatal("foreign receipt accepted")
	}
	raw, _ := cache.PendingInstallation(control.authority.CredentialID, 7)
	if len(raw) == 0 {
		t.Fatal("foreign receipt cleared testimony")
	}
	control.authority.ExpiresAt = gatewayRuntimeTime()
	if worker.SyncOnce(context.Background()) == nil || sent != 1 {
		t.Fatal("expired authority sent testimony")
	}
	control.authority.ExpiresAt = gatewayRuntimeTime().Add(time.Hour)
	control.authority.CredentialGeneration = 8
	if worker.SyncOnce(context.Background()) != nil || sent != 1 {
		t.Fatal("rotation relabeled old observation")
	}
}
func TestGatewayInstallationWorkerCancellationJoinsBlockedDelivery(t *testing.T) {
	_, control, worker, _ := installationWorkerFixture(t)
	entered := make(chan struct{})
	var once sync.Once
	control.send = func(ctx context.Context, _ []byte) (wire.Receipt, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return wire.Receipt{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx, time.Millisecond, time.Second) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("delivery did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery worker did not join cancellation")
	}
}

type installationRuntimeControlFixture struct {
	*gatewayControlStub
	selected *installationControlFixture
}

func (c *installationRuntimeControlFixture) InstallationAuthority(ctx context.Context, id string) (gatewaycontrol.Authority, error) {
	return c.selected.InstallationAuthority(ctx, id)
}
func (c *installationRuntimeControlFixture) RecordInstallation(ctx context.Context, id string, raw []byte) (wire.Receipt, error) {
	return c.selected.RecordInstallation(ctx, id, raw)
}
