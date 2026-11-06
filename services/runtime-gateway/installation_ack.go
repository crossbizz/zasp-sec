package main

import (
	"context"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// This optional capability keeps the legacy control plane and decision replay
// authority unchanged. The selected path retains the authenticated generation.
type gatewayInstallationControl interface {
	InstallationAuthority(context.Context, string) (gatewaycontrol.Authority, error)
	RecordInstallation(context.Context, string, []byte) (wire.Receipt, error)
}

func gatewayInstallationLegacyAuthority(value gatewaycontrol.Authority) gatewayAuthority {
	return gatewayAuthority{OrganizationID: value.OrganizationID, WorkspaceID: value.WorkspaceID, EnvironmentID: value.EnvironmentID, DeviceID: value.DeviceID, CredentialID: value.CredentialID, ReplayFloor: value.ReplayFloor}
}
func validGatewayInstallationAuthority(value gatewaycontrol.Authority, expected gatewayAuthority, now time.Time) bool {
	return validGatewayTime(now) && validGatewayAuthority(gatewayInstallationLegacyAuthority(value), expected.CredentialID) && sameGatewayAuthority(gatewayInstallationLegacyAuthority(value), expected) && value.CredentialGeneration > 0 && value.CredentialGeneration <= math.MaxInt64 && validGatewayTime(value.ExpiresAt) && value.ExpiresAt.After(now)
}

type gatewayInstallationWorker struct {
	cache          *policy.GatewayPolicyCache
	control        gatewayInstallationControl
	expected       gatewayAuthority
	now            func() time.Time
	syncMu         sync.Mutex
	lifecycleMu    sync.Mutex
	closed         bool
	cancel         context.CancelFunc
	done           chan struct{}
	deliveryErrors atomic.Uint64
	confirmed      atomic.Uint64
}

func newGatewayInstallationWorker(cache *policy.GatewayPolicyCache, control gatewayInstallationControl, expected gatewayAuthority, now func() time.Time) (*gatewayInstallationWorker, error) {
	if cache == nil || !cache.InstallationEnabled() || invalidRuntimeValue(control) || !validGatewayAuthority(expected, expected.CredentialID) || now == nil || !validGatewayTime(now()) {
		return nil, errGatewayRuntime
	}
	return &gatewayInstallationWorker{cache: cache, control: control, expected: expected, now: now}, nil
}
func (worker *gatewayInstallationWorker) SyncOnce(ctx context.Context) (resultErr error) {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRuntime
	}
	defer func() {
		if recover() != nil {
			resultErr = errGatewayRuntime
		}
		if resultErr != nil {
			worker.deliveryErrors.Add(1)
		}
	}()
	worker.syncMu.Lock()
	defer worker.syncMu.Unlock()
	authority, err := worker.control.InstallationAuthority(ctx, worker.expected.CredentialID)
	if err != nil || !validGatewayInstallationAuthority(authority, worker.expected, worker.now()) {
		return errGatewayRuntime
	}
	raw, err := worker.cache.PendingInstallation(authority.CredentialID, authority.CredentialGeneration)
	if err != nil {
		return errGatewayRuntime
	}
	if len(raw) == 0 {
		return nil
	}
	observation, err := wire.ParseObservation(raw)
	if err != nil {
		return errGatewayRuntime
	}
	// Delivery is separate from policy refresh. The exact immutable body can be
	// retried after an unknown commit; the server alone decides its disposition.
	receipt, err := worker.control.RecordInstallation(ctx, authority.CredentialID, raw)
	binding := wire.Binding{OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, CredentialID: authority.CredentialID}
	if err != nil || !wire.ReceiptMatches(receipt, observation, wire.Digest(raw), binding) {
		return errGatewayRuntime
	}
	// Comparison and durable clearing are one cache critical section. A late
	// response cannot erase a more recent policy or another credential's witness.
	if worker.cache.ConfirmInstallation(raw) != nil {
		return errGatewayRuntime
	}
	worker.confirmed.Add(1)
	return nil
}
func (worker *gatewayInstallationWorker) prepare(ctx context.Context, interval, timeout time.Duration) (context.Context, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil || interval < time.Millisecond || interval > 5*time.Minute || timeout < time.Millisecond || timeout > 30*time.Second {
		return nil, errGatewayRuntime
	}
	worker.lifecycleMu.Lock()
	defer worker.lifecycleMu.Unlock()
	if worker.closed || worker.done != nil {
		return nil, errGatewayRuntime
	}
	child, cancel := context.WithCancel(ctx)
	worker.cancel = cancel
	worker.done = make(chan struct{})
	return child, nil
}
func (worker *gatewayInstallationWorker) loop(ctx context.Context, interval, timeout time.Duration) error {
	defer close(worker.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		operation, cancel := context.WithTimeout(ctx, timeout)
		_ = worker.SyncOnce(operation)
		cancel()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (worker *gatewayInstallationWorker) Run(ctx context.Context, interval, timeout time.Duration) error {
	child, err := worker.prepare(ctx, interval, timeout)
	if err != nil {
		return err
	}
	return worker.loop(child, interval, timeout)
}
func (worker *gatewayInstallationWorker) Start(ctx context.Context, interval, timeout time.Duration) error {
	child, err := worker.prepare(ctx, interval, timeout)
	if err != nil {
		return err
	}
	go func() { _ = worker.loop(child, interval, timeout) }()
	return nil
}
func (worker *gatewayInstallationWorker) Close() error {
	if worker == nil {
		return nil
	}
	worker.lifecycleMu.Lock()
	worker.closed = true
	cancel, done := worker.cancel, worker.done
	worker.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	return nil
}
func (worker *gatewayInstallationWorker) Metrics() string {
	if worker == nil {
		return ""
	}
	return "zasp_gateway_installation_ack_delivery_errors_total " + strconv.FormatUint(worker.deliveryErrors.Load(), 10) + "\nzasp_gateway_installation_ack_confirmed_total " + strconv.FormatUint(worker.confirmed.Load(), 10) + "\n"
}

func (control gatewayHTTPControl) InstallationAuthority(ctx context.Context, id string) (gatewaycontrol.Authority, error) {
	if control.next == nil {
		return gatewaycontrol.Authority{}, errGatewayRuntime
	}
	value, err := control.next.Authority(ctx, id)
	if err != nil {
		return gatewaycontrol.Authority{}, errGatewayRuntime
	}
	return value, nil
}
func (control gatewayHTTPControl) RecordInstallation(ctx context.Context, id string, raw []byte) (wire.Receipt, error) {
	next, ok := control.next.(interface {
		RecordInstallation(context.Context, string, []byte) (wire.Receipt, error)
	})
	if !ok {
		return wire.Receipt{}, errGatewayRuntime
	}
	return next.RecordInstallation(ctx, id, raw)
}
func (control boundGatewayControl) InstallationAuthority(ctx context.Context, id string) (gatewaycontrol.Authority, error) {
	next, ok := control.next.(gatewayInstallationControl)
	if !ok || id != control.expected.CredentialID {
		return gatewaycontrol.Authority{}, errGatewayRuntime
	}
	value, err := next.InstallationAuthority(ctx, id)
	if err != nil || !sameGatewayAuthority(gatewayInstallationLegacyAuthority(value), control.expected) {
		return gatewaycontrol.Authority{}, errGatewayRuntime
	}
	return value, nil
}
func (control boundGatewayControl) RecordInstallation(ctx context.Context, id string, raw []byte) (wire.Receipt, error) {
	next, ok := control.next.(gatewayInstallationControl)
	if !ok || id != control.expected.CredentialID {
		return wire.Receipt{}, errGatewayRuntime
	}
	return next.RecordInstallation(ctx, id, raw)
}
