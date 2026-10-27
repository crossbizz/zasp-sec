package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
)

// Only a registered native repository can bridge the recovery worker to SQL.
// Callback compensation has distinct operations and cannot reuse forward proof.
func (r *NativeConnectorRepository) invokeCallbackRecovery(ctx context.Context, operation connectorCallbackRecoveryOperation, request, proof json.RawMessage) (json.RawMessage, error) {
	if !validNativeConnectorRepository(r, ctx) {
		return nil, ErrRepositoryUnavailable
	}
	var native connectormaintenance.Operation
	switch operation {
	case callbackRecoveryClaim:
		native = connectormaintenance.RecoverCallbacks
	case callbackRecoveryBefore:
		native = connectormaintenance.BeforeCallbackCompensation
	case callbackRecoverySettle:
		native = connectormaintenance.SettleCallbackRecovery
	default:
		return nil, ErrRepositoryOperation
	}
	raw, err := r.executor.Invoke(ctx, native, request, proof)
	if err != nil {
		return nil, connectorNativeError(err)
	}
	return raw, nil
}
