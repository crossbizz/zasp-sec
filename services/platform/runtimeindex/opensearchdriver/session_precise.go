package opensearchdriver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/sessionsearch"
)

// ApplyPrecise writes committed V3 receipts only to the sandbox-capable target.
// It shares immutable readback and refresh checks with historical writes.
func (index *SessionIndex) ApplyPrecise(ctx context.Context, binding sessionsearch.ReceiptBinding, receiptBody, archiveBody []byte) (SessionWriteResult, error) {
	return index.applyProfile(ctx, binding, receiptBody, archiveBody, true)
}
