package awsdiscovery

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// InventoryBinding names the one account inventory the pages of one run are
// derived from: the run, its integration, connection and subject, and the
// digest the first page put into the cursor.
type InventoryBinding struct {
	Scope                              domain.Scope
	IntegrationID, ConnectionID, JobID domain.ProductID
	Subject                            collection.SubjectBinding
	Digest                             [16]byte
}

// CollectionInventoryResumer is optional. A run reads the account inventory
// on its first page and binds every later page to it by digest: a later page
// whose inventory has another digest is refused. Reading the whole account
// again on each later page therefore can only reproduce the first read or
// fail the run. A caller that implements this interface may keep the
// inventory it returned for a binding and hand it back for a later page of
// the same binding instead of reading the account again.
//
// ResumeCollectionInventory must still verify the page's own credential
// against the provider (the caller identity and its account), with the same
// per-request authorization as any other provider request, and must return
// that credential's identity and expiry. It reports false when it holds
// nothing for the binding; the page then reads the account as before. The
// page checks what it is handed exactly as it checks a fresh read, including
// the digest.
type CollectionInventoryResumer interface {
	ResumeCollectionInventory(context.Context, []byte, InventoryBinding) (CollectionInventory, bool, error)
	RetainCollectionInventory(InventoryBinding, CollectionInventory)
}

func (api *InventoryCollectionAPI) inventoryBinding(subject collection.SubjectBinding, digest [16]byte) InventoryBinding {
	return InventoryBinding{Scope: api.authority.Scope, IntegrationID: api.authority.IntegrationID, ConnectionID: api.authority.ConnectionID, JobID: api.authority.JobID, Subject: subject, Digest: digest}
}

func callResumeInventory(resumer CollectionInventoryResumer, ctx context.Context, credential []byte, binding InventoryBinding) (inventory CollectionInventory, found bool, resultErr error) {
	defer func() {
		if recover() != nil {
			inventory, found, resultErr = CollectionInventory{}, false, ErrDenied
		}
	}()
	return resumer.ResumeCollectionInventory(ctx, credential, binding)
}

func callRetainInventory(resumer CollectionInventoryResumer, binding InventoryBinding, inventory CollectionInventory) {
	defer func() { _ = recover() }()
	resumer.RetainCollectionInventory(binding, inventory)
}
