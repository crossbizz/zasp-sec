package main

import (
	"bytes"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
)

const (
	// A run's pages follow each other within minutes. An inventory is held
	// for the run that read it only, and only this long.
	discoveryAWSInventoryRetentionTime    = 30 * time.Minute
	discoveryAWSInventoryRetentionEntries = 16
	discoveryAWSInventoryRetentionBytes   = 8 << 20
)

// discoveryAWSInventoryRetention keeps, in this process only, the account
// inventory a run's first page read, so the run's later pages need not read
// the whole account again. An entry is addressed by the run, integration,
// connection, subject and the digest in the page cursor, so it can serve only
// later pages of the run that read it; another run always reads the account
// itself. It holds the two analyzer sources (role, policy and instance
// descriptions) and the account id: no credential and no caller identity.
// A process that does not hold the entry (another worker, a restart, an
// expired or evicted entry, an inventory over the size limit) reads the
// account as before.
type discoveryAWSInventoryRetention struct {
	mu      sync.Mutex
	clock   func() time.Time
	entries map[awsdiscovery.InventoryBinding]discoveryAWSRetainedInventory
}

type discoveryAWSRetainedInventory struct {
	accountID            string
	cartography, prowler []byte
	keptAt               time.Time
}

func newDiscoveryAWSInventoryRetention(clock func() time.Time) *discoveryAWSInventoryRetention {
	return &discoveryAWSInventoryRetention{clock: clock, entries: make(map[awsdiscovery.InventoryBinding]discoveryAWSRetainedInventory)}
}

func (retention *discoveryAWSInventoryRetention) find(binding awsdiscovery.InventoryBinding) (discoveryAWSRetainedInventory, bool) {
	if retention == nil || retention.clock == nil || !validDiscoveryAWSInventoryBinding(binding) {
		return discoveryAWSRetainedInventory{}, false
	}
	retention.mu.Lock()
	defer retention.mu.Unlock()
	retention.expire()
	held, found := retention.entries[binding]
	return held, found
}

func (retention *discoveryAWSInventoryRetention) keep(binding awsdiscovery.InventoryBinding, inventory awsdiscovery.CollectionInventory) {
	if retention == nil || retention.clock == nil || !validDiscoveryAWSInventoryBinding(binding) || inventory.Identity.AccountID == "" || inventory.Identity.AccountID != binding.Subject.ID ||
		len(inventory.CartographySource) == 0 || len(inventory.ProwlerSource) == 0 || len(inventory.CartographySource)+len(inventory.ProwlerSource) > discoveryAWSInventoryRetentionBytes {
		return
	}
	retention.mu.Lock()
	defer retention.mu.Unlock()
	retention.expire()
	if _, present := retention.entries[binding]; !present && len(retention.entries) >= discoveryAWSInventoryRetentionEntries {
		var oldest awsdiscovery.InventoryBinding
		var oldestAt time.Time
		for key, entry := range retention.entries {
			if oldestAt.IsZero() || entry.keptAt.Before(oldestAt) {
				oldest, oldestAt = key, entry.keptAt
			}
		}
		delete(retention.entries, oldest)
	}
	retention.entries[binding] = discoveryAWSRetainedInventory{accountID: inventory.Identity.AccountID, cartography: bytes.Clone(inventory.CartographySource), prowler: bytes.Clone(inventory.ProwlerSource), keptAt: retention.clock()}
}

func (retention *discoveryAWSInventoryRetention) expire() {
	now := retention.clock()
	for key, entry := range retention.entries {
		if !now.Before(entry.keptAt.Add(discoveryAWSInventoryRetentionTime)) || now.Before(entry.keptAt) {
			delete(retention.entries, key)
		}
	}
}

func validDiscoveryAWSInventoryBinding(binding awsdiscovery.InventoryBinding) bool {
	return binding.Scope.Validate() == nil && !binding.IntegrationID.IsZero() && !binding.ConnectionID.IsZero() && !binding.JobID.IsZero() && binding.Subject.Kind == "aws_account" && binding.Subject.ID != "" && binding.Digest != [16]byte{}
}
