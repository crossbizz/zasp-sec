package main

import (
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/endpoint-agent/internal/inventoryreport"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

// The user-context CLI performs the filesystem walk. The broker never opens
// employee paths, and queues only keyed installation references and digests.
func (b *broker) queueInventory(raw []byte, project string) error {
	next := b.store.state
	snapshots, sequence, err := inventoryreport.Parse(raw, project, b.key.Seed(), next.InventorySequence)
	if err != nil {
		return err
	}
	next.InventorySequence = sequence
	next.Inventory = copyInventory(next.Inventory)
	for _, v := range snapshots {
		var keep []endpointprotocol.Inventory
		if !*v.Complete {
			for _, old := range next.Inventory[v.Partition] {
				if old.Complete != nil && *old.Complete {
					keep = append(keep, old)
				}
			}
		}
		next.Inventory[v.Partition] = append(keep, v)
	}
	serialized, err := json.Marshal(next.Inventory)
	if err != nil || len(serialized) > maxStateBytes/2 {
		return errInvalid
	}
	if len(next.Inventory) > 128 {
		return errInvalid
	}
	return b.store.commit(next)
}

func copyInventory(source map[string][]endpointprotocol.Inventory) map[string][]endpointprotocol.Inventory {
	result := make(map[string][]endpointprotocol.Inventory, len(source))
	for id, v := range source {
		result[id] = v
	}
	return result
}

func (b *broker) ackInventory(v endpointprotocol.Inventory) error {
	next := b.store.state
	next.Inventory = copyInventory(next.Inventory)
	var left []endpointprotocol.Inventory
	for _, prev := range next.Inventory[v.Partition] {
		if prev.Generation > v.Generation {
			left = append(left, prev)
		}
	}
	if len(left) == 0 {
		delete(next.Inventory, v.Partition)
	} else {
		next.Inventory[v.Partition] = left
	}
	return b.store.commit(next)
}
