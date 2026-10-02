package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestProductionDiscoveryScheduleReplayMetadata(t *testing.T) {
	m := ProductionDiscoveryScheduleReplay()
	if m.Version() != 60 || m.Name() != "production_discovery_schedule_replay" || len(DiscoveryScheduleReplayFingerprint()) != 64 {
		t.Fatal("schedule replay release identity")
	}
	up := strings.NewReplacer("-- schedule replay predecessor checksum", ProductionSecurityAgentWebhooks().Checksum(), "-- schedule replay predecessor fingerprint", SecurityAgentWebhooksFingerprint()).Replace(discoveryScheduleReplayUpSQL)
	sum := sha256.Sum256([]byte(up + "\x00" + discoveryScheduleReplayDownSQL))
	if m.Checksum() != hex.EncodeToString(sum[:]) || strings.Contains(m.UpSQL(), "-- compiled schedule replay") || !strings.Contains(m.UpSQL(), m.Checksum()) || !strings.Contains(m.UpSQL(), DiscoveryScheduleReplayFingerprint()) {
		t.Fatal("unbound registered source")
	}
	if ProductionSecurityAgentWebhooks().Checksum() != "f5021eaf0e9954cba9ab16b4ae1e0ee57e9ea85d909b44eeffe6ac853d0073f4" || SecurityAgentWebhooksFingerprint() != "e89317deca2aabbeb6e35bbe303d8245ba8ea0dbda6351c2d1b2e458e79842f1" {
		t.Fatal("predecessor59 changed")
	}
	for _, r := range []*Runner{nil, {}} {
		if !errors.Is(r.UpProductionDiscoveryScheduleReplay(context.Background()), ErrInvalidRunner) || !errors.Is(r.DownProductionDiscoveryScheduleReplay(context.Background()), ErrInvalidRunner) {
			t.Fatal("invalid runner accepted")
		}
	}
}

func TestProductionDiscoveryScheduleReplayRunnerFailsClosed(t *testing.T) {
	prior := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks())
	for _, mode := range []string{"healthy", "predecessor-drift", "final-drift"} {
		t.Run(mode, func(t *testing.T) {
			rows := append(exactReleaseRows(prior...), fakeRow{values: []any{mode != "predecessor-drift"}})
			rows = append(rows, exactReleaseRows(append(prior, ProductionDiscoveryScheduleReplay())...)...)
			rows = append(rows, fakeRow{values: []any{mode != "final-drift"}})
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			runner, _ := NewRunner(db)
			err := runner.UpProductionDiscoveryScheduleReplay(context.Background())
			if (err == nil) != (mode == "healthy") {
				t.Fatalf("migration outcome=%v", err)
			}
			committed := false
			for _, event := range db.events {
				if event == "commit" {
					committed = true
				}
			}
			if committed != (mode == "healthy") {
				t.Fatal("drift committed")
			}
		})
	}
}

func TestProductionDiscoveryScheduleReplayDownRequiresExactIdentity(t *testing.T) {
	prior := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks())
	for _, mode := range []string{"healthy", "current-drift", "restored-drift"} {
		t.Run(mode, func(t *testing.T) {
			rows := append(exactReleaseRows(append(prior, ProductionDiscoveryScheduleReplay())...), fakeRow{values: []any{mode != "current-drift"}})
			rows = append(rows, exactReleaseRows(prior...)...)
			rows = append(rows, fakeRow{values: []any{mode != "restored-drift"}})
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			runner, _ := NewRunner(db)
			err := runner.DownProductionDiscoveryScheduleReplay(context.Background())
			if (err == nil) != (mode == "healthy") {
				t.Fatalf("rollback outcome=%v", err)
			}
			committed := false
			for _, event := range db.events {
				if event == "commit" {
					committed = true
				}
			}
			if committed != (mode == "healthy") {
				t.Fatal("rollback drift committed")
			}
		})
	}
}
