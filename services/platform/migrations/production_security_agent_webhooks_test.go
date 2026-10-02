package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestProductionSecurityAgentWebhooksMetadata(t *testing.T) {
	m := ProductionSecurityAgentWebhooks()
	if m.Version() != 59 || m.Name() != "production_security_agent_webhooks" || len(SecurityAgentWebhooksFingerprint()) != 64 {
		t.Fatal("webhook release identity")
	}
	up := strings.NewReplacer("-- webhook predecessor checksum", ProductionSecurityAgentExports().Checksum(), "-- webhook predecessor fingerprint", SecurityAgentExportsFingerprint()).Replace(securityAgentWebhooksUpSQL)
	sum := sha256.Sum256([]byte(up + "\x00" + securityAgentWebhooksDownSQL))
	if m.Checksum() != hex.EncodeToString(sum[:]) || strings.Contains(m.UpSQL(), "-- compiled webhook") || !strings.Contains(m.UpSQL(), m.Checksum()) || !strings.Contains(m.UpSQL(), SecurityAgentWebhooksFingerprint()) {
		t.Fatal("unbound registered source")
	}
	if ProductionSecurityAgentExports().Checksum() != "5ee183aae4e67f55c6e1ed89b2d020266b3160e0df8e3101ba51faa705f4c985" || SecurityAgentExportsFingerprint() != "8ddd2617904003772da27cdf92dd48fcc3714596d773a144f67dc8abf175ca1f" {
		t.Fatal("predecessor58 changed")
	}
	for _, r := range []*Runner{nil, {}} {
		if !errors.Is(r.UpProductionSecurityAgentWebhooks(context.Background()), ErrInvalidRunner) || !errors.Is(r.DownProductionSecurityAgentWebhooks(context.Background()), ErrInvalidRunner) {
			t.Fatal("invalid runner accepted")
		}
	}
}

func TestProductionSecurityAgentWebhooksRunnerFailsClosed(t *testing.T) {
	prior := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports())
	for _, mode := range []string{"healthy", "predecessor-drift", "final-drift"} {
		t.Run(mode, func(t *testing.T) {
			rows := append(exactReleaseRows(prior...), fakeRow{values: []any{mode != "predecessor-drift"}})
			rows = append(rows, exactReleaseRows(append(prior, ProductionSecurityAgentWebhooks())...)...)
			rows = append(rows, fakeRow{values: []any{mode != "final-drift"}})
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			runner, _ := NewRunner(db)
			err := runner.UpProductionSecurityAgentWebhooks(context.Background())
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
