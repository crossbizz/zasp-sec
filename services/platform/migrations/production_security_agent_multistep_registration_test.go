package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type multistepRunner interface {
	UpProductionSecurityAgentMultistep(context.Context) error
	DownProductionSecurityAgentMultistep(context.Context) error
}

func TestSecurityAgentMultistepRegisteredTransactionBoundaries(t *testing.T) {
	prior := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks(), ProductionDiscoveryScheduleReplay())
	current := append(append([]Metadata(nil), prior...), ProductionSecurityAgentMultistep())
	for _, mode := range []string{"up", "up-predecessor-drift", "up-final-drift", "retry", "retry-drift", "down", "down-current-drift", "down-restored-drift"} {
		t.Run(mode, func(t *testing.T) {
			var rows []Row
			switch {
			case strings.HasPrefix(mode, "up"):
				rows = append([]Row{fakeRow{values: []any{int64(60)}}}, exactReleaseRows(prior...)...)
				rows = append(rows, fakeRow{values: []any{mode != "up-predecessor-drift"}})
				rows = append(rows, exactReleaseRows(current...)...)
				rows = append(rows, fakeRow{values: []any{mode != "up-final-drift"}})
			case strings.HasPrefix(mode, "retry"):
				rows = append([]Row{fakeRow{values: []any{int64(61)}}}, exactReleaseRows(current...)...)
				rows = append(rows, fakeRow{values: []any{mode != "retry-drift"}})
			default:
				rows = append(exactReleaseRows(current...), fakeRow{values: []any{mode != "down-current-drift"}})
				rows = append(rows, exactReleaseRows(prior...)...)
				rows = append(rows, fakeRow{values: []any{mode != "down-restored-drift"}})
			}
			db := &fakeDatabase{transaction: &fakeTransaction{rows: rows}}
			r, _ := NewRunner(db)
			var err error
			if strings.HasPrefix(mode, "down") {
				err = r.DownProductionSecurityAgentMultistep(context.Background())
			} else {
				err = r.UpProductionSecurityAgentMultistep(context.Background())
			}
			healthy := !strings.Contains(mode, "drift")
			if (err == nil) != healthy || contains(db.events, "commit") != healthy {
				t.Fatalf("mode=%s err=%v commit=%t", mode, err, contains(db.events, "commit"))
			}
			if !healthy && !errors.Is(err, ErrInvalidState) {
				t.Fatal("wrong refusal", err)
			}
			events := strings.Join(db.events, "\n")
			if healthy && strings.HasPrefix(mode, "up") && !strings.Contains(events, "args:"+ProductionSecurityAgentMultistep().Checksum()+","+SecurityAgentMultistepRegisteredFingerprint()) {
				t.Fatal("shared metadata did not bind compiled registered identity")
			}
			if strings.HasPrefix(mode, "retry") && strings.Contains(events, "exec:INSERT INTO public.zasp_schema_metadata") {
				t.Fatal("retry rewrote shared identity")
			}
		})
	}
}

func TestSecurityAgentMultistepRegisteredRunner(t *testing.T) {
	for _, r := range []*Runner{nil, {}} {
		methods, ok := any(r).(multistepRunner)
		if !ok {
			t.Fatal("release61 has no registered Runner methods")
		}
		if !errors.Is(methods.UpProductionSecurityAgentMultistep(context.Background()), ErrInvalidRunner) || !errors.Is(methods.DownProductionSecurityAgentMultistep(context.Background()), ErrInvalidRunner) {
			t.Fatal("invalid runner accepted")
		}
	}
}

func TestSecurityAgentMultistepRegisteredVersion(t *testing.T) {
	prior := append(productionAuditExportsPredecessors(), ProductionAuditExports(), ProductionSecurityAgentBudgets(), ProductionSecurityAgentRunContext(), ProductionSecurityAgentExistingTests(), ProductionCompliance(), ProductionSecurityAgentAttackLab(), ProductionSecurityAgentExports(), ProductionSecurityAgentWebhooks(), ProductionDiscoveryScheduleReplay(), ProductionSecurityAgentMultistep())
	for _, drift := range []bool{false, true} {
		if drift {
			prior[60].checksum = "drift"
		}
		db := &fakeDatabase{rows: append([]Row{fakeRow{values: []any{true}}}, exactReleaseRows(prior...)...)}
		r, _ := NewRunner(db)
		got, err := r.Version(context.Background())
		if !drift && (got != 61 || err != nil) {
			t.Fatalf("registered61 version=%d err=%v", got, err)
		}
		if drift && !errors.Is(err, ErrInvalidState) {
			t.Fatal("drift accepted", err)
		}
	}
}
