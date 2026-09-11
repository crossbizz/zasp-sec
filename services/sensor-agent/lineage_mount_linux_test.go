package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The host harness provisions one disposable Docker volume and mounts its
// initialized subdirectories with the chart's per-role write permissions. Each
// phase runs in a fresh container; no production test mode is introduced.
func TestLineageReadOnlyMountLifecycle(t *testing.T) {
	phase := os.Getenv("ZASP_TEST_LINEAGE_MOUNT_PHASE")
	if phase == "" {
		t.Skip("requires isolated per-role mount composition")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	round, err := parseBoundedInteger(os.Getenv("ZASP_TEST_LINEAGE_MOUNT_ROUND"), 1, 3)
	if err != nil {
		t.Fatal("invalid fixture round")
	}
	consumer := phase == "process" || phase == "retire" || phase == "release"
	uid := 0
	if consumer {
		uid = 65532
	}
	if os.Geteuid() != uid || os.Getegid() != 65532 {
		t.Fatal("incorrect role identity")
	}
	for _, path := range []string{"/producer", "/acks"} {
		var stat unix.Statfs_t
		if unix.Statfs(path, &stat) != nil {
			t.Fatal("missing role mount", path)
		}
		readOnly := stat.Flags&unix.ST_RDONLY != 0
		wantReadOnly := consumer && path == "/producer" || !consumer && path == "/acks"
		if readOnly != wantReadOnly {
			t.Fatal("wrong actual mount flags", path, readOnly)
		}
	}
	ctx := context.Background()
	source := lineageSpoolSource()
	source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", round)
	const destination = "https://runtime.example.test/internal/v1/runtime/events"
	request := lineageReclaimRequest{Source: source, Destination: destination, ConsumerUID: 65532}
	if !consumer {
		spool, err := newLineageSpool("/producer", 0)
		if err != nil {
			t.Fatal(err)
		}
		defer spool.Close()
		receipts, err := newProductionLineageReceiptReader("/acks", 65532)
		if err != nil {
			t.Fatal(err)
		}
		defer receipts.Close()
		switch phase {
		case "prepare":
			generation, err := spool.Create(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			defer generation.Close()
			line, err := sanitizeLineageEvent(lineageProviderFixture("exec"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
				t.Fatal(err)
			}
			if err := generation.Seal(ctx, "shutdown", 0, 0); err != nil {
				t.Fatal(err)
			}
		case "reclaim":
			if done, err := spool.ReclaimAcknowledged(ctx, receipts, request); err != nil || !done {
				t.Fatal("read-only ACK sync/reclaim", err)
			}
		case "collect":
			if done, err := spool.CollectCompletion(ctx, receipts, request); err != nil || !done {
				t.Fatal("read-only retired ACK sync/collect", err)
			}
		default:
			t.Fatal("unknown root fixture phase")
		}
		return
	}
	var stateFS unix.Statfs_t
	if unix.Statfs("/consumer", &stateFS) != nil || stateFS.Flags&unix.ST_RDONLY != 0 {
		t.Fatal("consumer private mount isn't writable")
	}
	producer, err := newProductionLineageCompletionReader("/producer")
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	acks, err := newLineageAcknowledgments("/acks")
	if err != nil {
		t.Fatal(err)
	}
	defer acks.Close()
	slots, err := newLineageConsumerSlots("/consumer", lineageSlotConfig{EnrollmentBinding: strings.Repeat("b", 64), Destination: destination, Producer: producer, Acknowledgments: acks})
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	switch phase {
	case "process":
		requests := 0
		progress, err := slots.ReconcileConsumer(ctx, lineageControllerClient(t, source.EnrollmentBinding, &requests), 16)
		if err != nil || progress.Submitted != 1 || progress.Acknowledged != 1 || requests != 1 {
			t.Fatal("read-only source process/ACK", progress, err)
		}
	case "retire":
		progress, err := slots.ReconcileConsumer(ctx, nil, 16)
		if err != nil || progress.Retired != 1 || progress.Released != 0 {
			t.Fatal("read-only completion sync/retirement", progress, err)
		}
	case "release":
		progress, err := slots.ReconcileConsumer(ctx, nil, 16)
		if err != nil || progress.Released != 1 {
			t.Fatal("mounted slot release", progress, err)
		}
		entries, err := os.ReadDir("/consumer")
		if err != nil || len(entries) != 3 {
			t.Fatal("mounted slot history remains", err)
		}
	default:
		t.Fatal("unknown consumer fixture phase")
	}
}
