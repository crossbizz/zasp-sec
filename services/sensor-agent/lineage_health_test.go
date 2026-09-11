package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real spool, controller, receipt/reclamation and probe composition. No product
// upload is needed for these zero-chunk generations, including rejected events.
func TestLineageHealthSurvivesRetirementAndRestart(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			baseline, sealed, err := fixture.reader.ReadSeal()
			if err != nil || !sealed || baseline.Dropped != 3 {
				t.Fatal("fixture baseline", baseline, err)
			}
			ctx := context.Background()
			source := fixture.reader.Source()
			source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			generation, err := fixture.generation.spool.Create(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			if !unknown {
				if err := generation.Seal(ctx, "disconnect", 7, 2); err != nil {
					t.Fatal(err)
				}
			}
			generation.Close()
			if unknown {
				if done, err := fixture.generation.spool.SealInterrupted(ctx, source); err != nil || !done {
					t.Fatal(done, err)
				}
			}
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { slots.Close() }()
			requests := 0
			client := lineageControllerClient(t, config.EnrollmentBinding, &requests)
			settings := lineageConsumerDaemonConfig(t, fixture.generation.spool.root.Name(), fixture.ackPath, path)
			newProbe := func() *LocalSensorProbe {
				probe, err := NewLocalSensorProbe(LocalSensorProbeConfig{
					NodeName: "node-a", KernelFile: settings.KernelFile, BTFFile: settings.BTFFile,
					MetricsURL: "http://127.0.0.1:2112/metrics", PollInterval: time.Second, Now: time.Now,
					Do: func(*http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.ReplaceAll(tetragonMetricsFixture(), " 1\n", " 0\n")))}, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return probe
			}
			probe := newProbe()
			additional := uint64(0)
			check := func() {
				runtime := &lineageConsumerRuntime{slots: slots, client: client, maximum: 16, operation: 5 * time.Second, readyDo: lineageProducerReadyFixture}
				result, err := runtime.ProcessAvailable(ctx)
				if err != nil {
					t.Fatal(err)
				}
				report, err := probe.Report(ctx, result)
				want := baseline.Dropped + 7
				if unknown {
					want = baseline.Dropped
				}
				want += additional
				if err != nil || report.Status != "degraded" || report.Drops != want || requests != 0 {
					t.Fatalf("lost or repeated coverage evidence: report=%+v result=%+v requests=%d err=%v", report, result, requests, err)
				}
			}
			check()
			check() // Repeated seal ACK must not add another seven drops.
			producer := lineageProducerConfig{EnrollmentBinding: config.EnrollmentBinding, Destination: config.Destination, ConsumerUID: uint32(os.Geteuid())}
			for phase := 0; phase < 2; phase++ {
				if _, err := fixture.generation.spool.ReconcileProducer(ctx, fixture.receipts, producer); err != nil {
					t.Fatal(err)
				}
				check()
			}
			if work, err := slots.ListConsumerWork(ctx); err != nil || len(work) != 0 {
				t.Fatal(work, err)
			}
			slots.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			probe = newProbe()
			check() // Both the consumer and its in-memory probe have restarted.
			for reuse := 0; reuse < 10; reuse++ {
				source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", reuse+2)
				generation, err := fixture.generation.spool.Create(ctx, source)
				if err != nil {
					t.Fatal(err)
				}
				if err := generation.Seal(ctx, "rotation", 5, 100); err != nil {
					t.Fatal(err)
				}
				generation.Close()
				additional += 5
				check()
				check()
				for phase := 0; phase < 2; phase++ {
					if _, err := fixture.generation.spool.ReconcileProducer(ctx, fixture.receipts, producer); err != nil {
						t.Fatal(err)
					}
					check()
				}
			}
			// Two initial cursor locks, controller lock, one bounded coverage file.
			if entries, err := os.ReadDir(path); err != nil || len(entries) != 4 {
				t.Fatal("unbounded coverage history", len(entries), err)
			}
		})
	}
}

func TestLineageHealthInterruptedPublicationIsIdempotent(t *testing.T) {
	for _, boundary := range []string{"scratch", "renamed"} {
		t.Run(boundary, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { slots.Close() }()
			ctx := context.Background()
			if state, err := slots.health(ctx); err != nil || state.Dropped != 0 || state.Unknown {
				t.Fatal(state, err)
			}
			assignment, err := slots.Reserve(ctx, fixture.reader)
			if err != nil {
				t.Fatal(err)
			}
			seal, _, err := fixture.reader.ReadSeal()
			if err != nil {
				t.Fatal(err)
			}
			interrupted, cancel := context.WithCancel(ctx)
			defer cancel()
			observed := lineageHealthPending
			if boundary == "renamed" {
				observed = lineageHealthName
			}
			publication := lineagePublicationContext{Context: interrupted, path: filepath.Join(path, observed), action: func() {
				raw, _ := os.ReadFile(filepath.Join(path, observed))
				if boundary == "scratch" || bytes.Contains(raw, []byte(`"producer_dropped":3`)) {
					cancel()
				}
			}}
			if err := slots.accountSeal(publication, assignment, seal); err == nil || interrupted.Err() == nil {
				t.Fatal("write did not stop at boundary", err)
			}
			slots.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal("interrupted admission", err)
			}
			for retry := 0; retry < 3; retry++ {
				if err := slots.accountSeal(ctx, assignment, seal); err != nil {
					t.Fatal(err)
				}
				if state, err := slots.health(ctx); err != nil || state.Dropped != 3 || state.Unknown {
					t.Fatal("lost or repeated counter", state, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(path, lineageHealthPending)); !os.IsNotExist(err) {
				t.Fatal("scratch survived", err)
			}
		})
	}
}

func TestLineageHealthMissingHistoryDegradesAndDamagedHistoryBlocksACK(t *testing.T) {
	for _, damage := range []string{"missing", "symlink", "hardlink", "permissive", "malformed", "foreign-binding"} {
		t.Run(damage, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			ctx := context.Background()
			if _, err := slots.health(ctx); err != nil {
				t.Fatal(err)
			}
			source := fixture.reader.Source()
			source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			generation, err := fixture.generation.spool.Create(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			if err := generation.Seal(ctx, "shutdown", 7, 0); err != nil {
				t.Fatal(err)
			}
			generation.Close()
			file := filepath.Join(path, lineageHealthName)
			switch damage {
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "coverage")
				if err := os.Rename(file, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, filepath.Join(t.TempDir(), "coverage")); err != nil {
					t.Fatal(err)
				}
			case "permissive":
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "malformed", "foreign-binding":
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "malformed" {
					raw = []byte("{")
				} else {
					raw = bytes.ReplaceAll(raw, []byte(config.EnrollmentBinding), []byte(strings.Repeat("a", 64)))
				}
				if err := os.Chmod(file, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(file, 0440); err != nil {
					t.Fatal(err)
				}
			}
			requests := 0
			runtime := &lineageConsumerRuntime{slots: slots, client: lineageControllerClient(t, config.EnrollmentBinding, &requests), maximum: 16, operation: 5 * time.Second, readyDo: lineageProducerReadyFixture}
			progress, err := runtime.ProcessAvailable(ctx)
			if damage == "missing" {
				if err != nil || !progress.CoverageUnknown || progress.ProducerDroppedTotal != 10 {
					t.Fatal("missing history fabricated healthy state", progress, err)
				}
			} else {
				if err == nil || !progress.CoverageUnknown {
					t.Fatal("damaged history accepted", progress, err)
				}
				if _, err := os.Lstat(filepath.Join(fixture.ackPath, "ack-"+source.GenerationID+".json")); !os.IsNotExist(err) {
					t.Fatal("unaccounted generation ACKed", err)
				}
			}
			if requests != 0 {
				t.Fatal("empty generation made uploads")
			}
		})
	}
}
