package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestLineageSpoolReaderLinuxNonRootConsumerCannotWriteProducerFiles(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_LINEAGE_READER_PATH"); path != "" {
		if os.Getuid() != 65532 {
			t.Fatal("consumer child isn't non-root")
		}
		if phase := os.Getenv("ZASP_TEST_LINEAGE_RETIRE_SOURCE"); phase != "" {
			completion, err := newProductionLineageCompletionReader(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			defer completion.Close()
			store, err := newLineageAcknowledgments(os.Getenv("ZASP_TEST_LINEAGE_ACK_OUTPUT"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			cursor := os.Getenv("ZASP_TEST_LINEAGE_CURSOR_OUTPUT")
			request := lineageReclaimRequest{Source: lineageSpoolSource(), Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: 65532}
			slots, err := newLineageConsumerSlots(filepath.Dir(cursor), lineageSlotConfig{EnrollmentBinding: request.Source.EnrollmentBinding, Destination: request.Destination, Producer: completion, Acknowledgments: store})
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			for retry := 0; retry < 2; retry++ {
				progress, err := slots.ReconcileConsumer(context.Background(), nil, 16)
				complete := false
				switch phase {
				case "1", "2":
					complete = progress.Retired == 1 && progress.Released == 0
				case "3":
					complete = retry == 0 && progress.Released == 1 || retry == 1 && progress == (lineageConsumerProgress{})
				default:
					t.Fatal("unknown fixture retirement phase")
				}
				if err != nil || !complete {
					t.Fatal("non-root checkpoint retirement failed", err)
				}
			}
			if _, err := os.Lstat(cursor); !os.IsNotExist(err) {
				t.Fatal("private checkpoint remains", err)
			}
			marker := filepath.Join(filepath.Dir(path), "reclaim-"+request.Source.GenerationID+".json")
			if phase == "3" {
				marker = filepath.Join(filepath.Dir(path), "consumer-write-probe")
			}
			if file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE, 0600); err == nil {
				file.Close()
				t.Fatal("consumer could write producer completion")
			} else if !os.IsPermission(err) {
				t.Fatal(err)
			}
			return
		}
		reader, err := newProductionLineageSpoolReader(path, strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if chunk, found, err := reader.ReadChunk(1); err != nil || !found || len(chunk.Lines) != 1 {
			t.Fatal("non-root consumer couldn't read owned chunk")
		}
		if seal, found, err := reader.ReadSeal(); err != nil || !found || seal.Records != 1 {
			t.Fatal("non-root consumer couldn't verify closure")
		}
		if os.Getenv("ZASP_TEST_RECOVERY_PERMISSION") == "1" {
			seal, _, err := reader.ReadSeal()
			if err != nil || !seal.CountersUnknown || seal.InterruptedDigest == "" {
				t.Fatal("non-root consumer lost interruption evidence", err)
			}
		}
		calls := 0
		client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
			BaseURL: "https://runtime.example.test", EnrollmentBinding: reader.Source().EnrollmentBinding,
			Now:   func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) },
			Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil },
			Do: func(request *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(request.Body)
				if err != nil || !bytes.Contains(body, []byte(`"boot_id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"`)) {
					t.Fatal("qualified chunk lost at non-root consumer", err)
				}
				return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ackPath := os.Getenv("ZASP_TEST_LINEAGE_ACK_OUTPUT")
		var store *lineageAcknowledgments
		if ackPath == "" {
			store, ackPath = acknowledgmentFixture(t)
		} else {
			store, err = newLineageAcknowledgments(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
		}
		cursor := os.Getenv("ZASP_TEST_LINEAGE_CURSOR_OUTPUT")
		if cursor == "" {
			cursor = filepath.Join(t.TempDir(), "cursor-0.json")
			if err := os.Chmod(filepath.Dir(cursor), 0700); err != nil {
				t.Fatal(err)
			}
		}
		producer, err := newProductionLineageCompletionReader(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		defer producer.Close()
		slots, err := newLineageConsumerSlots(filepath.Dir(cursor), lineageSlotConfig{EnrollmentBinding: reader.Source().EnrollmentBinding, Destination: "https://runtime.example.test/internal/v1/runtime/events", Producer: producer, Acknowledgments: store})
		if err != nil {
			t.Fatal("non-root slot admission", err)
		}
		defer slots.Close()
		if result, err := slots.ReconcileConsumer(context.Background(), client, 16); err != nil || result.SourcesProcessed != 1 || result.Acknowledged != 1 || result.Submitted != 1 || calls != 1 {
			t.Fatal("non-root consumer couldn't commit root-owned source", result, err)
		}
		if result, err := slots.ReconcileConsumer(context.Background(), client, 16); err != nil || result.Acknowledged != 1 || result.Submitted != 0 || calls != 1 {
			t.Fatal("non-root controller replay duplicated upload", result, err)
		}
		ackInfo, err := os.Lstat(filepath.Join(ackPath, "ack-"+reader.Source().GenerationID+".json"))
		if err != nil || !lineageOwnedRegular(ackInfo, 65532, 0440) {
			t.Fatal("acknowledgment didn't retain consumer ownership", err)
		}
		for _, target := range []string{filepath.Join(path, ".pending"), filepath.Join(path, "interrupted.bin"), filepath.Join(path, "chunk-0000000001.jsonl"), filepath.Join(filepath.Dir(path), ".producer.lock")} {
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE, 0o600)
			if err == nil {
				file.Close()
				t.Fatal("consumer acquired producer write access")
			}
			if !os.IsPermission(err) {
				t.Fatalf("write failed for a reason other than permissions: %v", err)
			}
		}
		return
	}
	if os.Getuid() != 0 || os.Getgid() != 65532 {
		t.Skip("requires isolated root producer with consumer group 65532 and SETUID/SETGID/CHOWN fixture capabilities")
	}
	generation, path := lineageSpoolReaderFixture(t)
	parent := filepath.Dir(path)
	// Only this test's temporary directories are made traversable to the child.
	for _, directory := range []string{parent, filepath.Dir(parent)} {
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ZASP_TEST_RECOVERY_PERMISSION") == "1" {
		if err := os.WriteFile(filepath.Join(path, ".pending"), []byte(`{"version":"tetragon-`), 0600); err != nil {
			t.Fatal(err)
		}
		generation.Close()
		if done, err := generation.spool.SealInterrupted(context.Background(), generation.source); err != nil || !done {
			t.Fatal("root recovery failed", err)
		}
	} else {
		if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ackParent := t.TempDir()
	if err := os.Chmod(ackParent, 0750); err != nil {
		t.Fatal(err)
	}
	ackPath := filepath.Join(ackParent, "acks")
	if err := os.Mkdir(ackPath, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(ackPath, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	cursorParent := filepath.Join(ackParent, "cursors")
	if err := os.Mkdir(cursorParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(cursorParent, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(cursorParent, "cursor-0.json")
	// This root fixture has CHOWN but no DAC override. Restore only its owned
	// temporary output directory after all assertions so TempDir can remove it.
	t.Cleanup(func() {
		if err := os.Chown(ackPath, 0, 65532); err != nil {
			t.Error("restore fixture output ownership for cleanup", err)
		}
		if err := os.Chown(cursorParent, 0, 65532); err != nil {
			t.Error("restore fixture cursor ownership for cleanup", err)
		}
	})
	child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSpoolReaderLinuxNonRootConsumerCannotWriteProducerFiles$")
	child.Env = append(os.Environ(), "ZASP_TEST_LINEAGE_READER_PATH="+path, "ZASP_TEST_LINEAGE_ACK_OUTPUT="+ackPath, "ZASP_TEST_LINEAGE_CURSOR_OUTPUT="+cursorPath)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("non-root consumer: %v %s", err, output)
	}
	// The child has exited, leaving its receipt in the owned fixture output.
	// The root producer admits that exact non-root issuer without token access.
	generation.Close()
	receipts, err := newProductionLineageReceiptReader(ackPath, 65532)
	if err != nil {
		t.Fatal("root producer couldn't admit configured consumer", err)
	}
	defer receipts.Close()
	ack, found, err := generation.spool.VerifyAcknowledgment(ctx, receipts, generation.source, "https://runtime.example.test/internal/v1/runtime/events")
	if err != nil || !found || ack.Consumption.Source != generation.source || ack.Consumption.Progress.Submitted != 1 || ack.Seal.CoverageComplete {
		t.Fatal("producer didn't verify non-root receipt against root-owned source", err)
	}
	if invalid, err := newProductionLineageReceiptReader(ackPath, 0); err == nil {
		invalid.Close()
		t.Fatal("root accepted as consumer issuer")
	}
	ackFile := filepath.Join(ackPath, "ack-"+generation.source.GenerationID+".json")
	if err := os.Chown(ackFile, 0, -1); err != nil {
		t.Fatal(err)
	}
	if _, found, err := generation.spool.VerifyAcknowledgment(ctx, receipts, generation.source, "https://runtime.example.test/internal/v1/runtime/events"); err == nil || found {
		t.Fatal("foreign receipt owner admitted")
	}
	if info, err := os.Lstat(ackFile); err != nil || !lineageOwnedRegular(info, 0, 0440) {
		t.Fatal("rejection changed foreign receipt", err)
	}
	if err := os.Chown(ackFile, 65532, -1); err != nil {
		t.Fatal(err)
	}
	producerConfig := lineageProducerConfig{EnrollmentBinding: generation.source.EnrollmentBinding, ConsumerUID: 65532, Destination: "https://runtime.example.test/internal/v1/runtime/events"}
	if progress, err := generation.spool.ReconcileProducer(ctx, receipts, producerConfig); err != nil || progress.SourcesReclaimed != 1 || progress.AwaitingConsumer != 1 {
		t.Fatal("root producer could not reclaim acknowledged source under restricted capabilities", err)
	}
	if info, err := os.Lstat(ackFile); err != nil || !lineageOwnedRegular(info, 65532, 0440) {
		t.Fatal("reclamation changed consumer receipt", err)
	}
	if invalid, err := newProductionLineageCompletionReader(parent); err == nil {
		invalid.Close()
		t.Fatal("root accepted as production consumer")
	}
	retiring := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSpoolReaderLinuxNonRootConsumerCannotWriteProducerFiles$")
	retiring.Env = append(child.Env, "ZASP_TEST_LINEAGE_RETIRE_SOURCE=1")
	retiring.SysProcAttr = child.SysProcAttr
	if output, err := retiring.CombinedOutput(); err != nil {
		t.Fatalf("non-root retiring consumer: %v %s", err, output)
	}
	for _, phase := range []string{"2", "3"} {
		child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSpoolReaderLinuxNonRootConsumerCannotWriteProducerFiles$")
		child.Env = append(retiring.Env[:len(retiring.Env)-1], "ZASP_TEST_LINEAGE_RETIRE_SOURCE="+phase)
		child.SysProcAttr = retiring.SysProcAttr
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("non-root retirement phase %s: %v %s", phase, err, output)
		}
		if phase == "2" {
			for retry := 0; retry < 2; retry++ {
				if progress, err := generation.spool.ReconcileProducer(ctx, receipts, producerConfig); err != nil || retry == 0 && progress.CompletionsCollected != 1 || retry == 1 && progress.CompletionsCollected != 0 {
					t.Fatal("root completion collection failed", err)
				}
			}
		}
	}
	if _, err := os.Lstat(ackFile); !os.IsNotExist(err) {
		t.Fatal("consumer retirement remains", err)
	}
}
