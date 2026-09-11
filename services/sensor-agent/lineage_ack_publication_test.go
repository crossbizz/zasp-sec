package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Publication-only fixture. It is not a consumed-source proof; full proof tests
// call consumer.Acknowledge and never call this private writer directly.
func lineageAckPublicationFixture() lineageConsumptionAck {
	ack := lineageConsumptionAck{Version: "tetragon-consumption-ack-v1"}
	ack.Consumption.Source = lineageSpoolSource()
	return ack
}

func TestLineageAcknowledgmentPublicationRecoversAfterCancellation(t *testing.T) {
	for _, stage := range []string{".pending", "ack-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.json"} {
		t.Run(stage, func(t *testing.T) {
			store, path := acknowledgmentFixture(t)
			ack := lineageAckPublicationFixture()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := lineagePublicationContext{Context: base, path: filepath.Join(path, stage), cancel: cancel}
			if err := store.publish(ctx, ack); err == nil {
				t.Fatal("uncertain publication reported success")
			}
			if _, err := os.Stat(filepath.Join(path, stage)); err != nil {
				t.Fatal("didn't reach publication boundary", err)
			}
			store.Close()
			restarted, err := newLineageAcknowledgments(path)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if err := restarted.publish(context.Background(), ack); err != nil {
				t.Fatal("uncertain publication didn't recover", err)
			}
			want, _ := json.Marshal(ack)
			got, err := os.ReadFile(filepath.Join(path, "ack-"+ack.Consumption.Source.GenerationID+".json"))
			if err != nil || !bytes.Equal(want, got) {
				t.Fatal("recovery changed acknowledgment", err)
			}
			if _, err := os.Lstat(filepath.Join(path, ".pending")); !os.IsNotExist(err) {
				t.Fatal("scratch retained after successful recovery")
			}
		})
	}
}

func TestLineageAcknowledgmentPublicationRecoversAfterProcessDeath(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_LINEAGE_ACK_PATH"); path != "" {
		store, err := newLineageAcknowledgments(path)
		if err != nil {
			t.Fatal(err)
		}
		ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(path, os.Getenv("ZASP_TEST_LINEAGE_ACK_STAGE")), action: func() { os.Exit(73) }}
		_ = store.publish(ctx, lineageAckPublicationFixture())
		t.Fatal("death boundary wasn't reached")
	}
	for _, stage := range []string{".pending", "ack-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.json"} {
		t.Run(stage, func(t *testing.T) {
			store, path := acknowledgmentFixture(t)
			store.Close()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageAcknowledgmentPublicationRecoversAfterProcessDeath$")
			child.Env = append(os.Environ(), "ZASP_TEST_LINEAGE_ACK_PATH="+path, "ZASP_TEST_LINEAGE_ACK_STAGE="+stage)
			child.WaitDelay = time.Second
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child missed death boundary: %v %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(path, stage)); err != nil {
				t.Fatal(err)
			}
			restarted, err := newLineageAcknowledgments(path)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if err := restarted.publish(context.Background(), lineageAckPublicationFixture()); err != nil {
				t.Fatal("dead writer lock or publication not recovered", err)
			}
		})
	}
}

func TestLineageAcknowledgmentPublicationQuotaAndConflict(t *testing.T) {
	store, path := acknowledgmentFixture(t)
	ack := lineageAckPublicationFixture()
	for index := 0; index < lineageSpoolSlots; index++ {
		ack.Consumption.Source.GenerationID = fmt.Sprintf("%08d-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
		if err := store.publish(context.Background(), ack); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.publish(context.Background(), ack); err != nil {
		t.Fatal("full quota rejected identical retry", err)
	}
	name := filepath.Join(path, "ack-"+ack.Consumption.Source.GenerationID+".json")
	before, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	ack.Seal.Dropped++
	if err := store.publish(context.Background(), ack); err == nil {
		t.Fatal("conflicting receipt overwritten")
	}
	after, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("conflict mutated prior receipt")
	}
	ack.Consumption.Source.GenerationID = "99999999-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := store.publish(context.Background(), ack); err != errLineageSpoolFull {
		t.Fatal("ninth receipt accepted", err)
	}
	if _, err := os.Lstat(filepath.Join(path, ".pending")); !os.IsNotExist(err) {
		t.Fatal("quota failure created scratch")
	}
}

func TestLineageAcknowledgmentPublicationRejectsUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"unknown", "symlink", "hardlink", "wrong mode", "oversized scratch", "scratch directory", "symlink scratch", "hardlink scratch", "oversized lock", "oversized acknowledgment"} {
		t.Run(kind, func(t *testing.T) {
			store, path := acknowledgmentFixture(t)
			name, mode, data := ".pending", os.FileMode(0600), []byte("partial")
			switch kind {
			case "unknown":
				name = "unknown"
			case "symlink", "hardlink", "wrong mode", "oversized acknowledgment":
				name = "ack-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.json"
				mode = 0440
			case "oversized lock":
				name = ".consumer.lock"
			}
			if kind == "wrong mode" {
				mode = 0640
			}
			if kind == "oversized scratch" || kind == "oversized acknowledgment" {
				data = bytes.Repeat([]byte("x"), lineageAckBytes+1)
			}
			target := filepath.Join(path, name)
			switch kind {
			case "symlink", "symlink scratch", "hardlink", "hardlink scratch":
				outside := filepath.Join(t.TempDir(), "untouched")
				if err := os.WriteFile(outside, data, mode); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "symlink" || kind == "symlink scratch" {
					err = os.Symlink(outside, target)
				} else {
					err = os.Link(outside, target)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "scratch directory":
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(target, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.publish(context.Background(), lineageAckPublicationFixture()); err == nil {
				t.Fatal("unsafe output accepted")
			}
			after, err := os.Lstat(target)
			if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() {
				t.Fatal("unsafe entry changed or deleted")
			}
			if reopened, err := newLineageAcknowledgments(path); err == nil {
				reopened.Close()
				t.Fatal("unsafe directory admitted")
			}
		})
	}
}

func TestLineageAcknowledgmentPublicationPinsDirectoryAndLock(t *testing.T) {
	for _, mutation := range []string{"directory replaced", "lock replaced", "closed", "canceled", "concurrent writer"} {
		t.Run(mutation, func(t *testing.T) {
			store, path := acknowledgmentFixture(t)
			ctx := context.Background()
			switch mutation {
			case "directory replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0750); err != nil {
					t.Fatal(err)
				}
			case "lock replaced":
				if err := store.publish(ctx, lineageAckPublicationFixture()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(path, ".consumer.lock"), filepath.Join(t.TempDir(), "old-lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, ".consumer.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "closed":
				store.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "concurrent writer":
				other, err := newLineageAcknowledgments(path)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if err := other.publish(ctx, lineageAckPublicationFixture()); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.publish(ctx, lineageAckPublicationFixture()); err == nil {
				t.Fatal("revoked or concurrent writer published")
			}
		})
	}
}

func TestLineageAcknowledgmentHoldsConsumerReaderAndStoreUntilPublicationEnds(t *testing.T) {
	generation, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) {
		t.Error("empty ACK uploaded")
		return nil, errors.New("unexpected upload")
	})
	if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	store, path := acknowledgmentFixture(t)
	consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, cursor, 16, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	if _, err := consumer.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(path, ".pending"), action: func() { once.Do(func() { close(entered); <-release }) }}
	done := make(chan error, 1)
	go func() { done <- consumer.Acknowledge(ctx) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("publication not reached")
	}
	for _, mutex := range []*sync.Mutex{&consumer.mu, &reader.mu, &store.mu} {
		if mutex.TryLock() {
			mutex.Unlock()
			close(release)
			t.Fatal("publication released ownership early")
		}
	}
	closed := make(chan error, 3)
	go func() { closed <- consumer.Close() }()
	go func() { closed <- reader.Close() }()
	go func() { closed <- store.Close() }()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication deadlock")
	}
	for index := 0; index < 3; index++ {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("close deadlock")
		}
	}
}
