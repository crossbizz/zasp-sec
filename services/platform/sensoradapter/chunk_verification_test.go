package sensoradapter

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChunkVerificationIndependentlyChecksConsumedSource(t *testing.T) {
	for _, mutation := range []string{"unchanged", "changed", "missing", "read canceled", "persistence failed", "after persistence canceled"} {
		t.Run(mutation, func(t *testing.T) {
			chunk := chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture()))
			reads, uploads := 0, 0
			found := true
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
				reads++
				if reads == 2 && mutation == "read canceled" {
					cancel()
				}
				return chunk, found, nil
			}, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if _, err := p.ProcessAvailable(context.Background()); err != nil {
				t.Fatal(err)
			}
			before, _, _ := p.Committed()
			switch mutation {
			case "changed":
				chunk = chunkFixture(1, qualifiedTetragonFixture(tetragonFileFixture()))
			case "missing":
				found = false
			case "persistence failed":
				p.writeCheckpoint = func(*os.Root, string, []byte) error { return ErrStream }
			case "after persistence canceled":
				p.writeCheckpoint = func(root *os.Root, name string, raw []byte) error {
					err := writeCheckpointBytes(root, name, raw)
					cancel()
					return err
				}
			}
			proof, err := p.VerifyConsumed(ctx)
			if mutation == "unchanged" {
				if err != nil || proof.Progress != before || proof.Source != config.Source || proof.Destination != "https://runtime.example.test/internal/v1/runtime/events" || proof.Device == 0 || proof.Inode == 0 {
					t.Fatalf("verified source: %+v %v", proof, err)
				}
			} else if !errors.Is(err, ErrStream) {
				t.Fatalf("invalid source verified: %v", err)
			}
			after, _, err := p.Committed()
			if err != nil || after != before || reads != 2 || uploads != 1 {
				t.Fatal("verification normalized, uploaded or advanced source")
			}
		})
	}
}

func TestChunkVerificationChecksWholeCommittedPrefixWithoutNormalizing(t *testing.T) {
	for _, state := range []string{"empty", "two chunks", "changed committed chain", "changed committed bytes"} {
		t.Run(state, func(t *testing.T) {
			chunks := []ImmutableChunk{chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), chunkFixture(2, qualifiedTetragonFixture(tetragonFileFixture()))}
			if state == "empty" {
				chunks = nil
			}
			reads, uploads := 0, 0
			config := chunkConfig(t, func(_ context.Context, sequence int) (ImmutableChunk, bool, error) {
				reads++
				if sequence > len(chunks) {
					return ImmutableChunk{}, false, nil
				}
				return chunks[sequence-1], true, nil
			}, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			for index := 0; index <= len(chunks); index++ {
				if _, err := p.ProcessAvailable(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "changed committed chain":
				p.checkpoint.Committed.Chain = strings.Repeat("0", 64)
			case "changed committed bytes":
				p.checkpoint.Committed.Bytes++
			}
			before := p.checkpoint.Committed
			beforeReads, beforeUploads := reads, uploads
			proof, err := p.VerifyConsumed(context.Background())
			if strings.HasPrefix(state, "changed") {
				if err == nil {
					t.Fatal("valid-shaped corrupt committed totals verified")
				}
			} else if err != nil || proof.Progress != before || proof.Progress.NextSequence != len(chunks)+1 {
				t.Fatal("whole prefix not verified", err)
			}
			if reads-beforeReads != len(chunks) || uploads != beforeUploads || p.checkpoint.Committed != before {
				t.Fatal("verification normalized, reread outside prefix, or changed accounting")
			}
		})
	}
}

func TestChunkVerificationRequiresDurableNonPendingProgress(t *testing.T) {
	reads := 0
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
		reads++
		return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
	}, func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.VerifyConsumed(context.Background()); err == nil || reads != 0 {
		t.Fatal("undurable state verified")
	}
	if _, err := p.ProcessAvailable(context.Background()); err == nil {
		t.Fatal("offline upload accepted")
	}
	if _, err := p.VerifyConsumed(context.Background()); err == nil || reads != 1 {
		t.Fatal("pending upload verified or source reread")
	}
}

func TestChunkProcessorRequiresDistinctOutputRootBeforeCreatingCursorLock(t *testing.T) {
	for _, overlap := range []string{"cursor", "source", "spool", "protected input"} {
		t.Run(overlap, func(t *testing.T) {
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
				t.Fatal("read")
				return ImmutableChunk{}, false, nil
			}, func(*http.Request) (*http.Response, error) { t.Fatal("upload"); return nil, nil })
			var root *os.Root
			switch overlap {
			case "cursor":
				root, _ = os.OpenRoot(filepath.Dir(config.CursorPath))
				defer root.Close()
			case "source":
				root = config.SourceRoot
			case "spool":
				root = config.SpoolRoot
			case "protected input":
				root, _ = os.OpenRoot(t.TempDir())
				defer root.Close()
				config.ProtectedInputs = []PinnedInput{{Parent: root, Name: "token"}}
			}
			config.DisjointOutputRoots = []*os.Root{root}
			if p, err := NewChunkProcessor(config); err == nil {
				p.Close()
				t.Fatal("overlapping output root accepted")
			}
			if _, err := os.Stat(config.CursorPath + ".lock"); !os.IsNotExist(err) {
				t.Fatal("overlap created cursor lock")
			}
		})
	}
}
