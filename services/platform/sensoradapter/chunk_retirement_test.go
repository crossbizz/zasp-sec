package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chunkRetirementFixture(t *testing.T, empty bool) (ChunkProcessorConfig, ChunkRetirementConfig) {
	t.Helper()
	config := chunkConfig(t, func(_ context.Context, sequence int) (ImmutableChunk, bool, error) {
		if empty || sequence > 1 {
			return ImmutableChunk{}, false, nil
		}
		return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
	}, func(*http.Request) (*http.Response, error) { return envelopeAccepted(), nil })
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	proof, err := p.VerifyConsumed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return config, ChunkRetirementConfig{CursorPath: config.CursorPath, Source: config.Source,
		Destination: proof.Destination, Consumption: proof, MaximumProcesses: config.MaximumProcesses,
		DisjointRoots: []*os.Root{config.SpoolRoot}, Authorize: func(context.Context) error { return nil }}
}

func TestChunkRetirementRemovesMatchingCheckpointWithoutSourceOrClient(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "record", true: "empty"}[empty], func(t *testing.T) {
			config, retirement := chunkRetirementFixture(t, empty)
			config.Client.token = func() ([]byte, error) { t.Fatal("token opened during retirement"); return nil, nil }
			config.Client.do = func(*http.Request) (*http.Response, error) { t.Fatal("upload during retirement"); return nil, nil }
			config.SourceRoot.Close()
			if err := os.Remove(filepath.Join(config.SpoolRoot.Name(), "generation")); err != nil {
				t.Fatal(err)
			}
			lockBefore, err := os.Lstat(config.CursorPath + ".lock")
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			retirement.Authorize = func(context.Context) error { calls++; return nil }
			for retry := 0; retry < 2; retry++ {
				if err := RetireConsumedCheckpoint(context.Background(), retirement); err != nil {
					t.Fatal("retirement failed", err)
				}
				if _, err := os.Lstat(config.CursorPath); !os.IsNotExist(err) {
					t.Fatal("checkpoint remains", err)
				}
			}
			lockAfter, err := os.Lstat(config.CursorPath + ".lock")
			if err != nil || !os.SameFile(lockBefore, lockAfter) || calls < 2 {
				t.Fatal("slot lock replaced or authorization skipped", err)
			}
		})
	}
}

func TestChunkRetirementPreservesMismatchedOrUnsafeCheckpoint(t *testing.T) {
	for _, mutation := range []string{"source", "destination", "physical source", "progress", "pending", "unknown field", "cache", "scratch", "mode", "symlink", "hardlink", "no lock", "live consumer", "canceled", "no authorizer", "denied", "protected input", "overlap"} {
		t.Run(mutation, func(t *testing.T) {
			config, retirement := chunkRetirementFixture(t, false)
			ctx := context.Background()
			raw, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			var cp chunkCheckpoint
			if json.Unmarshal(raw, &cp) != nil {
				t.Fatal("fixture checkpoint")
			}
			switch mutation {
			case "source":
				retirement.Source.NodeName = "different-node"
			case "destination":
				retirement.Destination = "https://other.example.test/internal/v1/runtime/events"
			case "physical source":
				retirement.Consumption.Inode++
			case "progress":
				retirement.Consumption.Progress.Chain = strings.Repeat("0", 64)
			case "pending":
				cp.Pending = &pendingChunk{}
			case "cache":
				cp.Cache = nil
			case "unknown field":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "scratch":
				if err := os.WriteFile(filepath.Join(filepath.Dir(config.CursorPath), temporaryCheckpointName(filepath.Base(config.CursorPath))), []byte("uncertain checkpoint"), 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(config.CursorPath, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				if err := os.Rename(config.CursorPath, config.CursorPath+".original"); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if mutation == "symlink" {
					link = os.Symlink
				}
				if err := link(config.CursorPath+".original", config.CursorPath); err != nil {
					t.Fatal(err)
				}
			case "no lock":
				if err := os.Remove(config.CursorPath + ".lock"); err != nil {
					t.Fatal(err)
				}
			case "live consumer":
				p, err := NewChunkProcessor(config)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "no authorizer":
				retirement.Authorize = nil
			case "denied":
				retirement.Authorize = func(context.Context) error { return ErrStream }
			case "protected input", "overlap":
				root, err := os.OpenRoot(filepath.Dir(config.CursorPath))
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				if mutation == "overlap" {
					retirement.DisjointRoots = append(retirement.DisjointRoots, root)
				} else {
					retirement.ProtectedInputs = []PinnedInput{{Parent: root, Name: filepath.Base(config.CursorPath)}}
				}
			}
			if mutation == "pending" || mutation == "cache" {
				raw, err = json.Marshal(cp)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, '\n')
			}
			if mutation == "pending" || mutation == "cache" || mutation == "unknown field" {
				if err := os.WriteFile(config.CursorPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := RetireConsumedCheckpoint(ctx, retirement); err == nil {
				t.Fatal("unsafe checkpoint retired")
			}
			after, err := os.ReadFile(config.CursorPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected retirement changed checkpoint", err)
			}
		})
	}
}
