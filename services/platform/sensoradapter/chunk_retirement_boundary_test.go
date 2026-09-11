package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

type chunkRetirementContext struct {
	context.Context
	check func() error
}

func (ctx *chunkRetirementContext) Err() error { return ctx.check() }

func TestChunkRetirementRejectsMutationDuringAuthorization(t *testing.T) {
	for _, mutation := range []string{"checkpoint replaced", "bytes changed", "lock replaced", "directory replaced", "scratch created", "canceled", "panic"} {
		t.Run(mutation, func(t *testing.T) {
			config, retirement := chunkRetirementFixture(t, false)
			path := config.CursorPath
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			retirement.Authorize = func(context.Context) error {
				switch mutation {
				case "checkpoint replaced", "lock replaced":
					target := path
					data := raw
					if mutation == "lock replaced" {
						target += ".lock"
						data = nil
					}
					if err := os.Rename(target, target+".held"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, data, 0600); err != nil {
						t.Fatal(err)
					}
				case "bytes changed":
					changed := bytes.Replace(raw, []byte(`"node-a"`), []byte(`"node-b"`), 1)
					if bytes.Equal(raw, changed) {
						t.Fatal("fixture has no cache node")
					}
					if err := os.WriteFile(path, changed, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory replaced":
					dir := filepath.Dir(path)
					if err := os.Rename(dir, dir+".held"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				case "scratch created":
					if err := os.WriteFile(filepath.Join(filepath.Dir(path), temporaryCheckpointName(filepath.Base(path))), raw, 0600); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				case "panic":
					panic("test-only authorization panic")
				}
				return nil
			}
			if err := RetireConsumedCheckpoint(ctx, retirement); err == nil {
				t.Fatal("mutation admitted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("named checkpoint deleted", err)
			}
			if mutation == "directory replaced" {
				if _, err := os.Lstat(filepath.Join(filepath.Dir(path)+".held", filepath.Base(path))); err != nil {
					t.Fatal("held checkpoint deleted", err)
				}
			}
		})
	}
}

func TestChunkRetirementInterruptedUnlinkRequiresAuthorizedRetry(t *testing.T) {
	config, retirement := chunkRetirementFixture(t, false)
	fired := false
	ctx := &chunkRetirementContext{Context: context.Background(), check: func() error {
		if _, err := os.Lstat(config.CursorPath); os.IsNotExist(err) {
			fired = true
			return context.Canceled
		}
		return nil
	}}
	if err := RetireConsumedCheckpoint(ctx, retirement); err == nil || !fired {
		t.Fatal("uncertain unlink reported durable", err)
	}
	if _, err := os.Lstat(config.CursorPath); !os.IsNotExist(err) {
		t.Fatal("boundary not reached", err)
	}
	retirement.Authorize = func(context.Context) error { return ErrStream }
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err == nil {
		t.Fatal("absence bypassed authorization")
	}
	retirement.Authorize = func(context.Context) error { return nil }
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err != nil {
		t.Fatal("authorized retry failed", err)
	}
}

func TestChunkRetirementRejectsNamedFileCreatedDuringAbsentRetry(t *testing.T) {
	config, retirement := chunkRetirementFixture(t, false)
	if err := os.Remove(config.CursorPath); err != nil {
		t.Fatal(err)
	}
	retirement.Authorize = func(context.Context) error {
		return os.WriteFile(config.CursorPath, []byte("another generation"), 0600)
	}
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err == nil {
		t.Fatal("new checkpoint accepted as absence")
	}
	raw, err := os.ReadFile(config.CursorPath)
	if err != nil || string(raw) != "another generation" {
		t.Fatal("new checkpoint deleted", err)
	}
}

func TestChunkRetirementRejectsFIFOWithoutBlocking(t *testing.T) {
	config, retirement := chunkRetirementFixture(t, false)
	if err := os.Remove(config.CursorPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(config.CursorPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err == nil {
		t.Fatal("FIFO accepted")
	}
	if info, err := os.Lstat(config.CursorPath); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("FIFO changed", err)
	}
}

type chunkRetirementProcessFixture struct {
	Cursor string
	Proof  VerifiedConsumption
	Stage  string
}

func TestChunkRetirementProcessDeathChild(t *testing.T) {
	path := os.Getenv("ZASP_TEST_CHECKPOINT_RETIRE")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8192 {
		t.Fatal("fixture read", err)
	}
	var fixture chunkRetirementProcessFixture
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture shape")
	}
	config := ChunkRetirementConfig{CursorPath: fixture.Cursor, Source: fixture.Proof.Source, Destination: fixture.Proof.Destination, Consumption: fixture.Proof, MaximumProcesses: 16,
		Authorize: func(context.Context) error {
			if fixture.Stage == "before unlink" {
				os.Exit(73)
			}
			return nil
		}}
	ctx := &chunkRetirementContext{Context: context.Background(), check: func() error {
		if fixture.Stage == "after unlink" {
			if _, err := os.Lstat(fixture.Cursor); os.IsNotExist(err) {
				os.Exit(73)
			}
		}
		return nil
	}}
	if err := RetireConsumedCheckpoint(ctx, config); err != nil {
		t.Fatal(err)
	}
	t.Fatal("process-death boundary not reached")
}

func TestChunkRetirementRecoversAfterProcessDeath(t *testing.T) {
	for _, stage := range []string{"before unlink", "after unlink"} {
		t.Run(stage, func(t *testing.T) {
			config, retirement := chunkRetirementFixture(t, false)
			fixturePath := filepath.Join(t.TempDir(), "retirement.json")
			raw, err := json.Marshal(chunkRetirementProcessFixture{Cursor: config.CursorPath, Proof: retirement.Consumption, Stage: stage})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixturePath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestChunkRetirementProcessDeathChild$", "-test.timeout=20s")
			child.Env = append(os.Environ(), "ZASP_TEST_CHECKPOINT_RETIRE="+fixturePath)
			output, err := child.CombinedOutput()
			var failure *exec.ExitError
			if !errors.As(err, &failure) || failure.ExitCode() != 73 {
				t.Fatalf("boundary child failed: %v %s", err, output)
			}
			_, statErr := os.Lstat(config.CursorPath)
			if stage == "before unlink" && statErr != nil || stage == "after unlink" && !os.IsNotExist(statErr) {
				t.Fatal("wrong death boundary", statErr)
			}
			if err := RetireConsumedCheckpoint(context.Background(), retirement); err != nil {
				t.Fatal("restart failed", err)
			}
			if _, err := os.Lstat(config.CursorPath); !os.IsNotExist(err) {
				t.Fatal("checkpoint remains", err)
			}
		})
	}
}
