package sensoradapter

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestChunkRetirementEnforcesDurableSlotBindingBeforeDeletion(t *testing.T) {
	for _, mutation := range []string{"none", "cursor name", "cursor inode", "source inode", "spool inode", "destination", "source identity", "missing spool"} {
		t.Run(mutation, func(t *testing.T) {
			config, retirement := chunkRetirementFixture(t, false)
			info, err := os.Stat(filepath.Dir(config.CursorPath))
			if err != nil {
				t.Fatal(err)
			}
			state := info.Sys().(*syscall.Stat_t)
			spoolInfo, err := chunkRootInfo(config.SpoolRoot)
			if err != nil {
				t.Fatal(err)
			}
			spool := spoolInfo.Sys().(*syscall.Stat_t)
			binding := &ChunkStateBinding{Source: config.Source, Destination: retirement.Destination, CursorName: filepath.Base(config.CursorPath), CursorDevice: uint64(state.Dev), CursorInode: state.Ino, SpoolDevice: uint64(spool.Dev), SpoolInode: spool.Ino, SourceDevice: retirement.Consumption.Device, SourceInode: retirement.Consumption.Inode}
			retirement.StateBinding = binding
			retirement.SpoolRoot = config.SpoolRoot
			switch mutation {
			case "cursor name":
				binding.CursorName = "wrong.json"
			case "cursor inode":
				binding.CursorInode++
			case "source inode":
				binding.SourceInode++
			case "spool inode":
				binding.SpoolInode++
			case "destination":
				binding.Destination = "https://foreign.example.test/internal/v1/runtime/events"
			case "source identity":
				binding.Source.NodeName = "foreign-node"
			case "missing spool":
				retirement.SpoolRoot = nil
			}
			before, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			retirement.Authorize = func(context.Context) error { calls++; return nil }
			err = RetireConsumedCheckpoint(context.Background(), retirement)
			if mutation == "none" {
				if err != nil || calls == 0 {
					t.Fatal("exact bound retirement rejected", err)
				}
				return
			}
			if err == nil || calls != 0 {
				t.Fatal("mismatch reached deletion authorization", calls, err)
			}
			after, err := os.ReadFile(config.CursorPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("wrong binding changed checkpoint", err)
			}
		})
	}
}

func TestChunkProcessorEnforcesDurableSlotBindingBeforeAnyWrite(t *testing.T) {
	for _, mutation := range []string{"none", "cursor name", "cursor device", "cursor inode", "source device", "source inode", "spool device", "spool inode", "source identity", "destination"} {
		t.Run(mutation, func(t *testing.T) {
			calls := 0
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { calls++; return ImmutableChunk{}, false, nil }, func(*http.Request) (*http.Response, error) { calls++; return nil, nil })
			cursor, err := os.OpenRoot(filepath.Dir(config.CursorPath))
			if err != nil {
				t.Fatal(err)
			}
			defer cursor.Close()
			stat := func(root *os.Root) *syscall.Stat_t {
				info, err := chunkRootInfo(root)
				if err != nil {
					t.Fatal(err)
				}
				return info.Sys().(*syscall.Stat_t)
			}
			state, source, spool := stat(cursor), stat(config.SourceRoot), stat(config.SpoolRoot)
			binding := &ChunkStateBinding{Source: config.Source, Destination: config.Client.base.String() + runtimeEventsPath, CursorName: filepath.Base(config.CursorPath), CursorDevice: uint64(state.Dev), CursorInode: state.Ino, SourceDevice: uint64(source.Dev), SourceInode: source.Ino, SpoolDevice: uint64(spool.Dev), SpoolInode: spool.Ino}
			config.StateBinding = binding
			switch mutation {
			case "cursor name":
				binding.CursorName = "wrong.json"
			case "cursor device":
				binding.CursorDevice++
			case "cursor inode":
				binding.CursorInode++
			case "source device":
				binding.SourceDevice++
			case "source inode":
				binding.SourceInode++
			case "spool device":
				binding.SpoolDevice++
			case "spool inode":
				binding.SpoolInode++
			case "source identity":
				binding.Source.NodeName = "different-node"
			case "destination":
				binding.Destination = "https://other.example.test/internal/v1/runtime/events"
			}
			processor, err := NewChunkProcessor(config)
			if mutation == "none" {
				if err != nil {
					t.Fatal("exact slot binding rejected", err)
				}
				processor.Close()
			} else {
				if err == nil {
					processor.Close()
					t.Fatal("mismatched slot authority admitted")
				}
				entries, err := os.ReadDir(filepath.Dir(config.CursorPath))
				if err != nil || len(entries) != 0 {
					t.Fatal("rejection wrote before identity check", len(entries), err)
				}
			}
			if calls != 0 {
				t.Fatal("construction accessed source or network")
			}
		})
	}
}
