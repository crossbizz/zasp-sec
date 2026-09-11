package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLineageRetirementHandshakeReleasesOnlyFinishedMetadata(t *testing.T) {
	fixture, store, reader := lineageCompletionFixture(t, false)
	request := reclaimFixtureRequest(fixture)
	spool := fixture.generation.spool
	marker := filepath.Join(spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")
	ackPath := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
	completion, _ := os.ReadFile(marker)
	for retry := 0; retry < 2; retry++ {
		if complete, err := store.RetireAcknowledgment(context.Background(), reader, request, fixture.cursor, 16, nil); err != nil || !complete {
			t.Fatal("retirement receipt not published", err)
		}
	}
	if _, err := os.Lstat(fixture.cursor); !os.IsNotExist(err) {
		t.Fatal("checkpoint remains", err)
	}
	raw, err := os.ReadFile(ackPath)
	var retired lineageRetirementAck
	if err != nil || !lineageDecodeCanonical(raw, &retired) || retired.Version != "tetragon-retirement-ack-v1" || retired.Request != request || retired.CompletionDigest != lineageHash(completion) {
		t.Fatal("wrong retirement binding", err)
	}
	if complete, err := store.ForgetRetirement(context.Background(), reader, request); err != nil || complete {
		t.Fatal("consumer forgot retirement before producer collection", err)
	}
	for retry := 0; retry < 2; retry++ {
		if complete, err := spool.CollectCompletion(context.Background(), fixture.receipts, request); err != nil || !complete {
			t.Fatal("producer completion not collected", err)
		}
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("completion remains", err)
	}
	after, err := os.ReadFile(ackPath)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("producer mutated consumer state", err)
	}
	for retry := 0; retry < 2; retry++ {
		if complete, err := store.ForgetRetirement(context.Background(), reader, request); err != nil || !complete {
			t.Fatal("consumer retirement not collected", err)
		}
	}
	if _, err := os.Lstat(ackPath); !os.IsNotExist(err) {
		t.Fatal("retirement remains", err)
	}
	for _, path := range []string{spool.root.Name(), fixture.ackPath, filepath.Dir(fixture.cursor)} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 1 {
			t.Fatal("metadata slot not released", path, err)
		}
	}
}

func TestLineageRetirementDoesNotCollectUnretiredOrMismatchedEvidence(t *testing.T) {
	for _, mutation := range []string{"original ack", "wrong completion digest", "wrong spool", "wrong ack directory", "wrong source", "wrong issuer", "missing ack", "active source"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			spool := fixture.generation.spool
			marker := filepath.Join(spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")
			ackPath := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
			if mutation != "original ack" {
				if complete, err := store.RetireAcknowledgment(context.Background(), reader, request, fixture.cursor, 16, nil); err != nil || !complete {
					t.Fatal(err)
				}
			}
			raw, err := os.ReadFile(ackPath)
			if err != nil {
				t.Fatal(err)
			}
			var retired lineageRetirementAck
			json.Unmarshal(raw, &retired)
			rewrite := false
			switch mutation {
			case "wrong completion digest":
				retired.CompletionDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				rewrite = true
			case "wrong spool":
				retired.SpoolInode++
				rewrite = true
			case "wrong ack directory":
				retired.AckInode++
				rewrite = true
			case "wrong source":
				request.Source.NodeName = "different-node"
			case "wrong issuer":
				request.ConsumerUID++
			case "missing ack":
				if err := os.Remove(ackPath); err != nil {
					t.Fatal(err)
				}
			case "active source":
				spool.active = fixture.generation
			}
			if rewrite {
				raw, _ = json.Marshal(retired)
				if err := os.Chmod(ackPath, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ackPath, raw, 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(ackPath, 0440); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			complete, err := spool.CollectCompletion(context.Background(), fixture.receipts, request)
			if complete || mutation != "missing ack" && err == nil || mutation == "missing ack" && err != nil {
				t.Fatal("invalid retirement collected completion", complete, err)
			}
			after, err := os.ReadFile(marker)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid retirement removed completion", err)
			}
		})
	}
}
