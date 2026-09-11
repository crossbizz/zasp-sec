package sensoradapter

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestConsumptionSourceVerifiesReceiptIndependentlyWithoutCheckpoint(t *testing.T) {
	for _, mutation := range []string{"unchanged", "empty", "source", "destination", "device", "inode", "chain", "bytes", "read count", "submitted", "dropped", "negative sequence", "too many chunks", "max sequence", "max read", "changed bytes", "missing chunk", "canceled", "closed root", "read canceled", "read panic", "root closed during read", "insecure destination", "query destination", "credential destination"} {
		t.Run(mutation, func(t *testing.T) {
			chunk := chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture()))
			found, reads, uploads := mutation != "empty", 0, 0
			read := func(context.Context, int) (ImmutableChunk, bool, error) { reads++; return chunk, found, nil }
			config := chunkConfig(t, read, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
			processor, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := processor.ProcessAvailable(context.Background()); err != nil {
				t.Fatal(err)
			}
			proof, err := processor.VerifyConsumed(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			processor.Close()
			if err := os.Remove(config.CursorPath); err != nil {
				t.Fatal(err)
			}
			beforeReads, beforeUploads := reads, uploads
			ctx := context.Background()
			destination := "https://runtime.example.test/internal/v1/runtime/events"
			switch mutation {
			case "source":
				proof.Source.NodeName = "other-node"
			case "destination":
				proof.Destination = "https://other.example.test/internal/v1/runtime/events"
			case "device":
				proof.Device++
			case "inode":
				proof.Inode++
			case "chain":
				proof.Progress.Chain = strings.Repeat("0", 64)
			case "bytes":
				proof.Progress.Bytes++
			case "read count":
				proof.Progress.Read++
				proof.Progress.Dropped++
			case "submitted":
				proof.Progress.Submitted = -1
			case "dropped":
				proof.Progress.Dropped++
			case "negative sequence":
				proof.Progress.NextSequence = -1
			case "too many chunks":
				proof.Progress.NextSequence = 130
			case "max sequence":
				proof.Progress.NextSequence = math.MaxInt
			case "max read":
				proof.Progress.Read = math.MaxInt
			case "insecure destination":
				destination = "http://runtime.example.test/internal/v1/runtime/events"
				proof.Destination = destination
			case "query destination":
				destination += "?x=1"
				proof.Destination = destination
			case "credential destination":
				credentialURL := &url.URL{Scheme: "https", Host: "runtime.example.test", Path: "/internal/v1/runtime/events", User: url.UserPassword("fixture-user", "not-a-secret")}
				destination = credentialURL.String()
				proof.Destination = destination
			case "changed bytes":
				chunk = chunkFixture(1, qualifiedTetragonFixture(tetragonFileFixture()))
			case "missing chunk":
				found = false
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed root":
				config.SourceRoot.Close()
			}
			verifyRead := read
			if mutation == "read canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				verifyRead = func(ctx context.Context, sequence int) (ImmutableChunk, bool, error) {
					chunk, found, err := read(ctx, sequence)
					cancel()
					return chunk, found, err
				}
			} else if mutation == "read panic" {
				verifyRead = func(context.Context, int) (ImmutableChunk, bool, error) { panic("fixture read panic") }
			} else if mutation == "root closed during read" {
				verifyRead = func(ctx context.Context, sequence int) (ImmutableChunk, bool, error) {
					chunk, found, err := read(ctx, sequence)
					config.SourceRoot.Close()
					return chunk, found, err
				}
			}
			err = VerifyConsumptionSource(ctx, config.SourceRoot, config.Source, destination, proof, verifyRead)
			if mutation == "unchanged" || mutation == "empty" {
				if err != nil {
					t.Fatal("genuine receipt rejected without consumer checkpoint", err)
				}
				wantReads := 1
				if mutation == "empty" {
					wantReads = 0
				}
				if reads-beforeReads != wantReads {
					t.Fatal("wrong prefix read")
				}
			} else if err == nil {
				t.Fatal("invalid consumption receipt accepted")
			}
			if uploads != beforeUploads {
				t.Fatal("producer verification uploaded")
			}
			if _, err := os.Stat(config.CursorPath); !os.IsNotExist(err) {
				t.Fatal("producer verification recreated consumer checkpoint")
			}
		})
	}
}
