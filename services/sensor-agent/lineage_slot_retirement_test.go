package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func lineageRetiringSlotFixture(t *testing.T, profiles ...string) (lineageReceiptFixtureState, *lineageConsumerSlots, lineageSlotAssignment) {
	t.Helper()
	fixture, parent, config := lineageSlotsFixture(t, profiles...)
	path := filepath.Join(parent, "slots")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slots.Close() })
	assignment, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := slots.CursorPath(assignment)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: config.EnrollmentBinding, Now: func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewBufferString(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := newAssignedLineageChunkConsumer(fixture.reader, client, cursor, 16, nil, config.Acknowledgments, assignment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	consumer.Close()
	if done, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	return fixture, slots, assignment
}

func TestLineageSlotRetirementReusesOneFixedSlotAcrossTwentyFourGenerations(t *testing.T) {
	checkLineageSlotRetirementAcrossGenerations(t)
}

func TestLineagePrecisionSlotRetirementReusesOneFixedSlotAcrossTwentyFourGenerations(t *testing.T) {
	checkLineageSlotRetirementAcrossGenerations(t, "tetragon-local-stream-v3")
}

func checkLineageSlotRetirementAcrossGenerations(t *testing.T, profiles ...string) {
	t.Helper()
	fixture, slots, assignment := lineageRetiringSlotFixture(t, profiles...)
	ctx := context.Background()
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: assignment.Source.EnrollmentBinding, Now: func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewBufferString(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 24; round++ {
		if round > 0 {
			source := assignment.Source
			source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", round)
			generation, err := fixture.generation.spool.Create(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			if round%2 == 1 {
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
					t.Fatal(err)
				}
			}
			if err := generation.Seal(ctx, "shutdown", 0, 0); err != nil {
				t.Fatal(err)
			}
			generation.Close()
			reader, err := newLineageSpoolReader(filepath.Join(fixture.generation.spool.root.Name(), "generation-"+source.GenerationID), source.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			assignment, err = slots.Reserve(ctx, reader)
			if err != nil || assignment.Slot != 0 {
				t.Fatal("fixed slot not reusable", round, assignment, err)
			}
			cursor, err := slots.CursorPath(assignment)
			if err != nil {
				t.Fatal(err)
			}
			consumer, err := newAssignedLineageChunkConsumer(reader, client, cursor, 16, nil, slots.config.Acknowledgments, assignment)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := consumer.ProcessAvailable(ctx); err != nil {
				t.Fatal(err)
			}
			if err := consumer.Acknowledge(ctx); err != nil {
				t.Fatal(err)
			}
			consumer.Close()
			reader.Close()
			if done, err := fixture.generation.spool.ReclaimAcknowledged(ctx, fixture.receipts, lineageReclaimRequest{Source: assignment.Source, Destination: assignment.Destination, ConsumerUID: assignment.ConsumerUID}); err != nil || !done {
				t.Fatal(err)
			}
		}
		if done, err := slots.Retire(ctx, assignment, 16); err != nil || !done {
			t.Fatal("repeated retirement", round, done, err)
		}
		if done, err := fixture.generation.spool.CollectCompletion(ctx, fixture.receipts, lineageReclaimRequest{Source: assignment.Source, Destination: assignment.Destination, ConsumerUID: assignment.ConsumerUID}); err != nil || !done {
			t.Fatal(err)
		}
		if done, err := slots.Release(ctx, assignment); err != nil || !done {
			t.Fatal("repeated release", round, done, err)
		}
		for path, want := range map[string]int{slots.root.Name(): 2, fixture.ackPath: 1, fixture.generation.spool.root.Name(): 1} {
			if entries, err := os.ReadDir(path); err != nil || len(entries) != want {
				t.Fatal("history grew across reuse", round, len(entries), want, err)
			}
		}
	}
}

func TestLineageSlotRetirementReleasesOnlyAfterProducerCollection(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	ctx := context.Background()
	if done, err := slots.Retire(ctx, assignment, 16); err != nil || !done {
		t.Fatal("authenticated slot retirement", done, err)
	}
	if _, err := os.Lstat(filepath.Join(slots.root.Name(), lineageSlotCursor(assignment.Slot))); !os.IsNotExist(err) {
		t.Fatal("checkpoint remains", err)
	}
	if done, err := slots.Release(ctx, assignment); err != nil || done {
		t.Fatal("slot released before producer collection", done, err)
	}
	if done, err := fixture.generation.spool.CollectCompletion(ctx, fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	if done, err := slots.Release(ctx, assignment); err != nil || !done {
		t.Fatal("authenticated slot release", done, err)
	}
	if done, err := slots.Release(ctx, assignment); err != nil || !done {
		t.Fatal("durable clean retry", done, err)
	}
	entries, err := os.ReadDir(slots.root.Name())
	if err != nil || len(entries) != 2 {
		t.Fatal("retirement left unbounded history", len(entries), err)
	}
	list, err := slots.List(ctx)
	if err != nil || len(list) != 0 {
		t.Fatal("released assignment remains", list, err)
	}
	source := assignment.Source
	source.GenerationID = "99999999-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	generation, err := fixture.generation.spool.Create(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	generation.Close()
	reader, err := newLineageSpoolReader(filepath.Join(fixture.generation.spool.root.Name(), "generation-"+source.GenerationID), source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	fresh, err := slots.Reserve(ctx, reader)
	if err != nil || fresh.Slot != assignment.Slot {
		t.Fatal("fixed slot wasn't reused", fresh, err)
	}
	before := recoveryEvidence(t, slots.root.Name())
	if done, err := slots.Release(ctx, assignment); err == nil || done {
		t.Fatal("stale release accepted against new assignment", done, err)
	}
	if !bytes.Equal(before, recoveryEvidence(t, slots.root.Name())) {
		t.Fatal("stale release changed new history")
	}
}
