package runtimeindex

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestStoreIndexesExactArchivedBatchDeterministically(t *testing.T) {
	scope := testScope(t, 1)
	body := testBody(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	digest := sha256.Sum256(body)
	driver := &driverStub{}
	store, err := New(driver, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
	if err != nil {
		t.Fatal(err)
	}
	input := Batch{Scope: scope, BatchID: testID(t, 9), Generation: 3, InputDigest: digest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "version-0001", Body: body}
	result, err := store.Apply(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.BatchID != input.BatchID || result.Generation != 3 || result.InputDigest != digest || result.ContentDigest == ([sha256.Size]byte{}) || len(result.DocumentIDs) != 1 || result.DocumentIDs[0] == "" || driver.calls != 1 {
		t.Fatalf("result=%#v calls=%d", result, driver.calls)
	}
	if driver.input.Scope != scope || driver.input.BatchID != input.BatchID.String() || driver.input.Generation != 3 || driver.input.InputDigest != digest || driver.input.ContentDigest != result.ContentDigest || driver.input.ArchiveReference != input.ArchiveReference || driver.input.ArchiveVersionID != input.ArchiveVersionID || len(driver.input.Documents) != 1 {
		t.Fatalf("driver input=%#v", driver.input)
	}
	document := driver.input.Documents[0]
	if document.RecordType != "runtime_event" || document.Source != "tetragon" || document.SourceEventID != "event-1" || document.EventClass != "process" || document.Action != "exec" || document.WorkloadID != "runtime-a" || document.EventTime != "2026-08-20T12:00:00.000Z" || document.EvidenceID == "" || document.ArchiveReference != input.ArchiveReference || document.ArchiveVersionID != input.ArchiveVersionID {
		t.Fatalf("document=%#v", document)
	}
	if got := sha256.Sum256(input.Body); got != digest {
		t.Fatal("store mutated caller body")
	}
}

func TestStoreRejectsDriftBeforeDriverAndFailsClosedOnHostileDriver(t *testing.T) {
	scope := testScope(t, 1)
	body := testBody(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	digest := sha256.Sum256(body)
	valid := Batch{Scope: scope, BatchID: testID(t, 9), Generation: 3, InputDigest: digest, ArchiveReference: "s3://zasp-evidence/runtime/v15/raw.json", ArchiveVersionID: "version-0001", Body: body}
	for _, test := range []struct {
		name   string
		mutate func(*Batch)
	}{
		{name: "scope", mutate: func(value *Batch) { value.Scope = domain.Scope{} }},
		{name: "batch", mutate: func(value *Batch) { value.BatchID = domain.ProductID{} }},
		{name: "generation", mutate: func(value *Batch) { value.Generation = 0 }},
		{name: "digest", mutate: func(value *Batch) { value.InputDigest = sha256.Sum256([]byte("drift")) }},
		{name: "reference", mutate: func(value *Batch) { value.ArchiveReference = "https://untrusted.invalid/raw" }},
		{name: "version", mutate: func(value *Batch) { value.ArchiveVersionID = "bad\nversion" }},
		{name: "body", mutate: func(value *Batch) { value.Body = []byte(`{"source":"tetragon","events":[]}`) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver := &driverStub{}
			store, _ := New(driver, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
			input := valid
			input.Body = append([]byte(nil), valid.Body...)
			test.mutate(&input)
			if result, err := store.Apply(context.Background(), input); err != ErrInput || result.BatchID != (domain.ProductID{}) || result.DocumentIDs != nil || driver.calls != 0 {
				t.Fatalf("result=%#v err=%v calls=%d", result, err, driver.calls)
			}
		})
	}

	driver := &driverStub{mutateResult: true}
	store, _ := New(driver, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
	if result, err := store.Apply(context.Background(), valid); err != ErrDrift || result.BatchID != (domain.ProductID{}) || result.DocumentIDs != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

type driverStub struct {
	input        DriverBatch
	calls        int
	mutateResult bool
}

func (stub *driverStub) Apply(_ context.Context, input DriverBatch) (DriverResult, error) {
	stub.calls++
	stub.input = input
	result := DriverResult{BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: input.ContentDigest, DocumentIDs: make([]string, len(input.Documents))}
	for index, document := range input.Documents {
		result.DocumentIDs[index] = document.DocumentID
	}
	if stub.mutateResult {
		result.ContentDigest = sha256.Sum256([]byte("drift"))
	}
	return result, nil
}

func testBody(now time.Time) []byte {
	return []byte(`{"source":"tetragon","events":[{"event_id":"event-1","class":"process","action":"exec","workload_id":"runtime-a","event_time":"` + now.Format("2006-01-02T15:04:05.000Z") + `","evidence_id":"pid_79000001-0000-4000-8000-000000000001","content":{"binary":"agent"}}]}`)
}

func testID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testScope(t *testing.T, value int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(testID(t, value), testID(t, value+1), testID(t, value+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

var _ Driver = (*driverStub)(nil)
