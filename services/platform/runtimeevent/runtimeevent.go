package runtimeevent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/observability"
	"github.com/zasp-ai/zasp-sec/services/platform/securityevent"
)

var (
	ErrInput       = errors.New("runtime event input rejected")
	ErrHealth      = errors.New("sensor health rejected")
	ErrFilter      = errors.New("runtime event filter rejected")
	ErrBatch       = errors.New("runtime event batch rejected")
	ErrWorker      = errors.New("runtime event worker rejected")
	ErrCorrelation = errors.New("runtime event correlation rejected")
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

type Record struct {
	ID            domain.ProductID
	Scope         domain.Scope
	Event         securityevent.SecurityEvent
	Source        string
	SourceEventID string
	Class         string
	Action        string
	WorkloadID    string
	AgentID       domain.ProductID
	SessionID     domain.ProductID
	TaskID        string
	ToolID        string
	SandboxID     string
	ContainerID   string
	CgroupID      string
	ProcessID     string
	TraceID       string
	SpanID        string
	EventTime     time.Time
	Content       map[string]string
}

type TetragonInput struct {
	Scope         domain.Scope
	SourceEventID string
	Kind          string
	Action        string
	WorkloadID    string
	EventTime     time.Time
	EvidenceID    domain.ProductID
	Content       map[string]string
}

type OTLPInput struct {
	Scope      domain.Scope
	EventTime  time.Time
	EvidenceID domain.ProductID
	Attributes map[string]string
	Content    map[string]string
}

func AdaptTetragon(input TetragonInput) (Record, error) {
	allowed := map[string]map[string]bool{
		"process": {"exec": true, "exit": true},
		"file":    {"read": true, "write": true},
		"network": {"connect": true, "accept": true},
	}
	if input.Scope.Validate() != nil || !allowed[input.Kind][input.Action] || !bounded(input.SourceEventID, 256) ||
		!bounded(input.WorkloadID, 256) || !canonicalTime(input.EventTime) || input.EvidenceID.IsZero() || !validContent(input.Content) {
		return Record{}, ErrInput
	}
	trace := digestHex("trace\x00" + input.SourceEventID)[:32]
	span := digestHex("span\x00" + input.SourceEventID)[:16]
	return buildRecord(input.Scope, "tetragon", input.SourceEventID, input.Kind, input.Action, input.WorkloadID,
		domain.ProductID{}, domain.ProductID{}, "", "", "", "", "", "", trace, span, input.EventTime, input.EvidenceID, input.Content)
}

func AdaptOTLP(input OTLPInput) (Record, error) {
	if input.Scope.Validate() != nil || !canonicalTime(input.EventTime) || input.EvidenceID.IsZero() || !validContent(input.Content) || len(input.Attributes) != 10 {
		return Record{}, ErrInput
	}
	expected := []string{"event.id", "event.class", "event.action", "agent.id", "session.id", "task.id", "tool.id", "sandbox.id", "trace.id", "span.id"}
	for _, key := range expected {
		if _, ok := input.Attributes[key]; !ok {
			return Record{}, ErrInput
		}
	}
	agentID, agentErr := domain.ParseProductID(input.Attributes["agent.id"])
	sessionID, sessionErr := domain.ParseProductID(input.Attributes["session.id"])
	if agentErr != nil || sessionErr != nil || input.Attributes["event.class"] != "tool" || input.Attributes["event.action"] != "invoke" ||
		!bounded(input.Attributes["event.id"], 256) || !bounded(input.Attributes["task.id"], 256) || !bounded(input.Attributes["tool.id"], 256) || !bounded(input.Attributes["sandbox.id"], 256) {
		return Record{}, ErrInput
	}
	return buildRecord(input.Scope, "otlp", input.Attributes["event.id"], "tool", "invoke", "", agentID, sessionID,
		input.Attributes["task.id"], input.Attributes["tool.id"], input.Attributes["sandbox.id"], "", "", "",
		input.Attributes["trace.id"], input.Attributes["span.id"], input.EventTime, input.EvidenceID, input.Content)
}

func buildRecord(scope domain.Scope, source, sourceEventID, class, action, workload string, agentID, sessionID domain.ProductID,
	taskID, toolID, sandboxID, containerID, cgroupID, processID, traceID, spanID string, eventTime time.Time, evidenceID domain.ProductID, content map[string]string,
) (Record, error) {
	id, err := deterministicID(scopeIdentity(scope) + "\x00" + source + "\x00" + sourceEventID)
	if err != nil {
		return Record{}, ErrInput
	}
	evidence, err := domain.NewEvidenceRef(evidenceID)
	if err != nil {
		return Record{}, ErrInput
	}
	correlationID, err := domain.NewCorrelationID(id)
	if err != nil {
		return Record{}, ErrInput
	}
	correlation, err := observability.NewCorrelation(correlationID, traceID, spanID)
	if err != nil {
		return Record{}, ErrInput
	}
	eventSource := securityevent.SourceOTLP
	if source == "tetragon" {
		eventSource = securityevent.SourceTetragon
	}
	event, err := securityevent.New(securityevent.Version1, scope, eventSource, eventTime, evidence, correlation)
	if err != nil {
		return Record{}, ErrInput
	}
	record := Record{ID: id, Scope: scope, Event: event, Source: source, SourceEventID: sourceEventID, Class: class, Action: action,
		WorkloadID: workload, AgentID: agentID, SessionID: sessionID, TaskID: taskID, ToolID: toolID, SandboxID: sandboxID,
		ContainerID: containerID, CgroupID: cgroupID, ProcessID: processID, TraceID: traceID, SpanID: spanID,
		EventTime: eventTime, Content: cloneContent(content)}
	if !validRecord(record) {
		return Record{}, ErrInput
	}
	return record, nil
}

type SensorHealthInput struct {
	Kernel    string
	BTF       bool
	CPUMilli  uint64
	MemoryMiB uint64
	EventRate uint64
	Drops     uint64
}

type SensorHealth struct {
	Kernel    string
	BTF       bool
	CPUMilli  uint64
	MemoryMiB uint64
	EventRate uint64
	Drops     uint64
	DropRatio float64
	Status    string
}

func EvaluateSensorHealth(input SensorHealthInput) (SensorHealth, error) {
	if !bounded(input.Kernel, 128) || input.CPUMilli > 100_000 || input.MemoryMiB > 1_048_576 || input.EventRate > 1_000_000_000 || input.Drops > input.EventRate {
		return SensorHealth{}, ErrHealth
	}
	ratio := float64(0)
	if input.EventRate > 0 {
		ratio = float64(input.Drops) / float64(input.EventRate)
	}
	status := "supported"
	if !input.BTF {
		status = "unsupported"
	} else if ratio > 0.01 {
		status = "degraded"
	}
	return SensorHealth{Kernel: input.Kernel, BTF: input.BTF, CPUMilli: input.CPUMilli, MemoryMiB: input.MemoryMiB, EventRate: input.EventRate, Drops: input.Drops, DropRatio: ratio, Status: status}, nil
}

func FilterRecord(record Record, mode string) (Record, error) {
	if !validRecord(record) || mode != "full" && mode != "metadata_only" {
		return Record{}, ErrFilter
	}
	result := cloneRecord(record)
	if mode == "metadata_only" {
		result.Content = map[string]string{}
	}
	return result, nil
}

type Batch struct {
	ID         domain.ProductID
	Scope      domain.Scope
	Date       time.Time
	Records    []Record
	Encoded    []byte
	Compressed []byte
}

func BuildBatches(records []Record, maximumCount, maximumBytes int) ([]Batch, error) {
	if len(records) == 0 || maximumCount <= 0 || maximumCount > 1000 || maximumBytes <= 0 || maximumBytes > 1_048_576 {
		return nil, ErrBatch
	}
	result := []Batch{}
	for start := 0; start < len(records); {
		end := start + maximumCount
		if end > len(records) {
			end = len(records)
		}
		var selected Batch
		for end > start {
			candidate, err := makeBatch(records[start:end])
			if err != nil {
				return nil, ErrBatch
			}
			if len(candidate.Encoded) <= maximumBytes {
				selected = candidate
				break
			}
			end--
		}
		if len(selected.Records) == 0 {
			return nil, ErrBatch
		}
		result = append(result, selected)
		start += len(selected.Records)
	}
	return result, nil
}

func makeBatch(records []Record) (Batch, error) {
	if len(records) == 0 {
		return Batch{}, ErrBatch
	}
	scope, date := records[0].Scope, records[0].EventTime
	identity := strings.Builder{}
	wires := make([]wireRecord, len(records))
	for index, record := range records {
		if !validRecord(record) || record.Scope != scope || record.EventTime.Year() != date.Year() || record.EventTime.YearDay() != date.YearDay() {
			return Batch{}, ErrBatch
		}
		identity.WriteString(record.ID.String())
		identity.WriteByte(0)
		wires[index] = toWire(record)
	}
	id, err := deterministicID(scopeIdentity(scope) + "\x00batch\x00" + identity.String())
	if err != nil {
		return Batch{}, ErrBatch
	}
	payload := struct {
		BatchID string       `json:"batch_id"`
		Events  []wireRecord `json:"events"`
	}{BatchID: id.String(), Events: wires}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Batch{}, ErrBatch
	}
	compressed, err := compress(encoded)
	if err != nil {
		return Batch{}, ErrBatch
	}
	return Batch{ID: id, Scope: scope, Date: date, Records: cloneRecords(records), Encoded: encoded, Compressed: compressed}, nil
}

func compress(payload []byte) ([]byte, error) {
	var destination bytes.Buffer
	writer := gzip.NewWriter(&destination)
	if _, err := writer.Write(payload); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return destination.Bytes(), nil
}

type wireRecord struct {
	ID            string            `json:"id"`
	Source        string            `json:"source"`
	SourceEventID string            `json:"source_event_id"`
	Class         string            `json:"class"`
	Action        string            `json:"action"`
	WorkloadID    string            `json:"workload_id,omitempty"`
	AgentID       string            `json:"agent_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	TaskID        string            `json:"task_id,omitempty"`
	ToolID        string            `json:"tool_id,omitempty"`
	SandboxID     string            `json:"sandbox_id,omitempty"`
	TraceID       string            `json:"trace_id"`
	SpanID        string            `json:"span_id"`
	EventTime     string            `json:"event_time"`
	Content       map[string]string `json:"content"`
}

func toWire(record Record) wireRecord {
	return wireRecord{ID: record.ID.String(), Source: record.Source, SourceEventID: record.SourceEventID, Class: record.Class, Action: record.Action,
		WorkloadID: record.WorkloadID, AgentID: record.AgentID.String(), SessionID: record.SessionID.String(), TaskID: record.TaskID, ToolID: record.ToolID,
		SandboxID: record.SandboxID, TraceID: record.TraceID, SpanID: record.SpanID, EventTime: record.EventTime.Format(timestampLayout), Content: cloneContent(record.Content)}
}

type Candidate struct {
	SessionID   domain.ProductID
	AgentID     domain.ProductID
	SandboxID   string
	ContainerID string
	CgroupID    string
	ProcessID   string
}

type CorrelationResult struct {
	SessionID  domain.ProductID
	AgentID    domain.ProductID
	Confidence domain.EvidenceConfidence
}

func Correlate(record Record, candidates []Candidate) CorrelationResult {
	if !validCorrelationRecord(record) || len(candidates) == 0 || len(candidates) > 1000 {
		return CorrelationResult{Confidence: domain.EvidenceConfidenceUnattributed}
	}
	if !record.SessionID.IsZero() && !record.AgentID.IsZero() {
		matches := []Candidate{}
		for _, candidate := range candidates {
			if candidate.SessionID == record.SessionID && candidate.AgentID == record.AgentID {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			return CorrelationResult{SessionID: matches[0].SessionID, AgentID: matches[0].AgentID, Confidence: domain.EvidenceConfidenceExact}
		}
	}
	matches := []Candidate{}
	for _, candidate := range candidates {
		if lineageMatch(record, candidate) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 1 {
		return CorrelationResult{SessionID: matches[0].SessionID, AgentID: matches[0].AgentID, Confidence: domain.EvidenceConfidenceStrong}
	}
	if len(matches) > 1 {
		return CorrelationResult{Confidence: domain.EvidenceConfidenceProbable}
	}
	return CorrelationResult{Confidence: domain.EvidenceConfidenceUnattributed}
}

func validCorrelationRecord(record Record) bool {
	if !validRecordEnvelope(record) {
		return false
	}
	return record.AgentID.IsZero() == record.SessionID.IsZero()
}

func lineageMatch(record Record, candidate Candidate) bool {
	fields := [][2]string{{record.SandboxID, candidate.SandboxID}, {record.ContainerID, candidate.ContainerID}, {record.CgroupID, candidate.CgroupID}, {record.ProcessID, candidate.ProcessID}}
	matched := 0
	for _, pair := range fields {
		if pair[0] != "" && pair[0] == pair[1] {
			matched++
		}
	}
	return matched >= 2
}

type Delivery struct {
	Batch       Batch
	Acknowledge func(context.Context) error
}

type Archiver interface {
	Archive(context.Context, Batch) (string, error)
}
type Indexer interface {
	Index(context.Context, Record, string) error
}
type CorrelationWriter interface {
	WriteCorrelation(context.Context, Record, string) error
}

type Worker struct {
	archive Archiver
	index   Indexer
	write   CorrelationWriter
}

func NewWorker(archive Archiver, index Indexer, write CorrelationWriter) (*Worker, error) {
	if archive == nil || index == nil || write == nil {
		return nil, ErrWorker
	}
	return &Worker{archive: archive, index: index, write: write}, nil
}

func (worker *Worker) Process(ctx context.Context, delivery Delivery) error {
	if worker == nil || worker.archive == nil || worker.index == nil || worker.write == nil || ctx == nil || delivery.Acknowledge == nil || !validBatch(delivery.Batch) {
		return ErrWorker
	}
	archiveKey, err := safeArchive(worker.archive, ctx, delivery.Batch)
	if err != nil || archiveKey == "" {
		return ErrWorker
	}
	for _, record := range delivery.Batch.Records {
		if safeIndex(worker.index, ctx, record, archiveKey) != nil {
			return ErrWorker
		}
	}
	for _, record := range delivery.Batch.Records {
		if safeCorrelation(worker.write, ctx, record, archiveKey) != nil {
			return ErrWorker
		}
	}
	if safeAcknowledge(delivery.Acknowledge, ctx) != nil {
		return ErrWorker
	}
	return nil
}

type MemoryDurable struct {
	mu           sync.Mutex
	archives     map[domain.ProductID]memoryArchive
	indexed      map[domain.ProductID]string
	correlations map[domain.ProductID]string
}

type memoryArchive struct {
	key     string
	payload []byte
}

func NewMemoryDurable() *MemoryDurable {
	return &MemoryDurable{archives: map[domain.ProductID]memoryArchive{}, indexed: map[domain.ProductID]string{}, correlations: map[domain.ProductID]string{}}
}

func (store *MemoryDurable) Archive(_ context.Context, batch Batch) (string, error) {
	if store == nil || !validBatch(batch) {
		return "", ErrWorker
	}
	key := "organizations/" + batch.Scope.OrganizationID().String() + "/runtime-events/" + batch.Date.Format("2006/01/02") + "/" + batch.ID.String() + ".json.gz"
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.archives[batch.ID]; ok {
		if existing.key != key || !bytes.Equal(existing.payload, batch.Compressed) {
			return "", ErrWorker
		}
		return key, nil
	}
	store.archives[batch.ID] = memoryArchive{key: key, payload: append([]byte(nil), batch.Compressed...)}
	return key, nil
}

func (store *MemoryDurable) Index(_ context.Context, record Record, archiveKey string) error {
	if store == nil || !validRecord(record) || !validArchiveKey(record.Scope, archiveKey) {
		return ErrWorker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.indexed[record.ID]; ok && existing != archiveKey {
		return ErrWorker
	}
	store.indexed[record.ID] = archiveKey
	return nil
}

func (store *MemoryDurable) WriteCorrelation(_ context.Context, record Record, archiveKey string) error {
	if store == nil || !validRecord(record) || !validArchiveKey(record.Scope, archiveKey) {
		return ErrWorker
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.correlations[record.ID]; ok && existing != archiveKey {
		return ErrWorker
	}
	store.correlations[record.ID] = archiveKey
	return nil
}

func (store *MemoryDurable) ArchiveCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.archives)
}
func (store *MemoryDurable) IndexCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.indexed)
}
func (store *MemoryDurable) CorrelationCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.correlations)
}
func (store *MemoryDurable) ArchiveKey(id domain.ProductID) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.archives[id].key
}
func (store *MemoryDurable) ArchivePayload(id domain.ProductID) []byte {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]byte(nil), store.archives[id].payload...)
}

func validBatch(batch Batch) bool {
	if batch.ID.IsZero() || batch.Scope.Validate() != nil || !canonicalTime(batch.Date) || len(batch.Records) == 0 || len(batch.Encoded) == 0 || len(batch.Compressed) == 0 {
		return false
	}
	expected, err := makeBatch(batch.Records)
	return err == nil && expected.ID == batch.ID && expected.Scope == batch.Scope && expected.Date == batch.Date &&
		bytes.Equal(expected.Encoded, batch.Encoded) && bytes.Equal(expected.Compressed, batch.Compressed)
}

func validRecord(record Record) bool {
	if !validRecordEnvelope(record) {
		return false
	}
	if record.Source == "tetragon" {
		allowed := map[string]map[string]bool{
			"process": {"exec": true, "exit": true},
			"file":    {"read": true, "write": true},
			"network": {"connect": true, "accept": true},
		}
		return bounded(record.WorkloadID, 256) && allowed[record.Class][record.Action]
	}
	return record.Source == "otlp" && record.Class == "tool" && record.Action == "invoke" && !record.AgentID.IsZero() && !record.SessionID.IsZero() && bounded(record.TaskID, 256) && bounded(record.ToolID, 256) && bounded(record.SandboxID, 256)
}

func validRecordEnvelope(record Record) bool {
	if record.ID.IsZero() || record.Scope.Validate() != nil || record.Event.Validate() != nil || !canonicalTime(record.EventTime) ||
		!bounded(record.SourceEventID, 256) || !validContent(record.Content) || record.Event.Time != record.EventTime || record.Event.Scope != record.Scope {
		return false
	}
	expectedSource := securityevent.SourceOTLP
	if record.Source == "tetragon" {
		expectedSource = securityevent.SourceTetragon
	} else if record.Source != "otlp" {
		return false
	}
	return record.Event.Source == expectedSource
}

func validContent(content map[string]string) bool {
	if len(content) > 64 {
		return false
	}
	for key, value := range content {
		if !bounded(key, 64) || !bounded(value, 4096) {
			return false
		}
	}
	return true
}

func cloneContent(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func cloneRecord(value Record) Record { value.Content = cloneContent(value.Content); return value }
func cloneRecords(values []Record) []Record {
	result := make([]Record, len(values))
	for index, value := range values {
		result[index] = cloneRecord(value)
	}
	return result
}

func deterministicID(value string) (domain.ProductID, error) {
	digest := sha256.Sum256([]byte(value))
	digest[6] = (digest[6] & 0x0f) | 0x40
	digest[8] = (digest[8] & 0x3f) | 0x80
	text := hex.EncodeToString(digest[:16])
	return domain.ParseProductID(fmt.Sprintf("pid_%s-%s-%s-%s-%s", text[:8], text[8:12], text[12:16], text[16:20], text[20:32]))
}

func scopeIdentity(scope domain.Scope) string {
	return scope.OrganizationID().String() + "\x00" + scope.WorkspaceID().String() + "\x00" + scope.EnvironmentID().String()
}

func digestHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
func canonicalTime(value time.Time) bool {
	if value.IsZero() || value.Location() != time.UTC || value.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	parsed, err := time.Parse(timestampLayout, value.Format(timestampLayout))
	return err == nil && parsed == value
}
func validArchiveKey(scope domain.Scope, key string) bool {
	return scope.Validate() == nil && strings.HasPrefix(key, "organizations/"+scope.OrganizationID().String()+"/runtime-events/") && !strings.Contains(key, "..")
}

func safeArchive(value Archiver, ctx context.Context, batch Batch) (key string, err error) {
	defer func() {
		if recover() != nil {
			key, err = "", ErrWorker
		}
	}()
	return value.Archive(ctx, batch)
}
func safeIndex(value Indexer, ctx context.Context, record Record, key string) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorker
		}
	}()
	return value.Index(ctx, record, key)
}
func safeCorrelation(value CorrelationWriter, ctx context.Context, record Record, key string) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorker
		}
	}()
	return value.WriteCorrelation(ctx, record, key)
}
func safeAcknowledge(value func(context.Context) error, ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWorker
		}
	}()
	return value(ctx)
}

func SortedIndexDocuments(records []Record, archiveKey string) ([]map[string]string, error) {
	result := make([]map[string]string, len(records))
	for index, record := range records {
		if !validRecord(record) || !validArchiveKey(record.Scope, archiveKey) {
			return nil, ErrWorker
		}
		result[index] = map[string]string{"organization_id": record.Scope.OrganizationID().String(), "workspace_id": record.Scope.WorkspaceID().String(), "environment_id": record.Scope.EnvironmentID().String(), "event_id": record.ID.String(), "session_id": record.SessionID.String(), "agent_id": record.AgentID.String(), "source": record.Source, "source_event_id": record.SourceEventID, "event_class": record.Class, "action": record.Action, "event_time": record.EventTime.Format(timestampLayout), "archive_key": archiveKey}
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["event_id"] < result[j]["event_id"] })
	return result, nil
}
