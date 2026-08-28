package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/graphstore"
	"github.com/zasp-ai/zasp-sec/services/platform/inventorysearch"
)

const recoveryProjectionPageSQL = `SELECT zasp_recovery_projection_page($1,$2,$3,$4,$5,$6,$7)`

var recoveryProjectionTextPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+-]+$`)

type recoveryProjectionPageDatabase interface {
	ProjectionPage(context.Context, string, string, string, string, string, string, int) (apiserver.SnapshotProjectionPage, error)
}

type recoveryProjectionCollectionCursor struct {
	CommittedAt string `json:"committed_at"`
	CursorValue string `json:"cursor_value"`
	Provider    string `json:"provider"`
	SnapshotID  string `json:"snapshot_id"`
}

type recoveryProjectionCursor struct {
	DriverDigest string `json:"driver_digest"`
	Generation   int64  `json:"generation"`
	InputDigest  string `json:"input_digest"`
	Kind         string `json:"kind"`
	SnapshotID   string `json:"snapshot_id"`
	Source       string `json:"source"`
	UpdatedAt    string `json:"updated_at"`
}

type recoveryProjectionSnapshotInput struct {
	CandidateDigest       string `json:"candidate_digest"`
	Generation            int64  `json:"generation"`
	ManifestChecksum      string `json:"manifest_checksum"`
	ManifestKey           string `json:"manifest_key"`
	ManifestMediaType     string `json:"manifest_media_type"`
	ManifestReference     string `json:"manifest_reference"`
	ManifestSchemaVersion string `json:"manifest_schema_version"`
	ManifestSizeBytes     int64  `json:"manifest_size_bytes"`
	ManifestVersionID     string `json:"manifest_version_id"`
	ParserVersion         string `json:"parser_version"`
	SnapshotID            string `json:"snapshot_id"`
	Source                string `json:"source"`
	ToolVersion           string `json:"tool_version"`
}

type recoveryProjectionDescriptor struct {
	CollectionCursors []recoveryProjectionCollectionCursor `json:"collection_cursors"`
	IntegrationID     string                               `json:"integration_id"`
	ProjectionCursors []recoveryProjectionCursor           `json:"projection_cursors"`
	SnapshotInputs    []recoveryProjectionSnapshotInput    `json:"snapshot_inputs"`
}

func (database *postgresRecoveryJobDatabase) ProjectionPage(ctx context.Context, organization, workspace, environment, snapshotID, section, afterID string, limit int) (apiserver.SnapshotProjectionPage, error) {
	if database == nil || database.pool == nil || ctx == nil || ctx.Err() != nil {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	var payload json.RawMessage
	if err := database.pool.QueryRow(ctx, recoveryProjectionPageSQL, organization, workspace, environment, snapshotID, section, nullableRecoveryCursor(afterID), limit).Scan(&payload); err != nil || len(payload) < 2 || len(payload) > 64<<20 {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	return decodeRecoveryProjectionPage(payload)
}

func nullableRecoveryCursor(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func decodeRecoveryProjectionPage(payload json.RawMessage) (apiserver.SnapshotProjectionPage, error) {
	var wire struct {
		SnapshotID            string            `json:"snapshot_id"`
		IntegrationID         string            `json:"integration_id"`
		Source                string            `json:"source"`
		Generation            int64             `json:"generation"`
		CandidateDigest       string            `json:"candidate_digest"`
		ManifestReference     string            `json:"manifest_reference"`
		ManifestKey           string            `json:"manifest_key"`
		ManifestVersionID     string            `json:"manifest_version_id"`
		ManifestChecksum      string            `json:"manifest_checksum"`
		ManifestSizeBytes     int64             `json:"manifest_size_bytes"`
		ManifestMediaType     string            `json:"manifest_media_type"`
		ManifestSchemaVersion string            `json:"manifest_schema_version"`
		ParserVersion         string            `json:"parser_version"`
		ToolVersion           string            `json:"tool_version"`
		Section               string            `json:"section"`
		Items                 []json.RawMessage `json:"items"`
		NextID                *string           `json:"next_id"`
	}
	if decodeStrictWorkerJSON(payload, &wire) != nil {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	candidate, candidateErr := hex.DecodeString(wire.CandidateDigest)
	manifest, manifestErr := hex.DecodeString(wire.ManifestChecksum)
	if candidateErr != nil || manifestErr != nil || len(candidate) != sha256.Size || len(manifest) != sha256.Size {
		return apiserver.SnapshotProjectionPage{}, errWorkerExecution
	}
	return apiserver.SnapshotProjectionPage{
		SnapshotID: wire.SnapshotID, IntegrationID: wire.IntegrationID, Source: wire.Source, Generation: wire.Generation, CandidateDigest: candidate,
		ManifestReference: wire.ManifestReference, ManifestKey: wire.ManifestKey, ManifestVersionID: wire.ManifestVersionID, ManifestChecksum: manifest,
		ManifestSizeBytes: wire.ManifestSizeBytes, ManifestMediaType: wire.ManifestMediaType, ManifestSchemaVersion: wire.ManifestSchemaVersion,
		ParserVersion: wire.ParserVersion, ToolVersion: wire.ToolVersion, Section: wire.Section, Items: cloneRawMessages(wire.Items), NextID: wire.NextID,
	}, nil
}

func runRecoveryProjectionRebuild(ctx context.Context, config recoveryJobConfig, database recoveryJobDatabase, raw json.RawMessage, kind string) error {
	pageDatabase, ok := database.(recoveryProjectionPageDatabase)
	if !ok || ctx == nil || ctx.Err() != nil || !stringInWorker(kind, "graph", "search") {
		return errWorkerExecution
	}
	var descriptors []recoveryProjectionDescriptor
	if decodeStrictWorkerJSON(raw, &descriptors) != nil || !validRecoveryProjectionDescriptors(descriptors) {
		return errWorkerExecution
	}
	target, err := newRecoveryProjectionTarget(config.TargetDirectory, kind)
	if err != nil {
		return errWorkerExecution
	}
	matched := 0
	for _, descriptor := range descriptors {
		for _, cursor := range descriptor.ProjectionCursors {
			if cursor.Kind != kind {
				continue
			}
			input, found := recoveryProjectionInput(descriptor.SnapshotInputs, cursor)
			if !found {
				return errWorkerExecution
			}
			candidate, loadErr := loadRecoveryProjectionCandidate(ctx, config, pageDatabase, descriptor.IntegrationID, cursor, input)
			if loadErr != nil {
				return errWorkerExecution
			}
			result, applyErr := target.Apply(ctx, candidate)
			expected, digestErr := hex.DecodeString(cursor.DriverDigest)
			if applyErr != nil || digestErr != nil || len(expected) != sha256.Size || !bytes.Equal(result.Digest[:], expected) {
				return errWorkerExecution
			}
			matched++
		}
	}
	if matched == 0 {
		return target.PersistEmpty(ctx)
	}
	return nil
}

func validRecoveryProjectionDescriptors(descriptors []recoveryProjectionDescriptor) bool {
	if len(descriptors) > 10_000 {
		return false
	}
	previousIntegration := ""
	for _, descriptor := range descriptors {
		if !validRecoveryProjectionProductID(descriptor.IntegrationID) || descriptor.IntegrationID <= previousIntegration || len(descriptor.CollectionCursors) > 16 || len(descriptor.ProjectionCursors) > 12 || len(descriptor.SnapshotInputs) > 16 {
			return false
		}
		previousIntegration = descriptor.IntegrationID
		previousCursor, previousInput := "", ""
		for _, cursor := range descriptor.CollectionCursors {
			key := cursor.Provider + "\x00" + cursor.SnapshotID
			if !stringInWorker(cursor.Provider, "aws", "kubernetes", "github", "okta") || !validRecoveryProjectionProductID(cursor.SnapshotID) || len(cursor.CursorValue) > 2048 || !validRecoveryTimestamp(cursor.CommittedAt) || key <= previousCursor {
				return false
			}
			previousCursor = key
		}
		previousCursor = ""
		for _, cursor := range descriptor.ProjectionCursors {
			key := cursor.Source + "\x00" + cursor.Kind
			if !stringInWorker(cursor.Source, "aws", "kubernetes", "github", "okta") || !stringInWorker(cursor.Kind, "risk", "graph", "search") || cursor.Generation < 1 || !validRecoveryProjectionProductID(cursor.SnapshotID) || !validRecoveryDigest(cursor.InputDigest) || !validRecoveryDigest(cursor.DriverDigest) || !validRecoveryTimestamp(cursor.UpdatedAt) || key <= previousCursor {
				return false
			}
			previousCursor = key
		}
		for _, input := range descriptor.SnapshotInputs {
			key := input.Source + "\x00" + leftPadRecoveryGeneration(input.Generation)
			if !stringInWorker(input.Source, "aws", "kubernetes", "github", "okta") || input.Generation < 1 || !validRecoveryProjectionProductID(input.SnapshotID) || !validRecoveryDigest(input.CandidateDigest) || !validRecoveryDigest(input.ManifestChecksum) || input.ManifestSizeBytes < 1 || input.ManifestSizeBytes > 512<<20 || !validRecoveryProjectionText(input.ManifestReference, 2048) || !validRecoveryProjectionText(input.ManifestKey, 1024) || !validRecoveryProjectionText(input.ManifestVersionID, 1024) || !validRecoveryProjectionText(input.ManifestMediaType, 128) || !validRecoveryProjectionText(input.ManifestSchemaVersion, 64) || !validRecoveryProjectionText(input.ParserVersion, 64) || !validRecoveryProjectionText(input.ToolVersion, 64) || key <= previousInput {
				return false
			}
			previousInput = key
		}
		for _, cursor := range descriptor.ProjectionCursors {
			if _, found := recoveryProjectionInput(descriptor.SnapshotInputs, cursor); !found {
				return false
			}
		}
	}
	return true
}

func recoveryProjectionInput(inputs []recoveryProjectionSnapshotInput, cursor recoveryProjectionCursor) (recoveryProjectionSnapshotInput, bool) {
	for _, input := range inputs {
		if input.Source == cursor.Source && input.SnapshotID == cursor.SnapshotID && input.Generation == cursor.Generation && input.CandidateDigest == cursor.InputDigest {
			return input, true
		}
	}
	return recoveryProjectionSnapshotInput{}, false
}

func loadRecoveryProjectionCandidate(ctx context.Context, config recoveryJobConfig, database recoveryProjectionPageDatabase, integrationID string, cursor recoveryProjectionCursor, input recoveryProjectionSnapshotInput) (projectionCandidate, error) {
	digest, err := hex.DecodeString(cursor.InputDigest)
	if err != nil || len(digest) != sha256.Size {
		return projectionCandidate{}, errWorkerExecution
	}
	scope, err := recoveryJobScope(config)
	if err != nil {
		return projectionCandidate{}, errWorkerExecution
	}
	candidate := projectionCandidate{Scope: scope, SnapshotID: cursor.SnapshotID, Kind: cursor.Kind}
	copy(candidate.InputDigest[:], digest)
	for _, section := range []string{"entities", "relationships", "evidence"} {
		afterID := ""
		for pageIndex := 0; pageIndex < recoveryMaximumCapturedPages; pageIndex++ {
			page, pageErr := database.ProjectionPage(ctx, config.OrganizationID, config.WorkspaceID, config.EnvironmentID, cursor.SnapshotID, section, afterID, projectionPageSize)
			if pageErr != nil || !bindProjectionPage(&candidate, page, section) {
				return projectionCandidate{}, errWorkerExecution
			}
			switch section {
			case "entities":
				candidate.Entities = append(candidate.Entities, cloneRawMessages(page.Items)...)
			case "relationships":
				candidate.Relationships = append(candidate.Relationships, cloneRawMessages(page.Items)...)
			case "evidence":
				candidate.Evidence = append(candidate.Evidence, cloneRawMessages(page.Items)...)
			}
			if !validProjectionCounts(candidate) {
				return projectionCandidate{}, errWorkerExecution
			}
			if page.NextID == nil {
				break
			}
			if *page.NextID == "" || *page.NextID <= afterID || !validRecoveryProjectionProductID(*page.NextID) {
				return projectionCandidate{}, errWorkerExecution
			}
			afterID = *page.NextID
			if pageIndex == recoveryMaximumCapturedPages-1 {
				return projectionCandidate{}, errWorkerExecution
			}
		}
	}
	if candidate.IntegrationID != integrationID || candidate.Source != input.Source || candidate.SnapshotID != input.SnapshotID || candidate.Generation != input.Generation || hex.EncodeToString(candidate.InputDigest[:]) != input.CandidateDigest || candidate.ManifestReference != input.ManifestReference || candidate.ManifestKey != input.ManifestKey || candidate.ManifestVersionID != input.ManifestVersionID || hex.EncodeToString(candidate.ManifestChecksum[:]) != input.ManifestChecksum || candidate.ManifestSizeBytes != input.ManifestSizeBytes || candidate.ManifestMediaType != input.ManifestMediaType || candidate.ManifestSchemaVersion != input.ManifestSchemaVersion || candidate.ParserVersion != input.ParserVersion || candidate.ToolVersion != input.ToolVersion {
		return projectionCandidate{}, errWorkerExecution
	}
	return candidate, nil
}

func recoveryJobScope(config recoveryJobConfig) (domain.Scope, error) {
	organization, organizationErr := domain.ParseProductID(config.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(config.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(config.EnvironmentID)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return domain.Scope{}, errWorkerExecution
	}
	return domain.NewScope(organization, workspace, environment)
}

func validRecoveryProjectionProductID(value string) bool {
	parsed, err := domain.ParseProductID(value)
	return err == nil && parsed.String() == value
}

func validRecoveryDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && !bytes.Equal(decoded, make([]byte, sha256.Size))
}

func validRecoveryTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	_, offset := parsed.Zone()
	return err == nil && offset == 0 && value == strings.TrimSpace(value)
}

func validRecoveryProjectionText(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && recoveryProjectionTextPattern.MatchString(value)
}

func leftPadRecoveryGeneration(value int64) string {
	return fmt.Sprintf("%020d", value)
}

type recoveryProjectionTarget struct {
	kind      string
	directory string
	projector projectionProjector
}

func newRecoveryProjectionTarget(directory, kind string) (*recoveryProjectionTarget, error) {
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, errWorkerExecution
	}
	if kind == "graph" {
		driver := &recoveryGraphFileDriver{directory: directory}
		store, storeErr := graphstore.New(driver, graphstore.Config{OperationTimeout: 30 * time.Second, MaximumNodes: projectionMaximumEntities, MaximumEdges: projectionMaximumRelationships, MaximumDepth: 8})
		if storeErr != nil {
			return nil, errWorkerExecution
		}
		projector, projectorErr := newGraphProjectionProjector(store)
		return &recoveryProjectionTarget{kind: kind, directory: directory, projector: projector}, projectorErr
	}
	driver := &recoverySearchFileDriver{directory: directory, stages: make(map[string]inventorysearch.DriverStage), active: make(map[string]inventorysearch.DriverActivation)}
	store, err := inventorysearch.New(driver, inventorysearch.Config{MaximumDocuments: projectionMaximumEntities, MaximumDocumentBytes: 65_536, MaximumBatchBytes: 8 << 20, MaximumResults: 100})
	if err != nil {
		return nil, errWorkerExecution
	}
	projector, err := newSearchProjectionProjector(store)
	return &recoveryProjectionTarget{kind: kind, directory: directory, projector: projector}, err
}

func (target *recoveryProjectionTarget) Apply(ctx context.Context, candidate projectionCandidate) (projectionDriverResult, error) {
	if target == nil || target.projector == nil || candidate.Kind != target.kind {
		return projectionDriverResult{}, errWorkerExecution
	}
	return target.projector.Apply(ctx, candidate)
}

func (target *recoveryProjectionTarget) PersistEmpty(ctx context.Context) error {
	if target == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	_, err := persistRecoveryTarget(target.directory, target.kind+"-empty", map[string]string{"kind": target.kind, "state": "empty"})
	return err
}

type recoveryGraphFileDriver struct{ directory string }

func (driver *recoveryGraphFileDriver) Upsert(context.Context, graphstore.DriverProjection) (graphstore.DriverUpserted, error) {
	return graphstore.DriverUpserted{}, graphstore.ErrSnapshotUnavailable
}

func (driver *recoveryGraphFileDriver) Read(context.Context, graphstore.DriverQuery) (graphstore.DriverProjection, error) {
	return graphstore.DriverProjection{}, graphstore.ErrSnapshotUnavailable
}

func (driver *recoveryGraphFileDriver) ReplaceSnapshot(ctx context.Context, input graphstore.DriverSnapshotProjection) (graphstore.DriverSnapshotReplaced, error) {
	if ctx == nil || ctx.Err() != nil {
		return graphstore.DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, Outcome: graphstore.DriverSnapshotNoMutation}, graphstore.ErrSnapshotCanceled
	}
	key := strings.Join([]string{"graph", input.Snapshot.OrganizationID, input.Snapshot.WorkspaceID, input.Snapshot.EnvironmentID, input.Snapshot.IntegrationID, input.Snapshot.Source}, "\x1f")
	replayed, err := persistRecoveryTarget(driver.directory, key, input)
	if err != nil {
		return graphstore.DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, Outcome: graphstore.DriverSnapshotNoMutation}, graphstore.ErrSnapshotUnknownOutcome
	}
	nodeIDs := make([]string, len(input.Nodes))
	for index, node := range input.Nodes {
		nodeIDs[index] = node.NodeID
	}
	edgeIDs := make([]string, len(input.Edges))
	for index, edge := range input.Edges {
		edgeIDs[index] = edge.EdgeID
	}
	return graphstore.DriverSnapshotReplaced{CandidateSnapshot: input.Snapshot, ActiveSnapshot: input.Snapshot, NodeIDs: nodeIDs, EdgeIDs: edgeIDs, Replayed: replayed, Outcome: graphstore.DriverSnapshotDurable}, nil
}

type recoverySearchFileDriver struct {
	mu        sync.Mutex
	directory string
	stages    map[string]inventorysearch.DriverStage
	active    map[string]inventorysearch.DriverActivation
}

func (driver *recoverySearchFileDriver) Stage(ctx context.Context, input inventorysearch.DriverStage) (inventorysearch.DriverStaged, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrCanceled
	}
	key := recoverySearchTargetKey(input.Snapshot)
	replayed, err := persistRecoveryTarget(driver.directory, "search-stage\x1f"+key, input)
	if err != nil {
		return inventorysearch.DriverStaged{}, inventorysearch.ErrUnknownOutcome
	}
	driver.stages[key] = input
	ids := make([]string, len(input.Documents))
	for index, document := range input.Documents {
		ids[index] = document.DocumentID
	}
	return inventorysearch.DriverStaged{Snapshot: input.Snapshot, DocumentIDs: ids, Replayed: replayed}, nil
}

func (driver *recoverySearchFileDriver) Activate(ctx context.Context, input inventorysearch.DriverActivation) (inventorysearch.DriverActivated, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	key := recoverySearchTargetKey(input.Snapshot)
	stage, exists := driver.stages[key]
	if ctx == nil || ctx.Err() != nil {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrCanceled
	}
	if !exists || stage.Snapshot != input.Snapshot || !reflect.DeepEqual(input.DocumentIDs, recoverySearchDocumentIDs(stage.Documents)) {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrDrift
	}
	replayed, err := persistRecoveryTarget(driver.directory, "search-active\x1f"+strings.Join([]string{input.Snapshot.OrganizationID, input.Snapshot.WorkspaceID, input.Snapshot.EnvironmentID, input.Snapshot.IntegrationID}, "\x1f"), input)
	if err != nil {
		return inventorysearch.DriverActivated{}, inventorysearch.ErrUnknownOutcome
	}
	driver.active[key] = input
	return inventorysearch.DriverActivated{ActiveSnapshot: input.Snapshot, ActiveDocumentIDs: append([]string(nil), input.DocumentIDs...), Replayed: replayed}, nil
}

func (driver *recoverySearchFileDriver) DiscardStage(context.Context, inventorysearch.DriverDiscard) (inventorysearch.DriverDiscarded, error) {
	return inventorysearch.DriverDiscarded{}, inventorysearch.ErrUnavailable
}

func (driver *recoverySearchFileDriver) RemoveStale(ctx context.Context, input inventorysearch.DriverCleanup) (inventorysearch.DriverCleaned, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	active, exists := driver.active[recoverySearchTargetKey(input.ActiveSnapshot)]
	if ctx == nil || ctx.Err() != nil {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrCanceled
	}
	if !exists || active.Snapshot != input.ActiveSnapshot {
		return inventorysearch.DriverCleaned{}, inventorysearch.ErrDrift
	}
	return inventorysearch.DriverCleaned{ActiveSnapshot: input.ActiveSnapshot}, nil
}

func (driver *recoverySearchFileDriver) Search(context.Context, inventorysearch.DriverQuery) (inventorysearch.DriverSearchResult, error) {
	return inventorysearch.DriverSearchResult{}, inventorysearch.ErrUnavailable
}

func recoverySearchTargetKey(snapshot inventorysearch.DriverSnapshot) string {
	return strings.Join([]string{snapshot.OrganizationID, snapshot.WorkspaceID, snapshot.EnvironmentID, snapshot.IntegrationID, snapshot.SnapshotID, hex.EncodeToString(snapshot.ContentDigest[:])}, "\x1f")
}

func recoverySearchDocumentIDs(documents []inventorysearch.DriverDocument) []string {
	ids := make([]string, len(documents))
	for index, document := range documents {
		ids[index] = document.DocumentID
	}
	return ids
}

func persistRecoveryTarget(directory, key string, value any) (bool, error) {
	body, err := json.Marshal(value)
	if err != nil || len(body) < 2 || len(body) > 8<<20 {
		return false, errWorkerExecution
	}
	nameDigest := sha256.Sum256([]byte(key))
	path := filepath.Join(directory, "target-"+hex.EncodeToString(nameDigest[:])+".json")
	if filepath.Dir(path) != directory {
		return false, errWorkerExecution
	}
	file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	replayed := false
	if errors.Is(openErr, os.ErrExist) {
		replayed = true
	} else if openErr != nil {
		return false, errWorkerExecution
	} else {
		written, writeErr := file.Write(body)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || written != len(body) {
			return false, errWorkerExecution
		}
	}
	opened, err := os.Open(path)
	if err != nil {
		return false, errWorkerExecution
	}
	info, statErr := opened.Stat()
	read, readErr := io.ReadAll(io.LimitReader(opened, 8<<20+1))
	closeErr := opened.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(body)) || len(read) > 8<<20 || !bytes.Equal(read, body) {
		return false, errWorkerExecution
	}
	return replayed, nil
}

var _ recoveryProjectionPageDatabase = (*postgresRecoveryJobDatabase)(nil)
var _ graphstore.Driver = (*recoveryGraphFileDriver)(nil)
var _ graphstore.SnapshotDriver = (*recoveryGraphFileDriver)(nil)
var _ inventorysearch.Driver = (*recoverySearchFileDriver)(nil)
