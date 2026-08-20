package runtimecorrelation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

var ErrInput = errors.New("runtime correlation input rejected")

const contentDigestDomain = "zasp.runtime-correlation.batch.v1"

type Batch struct {
	Scope         domain.Scope
	BatchID       domain.ProductID
	Generation    int64
	ArchiveDigest [sha256.Size]byte
	Body          []byte
	Candidates    []runtimeevent.Candidate
}

type Result struct {
	EventID    domain.ProductID
	SessionID  domain.ProductID
	AgentID    domain.ProductID
	Confidence domain.EvidenceConfidence
}

type CorrelatedBatch struct {
	BatchID       domain.ProductID
	Generation    int64
	ArchiveDigest [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	Results       []Result
}

func Correlate(input Batch) (CorrelatedBatch, error) {
	if input.Scope.Validate() != nil || input.BatchID.IsZero() || input.Generation < 1 || input.ArchiveDigest == ([sha256.Size]byte{}) || len(input.Body) < 1 || len(input.Body) > 64<<20 || sha256.Sum256(input.Body) != input.ArchiveDigest || len(input.Candidates) > 1000 || !validCandidates(input.Candidates) {
		return CorrelatedBatch{}, ErrInput
	}
	batch, err := runtimeevent.DecodeArchivedBatch(input.Scope, input.Body)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	results := make([]Result, len(batch.Records))
	for index, record := range batch.Records {
		correlation := runtimeevent.Correlate(record, input.Candidates)
		results[index] = Result{EventID: record.ID, SessionID: correlation.SessionID, AgentID: correlation.AgentID, Confidence: correlation.Confidence}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].EventID.String() < results[j].EventID.String() })
	for index := 1; index < len(results); index++ {
		if results[index-1].EventID == results[index].EventID {
			return CorrelatedBatch{}, ErrInput
		}
	}
	contentDigest, err := correlationDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, results)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	return CorrelatedBatch{BatchID: input.BatchID, Generation: input.Generation, ArchiveDigest: input.ArchiveDigest, ContentDigest: contentDigest, Results: append([]Result(nil), results...)}, nil
}

func correlationDigest(scope domain.Scope, batchID domain.ProductID, generation int64, archiveDigest [sha256.Size]byte, results []Result) ([sha256.Size]byte, error) {
	wire := struct {
		Domain         string       `json:"domain"`
		OrganizationID string       `json:"organization_id"`
		WorkspaceID    string       `json:"workspace_id"`
		EnvironmentID  string       `json:"environment_id"`
		BatchID        string       `json:"batch_id"`
		Generation     int64        `json:"generation"`
		ArchiveDigest  string       `json:"archive_digest"`
		Results        []resultWire `json:"results"`
	}{contentDigestDomain, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), generation, hex.EncodeToString(archiveDigest[:]), resultsToWire(results)}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return [sha256.Size]byte{}, ErrInput
	}
	return sha256.Sum256(encoded), nil
}

type resultWire struct {
	EventID    string `json:"event_id"`
	SessionID  string `json:"session_id"`
	AgentID    string `json:"agent_id"`
	Confidence string `json:"confidence"`
}

func resultsToWire(results []Result) []resultWire {
	wire := make([]resultWire, len(results))
	for index, result := range results {
		wire[index] = resultWire{EventID: result.EventID.String(), SessionID: result.SessionID.String(), AgentID: result.AgentID.String(), Confidence: result.Confidence.String()}
	}
	return wire
}

func validCandidates(candidates []runtimeevent.Candidate) bool {
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.SessionID.IsZero() || candidate.AgentID.IsZero() || !validOptional(candidate.SandboxID, 256) || !validOptional(candidate.ContainerID, 256) || !validOptional(candidate.CgroupID, 256) || !validOptional(candidate.ProcessID, 256) {
			return false
		}
		key := candidate.SessionID.String() + "\x00" + candidate.AgentID.String() + "\x00" + candidate.SandboxID + "\x00" + candidate.ContainerID + "\x00" + candidate.CgroupID + "\x00" + candidate.ProcessID
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func validOptional(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
