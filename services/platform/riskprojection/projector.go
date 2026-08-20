package riskprojection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumItems     = 4_000
	maximumItemBytes = 1 << 20
)

var (
	ErrRejected    = errors.New("risk projection input rejected")
	ErrUnavailable = errors.New("risk projection input unavailable")
	ErrStale       = errors.New("risk projection input stale")
	ErrDrift       = errors.New("risk projection input drift")

	versionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,63}$`)
	workerPattern  = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
	receiptPattern = regexp.MustCompile(`^postgres:risk-input:pid_[0-9a-f-]{36}:sha256:[0-9a-f]{64}$`)
)

type Candidate struct {
	Scope                             domain.Scope
	IntegrationID, SnapshotID         domain.ProductID
	Source                            string
	Generation                        int64
	Version, Worker, LeaseToken       string
	InputDigest                       [sha256.Size]byte
	Entities, Relationships, Evidence []json.RawMessage
}

type Item struct {
	Section string           `json:"section"`
	ID      domain.ProductID `json:"-"`
	Payload json.RawMessage  `json:"payload"`
}

type CompleteInput struct {
	Scope                       domain.Scope
	IntegrationID, SnapshotID   domain.ProductID
	Source                      string
	Generation                  int64
	Version, Worker, LeaseToken string
	InputDigest                 [sha256.Size]byte
	Items                       []Item
}

type ApplyResult struct {
	SnapshotID, IntegrationID  domain.ProductID
	Source                     string
	Generation                 int64
	InputDigest, ContentDigest [sha256.Size]byte
	Receipt                    string
	Replayed                   bool
}

type Result struct {
	Receipt string
	Digest  [sha256.Size]byte
}

type Store interface {
	ApplyComplete(context.Context, CompleteInput) (ApplyResult, error)
}

type Projector struct{ store Store }

func NewProjector(store Store) (*Projector, error) {
	if store == nil {
		return nil, ErrRejected
	}
	return &Projector{store: store}, nil
}

func (projector *Projector) Project(ctx context.Context, candidate Candidate) (Result, error) {
	if projector == nil || projector.store == nil || ctx == nil || ctx.Err() != nil || !validCandidate(candidate) {
		return Result{}, ErrRejected
	}
	items, ok := canonicalItems(candidate)
	if !ok {
		return Result{}, ErrRejected
	}
	input := CompleteInput{
		Scope: candidate.Scope, IntegrationID: candidate.IntegrationID, SnapshotID: candidate.SnapshotID,
		Source: candidate.Source, Generation: candidate.Generation, Version: candidate.Version, Worker: candidate.Worker,
		LeaseToken: candidate.LeaseToken, InputDigest: candidate.InputDigest, Items: items,
	}
	result, err := projector.store.ApplyComplete(ctx, input)
	if err != nil {
		return Result{}, err
	}
	if result.SnapshotID != candidate.SnapshotID || result.IntegrationID != candidate.IntegrationID || result.Source != candidate.Source ||
		result.Generation != candidate.Generation || result.InputDigest != candidate.InputDigest || result.ContentDigest == [sha256.Size]byte{} ||
		!receiptPattern.MatchString(result.Receipt) {
		return Result{}, ErrUnavailable
	}
	return Result{Receipt: result.Receipt, Digest: result.ContentDigest}, nil
}

func validCandidate(candidate Candidate) bool {
	return candidate.Scope.Validate() == nil && candidate.IntegrationID != (domain.ProductID{}) && candidate.SnapshotID != (domain.ProductID{}) &&
		stringIn(candidate.Source, "aws", "kubernetes", "github", "okta") && candidate.Generation > 0 &&
		versionPattern.MatchString(candidate.Version) && workerPattern.MatchString(candidate.Worker) && len(candidate.LeaseToken) >= 16 && len(candidate.LeaseToken) <= 128 &&
		strings.TrimSpace(candidate.LeaseToken) == candidate.LeaseToken && candidate.InputDigest != [sha256.Size]byte{} &&
		candidate.Entities != nil && candidate.Relationships != nil && candidate.Evidence != nil &&
		len(candidate.Entities)+len(candidate.Relationships)+len(candidate.Evidence) <= maximumItems
}

func canonicalItems(candidate Candidate) ([]Item, bool) {
	items := make([]Item, 0, len(candidate.Entities)+len(candidate.Relationships)+len(candidate.Evidence))
	seen := make(map[domain.ProductID]struct{}, cap(items))
	for _, section := range []struct {
		name   string
		values []json.RawMessage
	}{{"entities", candidate.Entities}, {"relationships", candidate.Relationships}, {"evidence", candidate.Evidence}} {
		for _, raw := range section.values {
			id, canonical, ok := canonicalItem(raw)
			if !ok {
				return nil, false
			}
			if _, duplicate := seen[id]; duplicate {
				return nil, false
			}
			seen[id] = struct{}{}
			items = append(items, Item{Section: section.name, ID: id, Payload: canonical})
		}
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].Section != items[right].Section {
			return items[left].Section < items[right].Section
		}
		return items[left].ID.String() < items[right].ID.String()
	})
	return items, true
}

func canonicalItem(raw json.RawMessage) (domain.ProductID, json.RawMessage, bool) {
	if len(raw) < 2 || len(raw) > maximumItemBytes || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return domain.ProductID{}, nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value == nil {
		return domain.ProductID{}, nil, false
	}
	identity, ok := value["id"].(string)
	if !ok {
		return domain.ProductID{}, nil, false
	}
	id, err := domain.ParseProductID(identity)
	if err != nil {
		return domain.ProductID{}, nil, false
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > maximumItemBytes {
		return domain.ProductID{}, nil, false
	}
	return id, canonical, true
}

func stringIn(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
