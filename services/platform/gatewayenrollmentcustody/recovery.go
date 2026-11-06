package gatewayenrollmentcustody

import (
	"bytes"
	"encoding/json"
	"fmt"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"io"
	"os"
	"sync"
	"time"
)

// Recovery is a live in-process capability. Its caller must be the trusted CLI
// performing the real TLS exchange and reading the actual local clock. It does
// not isolate malicious code in this process or make saved history live again.
type Recovery struct {
	mu         sync.Mutex
	store      *Store
	closed     bool
	attempted  bool
	observed   bool
	consumed   bool
	sentAt     time.Time
	observedAt time.Time
	authority  wire.CurrentAuthority
}
type authorityObservation struct {
	Schema                  string                `json:"schema"`
	LocalRequestSHA256      string                `json:"local_request_sha256"`
	Endpoint                string                `json:"endpoint"`
	RequestSentAt           time.Time             `json:"request_sent_at"`
	ResponseObservedAt      time.Time             `json:"response_observed_at"`
	AuthorityResponseSHA256 string                `json:"authority_response_sha256"`
	Authority               wire.CurrentAuthority `json:"authority"`
}

func (*Recovery) String() string                 { return "[REDACTED]" }
func (*Recovery) GoString() string               { return "[REDACTED]" }
func (*Recovery) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (s *Store) authorityName() string {
	return ".zasp-gateway-enrollment-" + wire.Digest([]byte(s.name)) + ".authority"
}
func (s *Store) BeginRecovery() (*Recovery, error) {
	if s == nil {
		return nil, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil {
		return nil, ErrUnavailable
	}
	return &Recovery{store: s}, nil
}
func (r *Recovery) Source() (string, Snapshot, error) {
	if r == nil {
		return "", Snapshot{}, ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.store == nil {
		return "", Snapshot{}, ErrUnavailable
	}
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil {
		return "", Snapshot{}, ErrUnavailable
	}
	return s.bundle.Endpoint, s.snapshotLocked(), nil
}
func (r *Recovery) Sign(message []byte) ([]byte, error) {
	if r == nil {
		return nil, ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.store == nil {
		return nil, ErrUnavailable
	}
	return r.store.Sign(message)
}
func (r *Recovery) Observe(raw []byte, sentAt, observedAt time.Time) error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.store == nil || r.attempted || r.consumed {
		return ErrUnavailable
	}
	r.attempted = true
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLocked() || s.bundle == nil || !validObservationTimes(sentAt, observedAt) {
		return ErrUnavailable
	}
	authority, err := wire.ParseCurrentAuthority(raw)
	if err != nil || !wire.CurrentAuthorityMatchesRequest(authority, s.request, observedAt) {
		return ErrUnavailable
	}
	canonical, err := wire.MarshalCurrentAuthority(authority)
	if err != nil {
		return ErrUnavailable
	}
	history := authorityObservation{Schema: "gateway-current-authority-observation-v1", LocalRequestSHA256: wire.Digest(s.bundle.Request), Endpoint: s.bundle.Endpoint, RequestSentAt: sentAt, ResponseObservedAt: observedAt, AuthorityResponseSHA256: wire.Digest(canonical), Authority: authority}
	existing, present, err := readRecoverable(s.root, s.authorityName())
	if err != nil {
		return ErrUnavailable
	}
	if present {
		if s.validateAuthorityHistory(existing) != nil {
			return ErrUnavailable
		}
	} else {
		encoded, err := json.Marshal(history)
		if err != nil || publish(s.root, s.authorityName(), encoded) != nil || !s.guard.Valid() {
			s.failed = true
			return ErrUnavailable
		}
	}
	r.sentAt, r.observedAt, r.authority, r.observed = sentAt, observedAt, authority, true
	return nil
}
func (r *Recovery) ExportCredential(path string, now time.Time) error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.store == nil || r.consumed {
		return ErrUnavailable
	}
	r.consumed = true
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !r.observed || !s.validLocked() || s.bundle == nil || !whole(now) || now.Before(r.observedAt) || now.After(r.observedAt.Add(30*time.Second)) || !validObservationTimes(r.sentAt, r.observedAt) || !wire.CurrentAuthorityMatchesRequest(r.authority, s.request, now) {
		return ErrUnavailable
	}
	return s.exportCredentialLocked(path)
}
func (r *Recovery) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.store = nil
	r.observed = false
	return nil
}
func validObservationTimes(sentAt, observedAt time.Time) bool {
	return whole(sentAt) && whole(observedAt) && !observedAt.Before(sentAt) && !observedAt.After(sentAt.Add(30*time.Second))
}
func (s *Store) validateAuthorityHistory(raw []byte) error {
	if s.bundle == nil || len(raw) == 0 || len(raw) > 16384 {
		return ErrUnavailable
	}
	var history authorityObservation
	if json.Unmarshal(raw, &history) != nil {
		return ErrUnavailable
	}
	canonical, err := json.Marshal(history)
	if err != nil || !bytes.Equal(raw, canonical) || history.Schema != "gateway-current-authority-observation-v1" || history.LocalRequestSHA256 != wire.Digest(s.bundle.Request) || history.Endpoint != s.bundle.Endpoint || !validObservationTimes(history.RequestSentAt, history.ResponseObservedAt) || !wire.CurrentAuthorityMatchesRequest(history.Authority, s.request, history.ResponseObservedAt) {
		return ErrUnavailable
	}
	authority, err := wire.MarshalCurrentAuthority(history.Authority)
	if err != nil || history.AuthorityResponseSHA256 != wire.Digest(authority) {
		return ErrUnavailable
	}
	return nil
}

// Open invokes this only after the original bundle and any enrollment receipt
// have been validated. A historical observation never changes StatePending.
func (s *Store) recoverAuthorityHistory() error {
	raw, present, err := readRecoverable(s.root, s.authorityName())
	if err != nil {
		return ErrUnavailable
	}
	if !present {
		return nil
	}
	if s.validateAuthorityHistory(raw) != nil || publish(s.root, s.authorityName(), raw) != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) checkAuthorityHistory() bool {
	info, err := s.root.Lstat(s.authorityName())
	if os.IsNotExist(err) {
		_, stageErr := s.root.Lstat(publicationStage(s.authorityName()))
		return os.IsNotExist(stageErr)
	}
	if err != nil || !safeInfo(info, 1) {
		return false
	}
	raw, err := readExactFile(s.root, s.authorityName(), 1)
	if err != nil {
		return false
	}
	return s.validateAuthorityHistory(raw) == nil
}
