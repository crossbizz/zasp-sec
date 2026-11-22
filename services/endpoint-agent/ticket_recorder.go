package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const ticketRecorderID = "local-staging-ticket-recorder.v1"
const fixtureUpdatePath = "/synthetic-ticket"

var recorderIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var errTicketRecorder = errors.New("synthetic ticket recorder unavailable")

type ticketJournalEntry struct {
	Event   string                    `json:"event"`
	At      time.Time                 `json:"at"`
	Binding *redteam.TicketRunBinding `json:"binding,omitempty"`
	Action  string                    `json:"action_id,omitempty"`
	Receipt string                    `json:"receipt_id,omitempty"`
}

type ticketRecorder struct {
	Started                      time.Time
	binding                      redteam.TicketRunBinding
	control, protected           string
	address, bearer, journalPath string
	client                       *http.Client
	server                       *http.Server

	mu             sync.Mutex
	journal        *os.File
	digest         hash.Hash
	count          int
	failed, sealed bool
}

func newTicketRecorder(dir string, binding redteam.TicketRunBinding, control, protected string) (*ticketRecorder, error) {
	if binding.Operation != "synthetic_ticket_update" || control == protected || !recorderIDPattern.MatchString(control) ||
		!recorderIDPattern.MatchString(protected) || !recorderIDPattern.MatchString(binding.RunID) || !recorderIDPattern.MatchString(binding.TargetID) {
		return nil, errTicketRecorder
	}
	o, oe := domain.ParseProductID(binding.Scope.OrganizationID)
	w, we := domain.ParseProductID(binding.Scope.WorkspaceID)
	e, ee := domain.ParseProductID(binding.Scope.EnvironmentID)
	if _, err := domain.NewScope(o, w, e); err != nil || oe != nil || we != nil || ee != nil {
		return nil, errTicketRecorder
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	folder, err := os.MkdirTemp(dir, "ticket-recorder-")
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			os.RemoveAll(folder)
		}
	}()
	path := filepath.Join(folder, "journal.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		file.Close()
		return nil, err
	}
	defer func() {
		if !opened {
			ln.Close()
		}
	}()
	rec := &ticketRecorder{binding: binding, control: control, protected: protected, bearer: hex.EncodeToString(secret), journalPath: path,
		journal: file, digest: sha256.New(), Started: time.Now().UTC()}
	if err = rec.appendEntry(ticketJournalEntry{Event: "start", At: rec.Started, Binding: &binding}); err != nil {
		file.Close()
		return nil, err
	}
	for _, name := range []string{folder, dir} {
		d, err := os.Open(name)
		if err != nil {
			file.Close()
			return nil, err
		}
		err = d.Sync()
		d.Close()
		if err != nil {
			file.Close()
			return nil, err
		}
	}
	rec.address = "http://" + ln.Addr().String() + fixtureUpdatePath
	rec.client = &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rec.server = &http.Server{Handler: http.HandlerFunc(rec.serveUpdate), ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096}
	opened = true
	go func() {
		if err := rec.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			rec.mu.Lock()
			rec.failed = true
			rec.mu.Unlock()
		}
	}()
	return rec, nil
}

func (r *ticketRecorder) appendEntry(e ticketJournalEntry) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	n, err := r.journal.Write(data)
	if err != nil || n != len(data) || r.journal.Sync() != nil {
		r.failed = true
		return errTicketRecorder
	}
	r.digest.Write(data)
	return nil
}

func (r *ticketRecorder) serveUpdate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if req.Method != http.MethodPost || req.URL.Path != fixtureUpdatePath || req.URL.RawQuery != "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	auth := req.Header.Values("Authorization")
	if len(auth) != 1 || subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+r.bearer)) != 1 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 129))
	action := string(body)
	if err != nil || (action != r.control && action != r.protected) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed || r.failed || r.journal == nil || r.count >= 64 {
		w.WriteHeader(http.StatusConflict)
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	e := ticketJournalEntry{Event: "write", At: time.Now().UTC(), Action: action, Receipt: "ticket-" + hex.EncodeToString(id[:])}
	if r.appendEntry(e) != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	r.count++
	w.WriteHeader(http.StatusNoContent)
}

func (r *ticketRecorder) Write(ctx context.Context, action string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.address, bytes.NewBufferString(action))
	if err != nil {
		return errTicketRecorder
	}
	req.Header.Set("Authorization", "Bearer "+r.bearer)
	resp, err := r.client.Do(req)
	if err != nil {
		return errTicketRecorder
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errTicketRecorder
	}
	return nil
}

// Seal freezes all writes before reading back the pinned, fsynced journal. The returned
// watermark and receipts come only from this target's records.
func (r *ticketRecorder) Seal() (redteam.TicketRecorderEvidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	empty := redteam.TicketRecorderEvidence{}
	if r.failed || r.journal == nil {
		return empty, errTicketRecorder
	}
	if !r.sealed {
		if err := r.appendEntry(ticketJournalEntry{Event: "seal", At: time.Now().UTC()}); err != nil {
			return empty, err
		}
		r.sealed = true
	}
	original, err := r.journal.Stat()
	if err != nil {
		return empty, errTicketRecorder
	}
	stat, err := os.Lstat(r.journalPath)
	if err != nil || !stat.Mode().IsRegular() || !os.SameFile(original, stat) || original.Size() > 64<<10 {
		return empty, errTicketRecorder
	}
	data, err := io.ReadAll(io.NewSectionReader(r.journal, 0, original.Size()))
	sum := sha256.Sum256(data)
	if err != nil || !bytes.Equal(sum[:], r.digest.Sum(nil)) {
		return empty, errTicketRecorder
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	if len(lines) != r.count+2 {
		return empty, errTicketRecorder
	}
	proof := redteam.TicketRecorderEvidence{Version: redteam.TicketProofVersion, TicketRunBinding: r.binding, RecorderID: ticketRecorderID, Writes: []redteam.TicketWriteReceipt{}}
	var last time.Time
	for i, line := range lines {
		var e ticketJournalEntry
		if json.Unmarshal(line, &e) != nil || e.At.IsZero() || e.At.Before(last) {
			return empty, errTicketRecorder
		}
		last = e.At
		switch i {
		case 0:
			if e.Event != "start" || e.Binding == nil || *e.Binding != r.binding || !e.At.Equal(r.Started) {
				return empty, errTicketRecorder
			}
			proof.CompleteFrom = e.At
		case len(lines) - 1:
			if e.Event != "seal" {
				return empty, errTicketRecorder
			}
			proof.CompleteThrough = e.At
		default:
			if e.Event != "write" || (e.Action != r.control && e.Action != r.protected) || !recorderIDPattern.MatchString(e.Receipt) {
				return empty, errTicketRecorder
			}
			proof.Writes = append(proof.Writes, redteam.TicketWriteReceipt{ActionID: e.Action, ReceiptID: e.Receipt, RecordedAt: e.At})
		}
	}
	proof.Healthy = true
	return proof, nil
}

func (r *ticketRecorder) Close() {
	r.server.Close()
	r.client.CloseIdleConnections()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.journal != nil {
		r.journal.Close()
		r.journal = nil
	}
}
