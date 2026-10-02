// Package exportfixture is a test-only, disk-backed S3 transport. It must never
// be used by a production binary or described as live-provider evidence.
package exportfixture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	Directory, Bucket, Owner, KMSKey string
	MaximumBytes                     int64
}
type Object struct {
	Key       string      `json:"key"`
	VersionID string      `json:"version_id"`
	Body      []byte      `json:"body"`
	Headers   http.Header `json:"headers"`
	Deleted   bool        `json:"deleted"`
}
type Request struct {
	Sequence  int64  `json:"sequence"`
	Method    string `json:"method"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	Stage     string `json:"stage"`
	Status    int    `json:"status"`
	Code      string `json:"code,omitempty"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
}
type Fault struct {
	StatusCode int
	Code       string
	Err        error
	Body       []byte
}
type Hook func(context.Context, Request) *Fault
type Options struct {
	ReadOnly      bool
	Before, After Hook
}
type Store struct {
	config          Config
	root            *os.Root
	info            os.FileInfo
	mu              sync.Mutex
	closed, creator bool
	marker          string
}

var errFixture = errors.New("controlled export fixture refused")

type manifest struct {
	Version int      `json:"version"`
	Objects []Object `json:"objects"`
}
type ownership struct {
	Token  string
	Config Config
}

const maxDiskBytes = 96 << 20
const maxLogBytes = 8 << 20

func validConfig(c Config) bool {
	if !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory || filepath.Dir(c.Directory) == c.Directory || c.Bucket == "" || strings.ContainsAny(c.Bucket, "/\\") || c.Owner == "" || c.KMSKey == "" || c.MaximumBytes < 1 || c.MaximumBytes > 8<<20 {
		return false
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(c.Directory))
	return err == nil && parent == filepath.Dir(c.Directory)
}
func Create(c Config) (*Store, error) {
	if !validConfig(c) {
		return nil, errFixture
	}
	if err := os.Mkdir(c.Directory, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(c.Directory)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(c.Directory)
	if err != nil {
		root.Close()
		return nil, err
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		root.Close()
		return nil, err
	}
	s := &Store{config: c, root: root, info: info, creator: true, marker: hex.EncodeToString(token)}
	for name, value := range map[string]any{"owner.json": ownership{s.marker, c}, "state.json": manifest{1, []Object{}}} {
		raw, _ := json.Marshal(value)
		if err = s.writeNew(name, raw); err != nil {
			root.Close()
			return nil, err
		}
	}
	for _, name := range []string{"lock", "requests.jsonl"} {
		if err = s.writeNew(name, nil); err != nil {
			root.Close()
			return nil, err
		}
	}
	return s, nil
}
func Open(c Config) (*Store, error) {
	if !validConfig(c) {
		return nil, errFixture
	}
	info, err := os.Lstat(c.Directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errFixture
	}
	root, err := os.OpenRoot(c.Directory)
	if err != nil {
		return nil, err
	}
	s := &Store{config: c, root: root, info: info}
	raw, err := s.read("owner.json", 16384)
	var o ownership
	if err != nil || json.Unmarshal(raw, &o) != nil || o.Config != c || len(o.Token) != 64 {
		root.Close()
		return nil, errFixture
	}
	s.marker = o.Token
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.root.Close()
}

// Remove is creator-only. All borrower processes must already be joined.
// A substituted root/marker or unexpected entry is refused, never followed.
func (s *Store) Remove() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.creator || s.closed {
		return errFixture
	}
	if err := s.checkRoot(); err != nil {
		return err
	}
	raw, err := s.read("owner.json", 16384)
	var owner ownership
	if err != nil || json.Unmarshal(raw, &owner) != nil || owner.Token != s.marker {
		return errFixture
	}
	entries, err := os.ReadDir(s.config.Directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !(entry.Name() == "owner.json" || entry.Name() == "state.json" || entry.Name() == "lock" || entry.Name() == "requests.jsonl" || strings.HasPrefix(entry.Name(), "state.tmp-")) {
			return errFixture
		}
	}
	for _, entry := range entries {
		if err = s.root.Remove(entry.Name()); err != nil {
			return err
		}
	}
	if err = s.root.Close(); err != nil {
		return err
	}
	s.closed = true
	return os.Remove(s.config.Directory)
}
func (s *Store) checkRoot() error {
	info, err := os.Lstat(s.config.Directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, s.info) {
		return errFixture
	}
	return nil
}
func (s *Store) file(name string, flags int) (*os.File, error) {
	f, err := s.root.OpenFile(name, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errFixture
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		f.Close()
		return nil, errFixture
	}
	return f, nil
}
func (s *Store) writeNew(name string, body []byte) error {
	f, err := s.file(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func (s *Store) read(name string, limit int64) ([]byte, error) {
	f, err := s.file(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > limit {
		return nil, errFixture
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(raw)) > limit {
		return nil, errFixture
	}
	return raw, err
}
func (s *Store) locked(ctx context.Context, fn func() error) error {
	if ctx == nil || ctx.Err() != nil {
		return errFixture
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errFixture
	}
	if err := s.checkRoot(); err != nil {
		return err
	}
	lock, err := s.file("lock", os.O_RDWR)
	if err != nil {
		return err
	}
	defer lock.Close()
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fn()
}
func (s *Store) state() (manifest, error) {
	var m manifest
	raw, err := s.read("state.json", maxDiskBytes)
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || m.Version != 1 || m.Objects == nil || len(m.Objects) > 128 {
		return m, errFixture
	}
	var total int64
	seen := map[string]bool{}
	for _, o := range m.Objects {
		total += int64(len(o.Body))
		if !validKey(o.Key) || o.VersionID == "" || seen[o.Key] || int64(len(o.Body)) > s.config.MaximumBytes || total > 64<<20 {
			return m, errFixture
		}
		seen[o.Key] = true
	}
	return m, nil
}
func (s *Store) save(m manifest) error {
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > maxDiskBytes {
		return errFixture
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return err
	}
	name := "state.tmp-" + hex.EncodeToString(token)
	if err = s.writeNew(name, raw); err != nil {
		return err
	}
	defer s.root.Remove(name)
	if err = s.root.Rename(name, "state.json"); err != nil {
		return err
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Store) Objects(ctx context.Context) (objects []Object, err error) {
	err = s.locked(ctx, func() error { m, e := s.state(); objects = m.Objects; return e })
	return
}
func (s *Store) requests() ([]Request, error) {
	raw, err := s.read("requests.jsonl", maxLogBytes)
	if err != nil {
		return nil, err
	}
	entries := []Request{}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r Request
		if json.Unmarshal(line, &r) != nil {
			return nil, errFixture
		}
		entries = append(entries, r)
	}
	return entries, nil
}
func (s *Store) Requests(ctx context.Context) (entries []Request, err error) {
	err = s.locked(ctx, func() error { var e error; entries, e = s.requests(); return e })
	return
}
func (s *Store) record(ctx context.Context, r Request) error {
	return s.locked(ctx, func() error {
		entries, err := s.requests()
		if err != nil {
			return err
		}
		r.Sequence = int64(len(entries) + 1)
		raw, _ := json.Marshal(r)
		f, err := s.file("requests.jsonl", os.O_WRONLY|os.O_APPEND)
		if err != nil {
			return err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || info.Size()+int64(len(raw))+1 > maxLogBytes {
			return errFixture
		}
		if _, err = f.Write(append(raw, '\n')); err != nil {
			return err
		}
		return f.Sync()
	})
}
func validKey(key string) bool {
	if key == "" || len(key) > 1024 || strings.ContainsAny(key, "\\\x00\r\n") || strings.HasPrefix(key, "/") || !strings.Contains(key, "/exports/") {
		return false
	}
	for _, p := range strings.Split(key, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func (s *Store) Transport(o Options) http.RoundTripper { return transport{s, o} }

type transport struct {
	store   *Store
	options Options
}

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.Context().Err() != nil || t.store == nil {
		return nil, errFixture
	}
	if _, ok := r.Context().Deadline(); !ok {
		return nil, errFixture
	}
	c := t.store.config
	if r.URL.Scheme != "https" || r.URL.Host != "controlled.invalid" || r.URL.User != nil || r.URL.Fragment != "" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != c.Owner || !strings.HasPrefix(r.URL.Path, "/"+c.Bucket+"/") {
		return nil, errFixture
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+c.Bucket+"/")
	version := r.URL.Query().Get("versionId")
	if !validKey(key) || len(r.URL.Query()["versionId"]) > 1 || len(version) > 1024 {
		return nil, errFixture
	}
	for name, values := range r.URL.Query() {
		if (name != "versionId" && name != "x-id") || len(values) != 1 {
			return nil, errFixture
		}
	}
	if r.Method != "PUT" && r.Method != "HEAD" && r.Method != "GET" && r.Method != "DELETE" {
		return nil, errFixture
	}
	if t.options.ReadOnly && (r.Method != "HEAD" && r.Method != "GET" || version == "") {
		return nil, errFixture
	}
	if (r.Method == "GET" || r.Method == "DELETE") && version == "" || r.Method == "PUT" && version != "" {
		return nil, errFixture
	}
	entry := Request{Method: r.Method, Key: key, VersionID: version, Stage: "before"}
	if err := t.store.record(r.Context(), entry); err != nil {
		return nil, err
	}
	deliver := func(status int, headers http.Header, body []byte, code string, transportErr error) (*http.Response, error) {
		entry.Stage = "response"
		entry.Status = status
		entry.Code = code
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := t.store.record(ctx, entry); err != nil {
			return nil, err
		}
		if transportErr != nil {
			return nil, transportErr
		}
		if code != "" {
			raw, _ := xml.Marshal(struct {
				XMLName xml.Name `xml:"Error"`
				Code    string   `xml:"Code"`
			}{Code: code})
			body = raw
		}
		if headers == nil {
			headers = http.Header{}
		}
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: r}, nil
	}
	faultResponse := func(f *Fault) (*http.Response, error) {
		if f.Err != nil {
			return deliver(0, nil, nil, "controlled_transport_failure", f.Err)
		}
		status := f.StatusCode
		if status < 400 || status > 599 {
			status = 500
		}
		code := f.Code
		if code == "" {
			code = "InternalError"
		}
		return deliver(status, nil, nil, code, nil)
	}
	if t.options.Before != nil {
		if f := t.options.Before(r.Context(), entry); f != nil {
			return faultResponse(f)
		}
	}
	if r.Context().Err() != nil {
		return deliver(0, nil, nil, "cancelled", r.Context().Err())
	}
	var body []byte
	if r.Method == "PUT" {
		if r.Header.Get("If-None-Match") != "*" || r.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != c.KMSKey || r.Header.Get("Content-Type") != "application/json" || r.Body == nil || r.ContentLength > c.MaximumBytes {
			return deliver(400, nil, nil, "InvalidRequest", nil)
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, c.MaximumBytes+1))
		if err != nil {
			return deliver(0, nil, nil, "body_read_failed", err)
		}
		if len(body) == 0 || int64(len(body)) > c.MaximumBytes {
			return deliver(400, nil, nil, "EntityTooLarge", nil)
		}
		h := sha256.Sum256(body)
		if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(h[:]) {
			return deliver(400, nil, nil, "BadDigest", nil)
		}
		entry.Size = int64(len(body))
		entry.SHA256 = hex.EncodeToString(h[:])
	}
	status, responseCode := 200, ""
	headers := http.Header{}
	var responseBody []byte
	err := t.store.locked(r.Context(), func() error {
		m, err := t.store.state()
		if err != nil {
			return err
		}
		index := -1
		for i, o := range m.Objects {
			if o.Key == key {
				index = i
				break
			}
		}
		if r.Method == "PUT" {
			if index >= 0 {
				status, responseCode = 412, "PreconditionFailed"
				return nil
			}
			total := int64(len(body))
			for _, o := range m.Objects {
				total += int64(len(o.Body))
			}
			if len(m.Objects) >= 128 || total > 64<<20 {
				status, responseCode = 507, "InsufficientStorage"
				return nil
			}
			digest := sha256.Sum256(append(append([]byte(key), 0), body...))
			version = "fixture-" + hex.EncodeToString(digest[:])
			entry.VersionID = version
			headers = http.Header{"Content-Type": {"application/json"}, "Content-Length": {fmt.Sprint(len(body))}, "X-Amz-Version-Id": {version}, "X-Amz-Checksum-Sha256": {r.Header.Get("X-Amz-Checksum-Sha256")}, "X-Amz-Server-Side-Encryption": {"aws:kms"}, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": {c.KMSKey}}
			metadataBytes := 0
			for k, v := range r.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
					for _, item := range v {
						metadataBytes += len(k) + len(item)
					}
					headers[k] = append([]string(nil), v...)
				}
			}
			if metadataBytes > 16384 {
				status, responseCode = 400, "MetadataTooLarge"
				return nil
			}
			m.Objects = append(m.Objects, Object{key, version, body, headers.Clone(), false})
			return t.store.save(m)
		}
		if index < 0 || m.Objects[index].Deleted || version != "" && m.Objects[index].VersionID != version {
			status = 404
			if version != "" {
				responseCode = "NoSuchVersion"
			} else {
				responseCode = "NotFound"
			}
			return nil
		}
		object := m.Objects[index]
		entry.VersionID = object.VersionID
		entry.Size = int64(len(object.Body))
		hash := sha256.Sum256(object.Body)
		entry.SHA256 = hex.EncodeToString(hash[:])
		headers = object.Headers.Clone()
		if r.Method == "DELETE" {
			m.Objects[index].Deleted = true
			// Keep only the immutable identity tombstone; erased artifact bytes
			// must not remain available through the fixture's snapshot oracle.
			m.Objects[index].Body = nil
			m.Objects[index].Headers = nil
			status = 204
			headers = http.Header{"X-Amz-Version-Id": {version}}
			return t.store.save(m)
		}
		if r.Method == "GET" {
			responseBody = object.Body
			if value := r.Header.Get("Range"); value != "" {
				if value != "bytes=0-0" {
					status, responseCode = 416, "InvalidRange"
					return nil
				}
				status = 206
				responseBody = responseBody[:1]
				headers.Set("Content-Length", "1")
				headers.Set("Content-Range", fmt.Sprintf("bytes 0-0/%d", len(object.Body)))
			}
		}
		return nil
	})
	if err != nil {
		return deliver(0, nil, nil, "store_failure", err)
	}
	entry.Stage = "stored"
	entry.Status = status
	entry.Code = responseCode
	if err = t.store.record(r.Context(), entry); err != nil {
		return nil, err
	}
	if t.options.After != nil {
		if f := t.options.After(r.Context(), entry); f != nil {
			if f.Err != nil || f.StatusCode != 0 || f.Code != "" {
				return faultResponse(f)
			}
			if f.Body != nil {
				responseBody = bytes.Clone(f.Body)
				headers.Set("Content-Length", fmt.Sprint(len(responseBody)))
			}
		}
	}
	if r.Context().Err() != nil {
		return deliver(0, nil, nil, "cancelled", r.Context().Err())
	}
	return deliver(status, headers, responseBody, responseCode, nil)
}
