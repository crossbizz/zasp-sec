//go:build linux

package gatewaypodidentity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type publisherDirectory struct {
	root    *os.Root
	file    *os.File
	path    string
	initial os.FileInfo
	private bool
}

func openPublisherDirectory(path string, private bool) (*publisherDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrDenied
	}
	before, e := os.Lstat(path)
	if e != nil || !before.IsDir() {
		return nil, ErrDenied
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrDenied
	}
	f, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, ErrDenied
	}
	p := &publisherDirectory{r, f, path, before, private}
	if !p.valid() {
		p.close()
		return nil, ErrDenied
	}
	return p, nil
}
func (p *publisherDirectory) close() {
	if p != nil {
		p.file.Close()
		p.root.Close()
	}
}
func (p *publisherDirectory) valid() bool {
	a, e := p.file.Stat()
	b, e2 := os.Lstat(p.path)
	if e != nil || e2 != nil || !a.IsDir() || !b.IsDir() || !os.SameFile(p.initial, a) || !os.SameFile(a, b) {
		return false
	}
	n, ok := a.Sys().(*syscall.Stat_t)
	other, ok2 := b.Sys().(*syscall.Stat_t)
	initial, ok3 := p.initial.Sys().(*syscall.Stat_t)
	if !ok || !ok2 || !ok3 || n.Uid != initial.Uid || n.Gid != initial.Gid || n.Mode != initial.Mode || other.Uid != n.Uid || other.Gid != n.Gid || other.Mode != n.Mode {
		return false
	}
	if p.private {
		return n.Uid == uint32(os.Getuid()) && a.Mode().Perm() == 0700 && a.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
	}
	if n.Uid != 0 && n.Uid != uint32(os.Getuid()) {
		return false
	}
	if a.Mode()&os.ModeSetuid != 0 {
		return false
	}
	if a.Mode().Perm()&0022 != 0 || a.Mode()&(os.ModeSetgid|os.ModeSticky) != 0 {
		var fs syscall.Statfs_t
		if syscall.Fstatfs(int(p.file.Fd()), &fs) != nil || fs.Flags&1 == 0 {
			return false
		}
	}
	return true
}
func publisherSafeFile(info os.FileInfo, source bool, allowEmpty bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() > 16384 || info.Size() < 0 || !allowEmpty && info.Size() == 0 {
		return false
	}
	n, ok := info.Sys().(*syscall.Stat_t)
	if !ok || n.Nlink != 1 {
		return false
	}
	if !source {
		return n.Uid == uint32(os.Getuid()) && info.Mode().Perm() == 0600
	}
	m := info.Mode().Perm()
	return (n.Uid == 0 || n.Uid == uint32(os.Getuid())) && (m == 0400 || m == 0440 || m == 0600 || m == 0640)
}
func publisherSameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x.Uid == y.Uid && x.Gid == y.Gid && x.Mode == y.Mode && x.Nlink == y.Nlink && x.Ctim == y.Ctim && x.Mtim == y.Mtim
}
func publisherRead(root *os.Root, name string, source, empty bool) ([]byte, os.FileInfo, error) {
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, nil, ErrDenied
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !publisherSafeFile(before, source, empty) {
		return nil, nil, ErrDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	after, e2 := f.Stat()
	path, e3 := root.Lstat(name)
	if e != nil || e2 != nil || e3 != nil || int64(len(raw)) != before.Size() || !publisherSameFile(before, after) || !publisherSameFile(before, path) {
		clear(raw)
		return nil, nil, ErrDenied
	}
	return raw, before, nil
}
func publisherExpiry(raw []byte) (time.Time, bool) {
	if !bearer(raw, 16384) {
		return time.Time{}, false
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	var payload []byte
	for i, s := range parts {
		if s == "" {
			return time.Time{}, false
		}
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
			return time.Time{}, false
		}
		if i == 1 {
			payload = b
		} else {
			clear(b)
		}
	}
	defer clear(payload)
	o, e := parseJSON(payload)
	if e != nil {
		return time.Time{}, false
	}
	n, ok := o["exp"].(json.Number)
	if !ok {
		return time.Time{}, false
	}
	seconds, e := strconv.ParseInt(string(n), 10, 64)
	if e != nil || seconds < 1 || seconds > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}
func publisherFresh(ctx context.Context, expiry time.Time, minimum time.Duration) bool {
	return ctx.Err() == nil && expiry.Sub(time.Now()) >= minimum
}
func (p *publisherDirectory) source(config PublisherConfig) ([]byte, time.Time, error) {
	if !p.valid() {
		return nil, time.Time{}, ErrDenied
	}
	outer, e := p.root.Readlink(config.SourceName)
	generation, e2 := p.root.Readlink("..data")
	if e != nil || e2 != nil || outer != "..data/"+config.SourceName || !strings.HasPrefix(generation, "..") || generation == ".." || filepath.Base(generation) != generation || strings.ContainsAny(generation, "/\\") {
		return nil, time.Time{}, ErrDenied
	}
	// Opening the exact generation name keeps the read coherent even when
	// kubelet atomically replaces ..data. All traversal remains rooted.
	before, e := p.root.Lstat(generation)
	if e != nil || !before.IsDir() {
		return nil, time.Time{}, ErrDenied
	}
	r, e := p.root.OpenRoot(generation)
	if e != nil {
		return nil, time.Time{}, ErrDenied
	}
	defer r.Close()
	f, e := r.Open(".")
	if e != nil {
		return nil, time.Time{}, ErrDenied
	}
	defer f.Close()
	dir := &publisherDirectory{r, f, filepath.Join(p.path, generation), before, false}
	if !dir.valid() {
		return nil, time.Time{}, ErrDenied
	}
	raw, _, e := publisherRead(r, config.SourceName, true, false)
	if e != nil {
		return nil, time.Time{}, ErrDenied
	}
	outerAfter, e3 := p.root.Readlink(config.SourceName)
	generationAfter, e4 := p.root.Readlink("..data")
	if e3 != nil || e4 != nil || outerAfter != outer || generationAfter != generation || !dir.valid() || !p.valid() {
		clear(raw)
		return nil, time.Time{}, ErrDenied
	}
	expiry, ok := publisherExpiry(raw)
	if !ok {
		clear(raw)
		return nil, time.Time{}, ErrDenied
	}
	return raw, expiry, nil
}

type reviewerPublisher struct {
	directory *publisherDirectory
	lock      *os.File
	lockInfo  os.FileInfo
	output    os.FileInfo
	stage     os.FileInfo
}

func (p *reviewerPublisher) valid() bool {
	if !p.directory.valid() {
		return false
	}
	a, e := p.lock.Stat()
	b, e2 := p.directory.root.Lstat(".publisher.lock")
	return e == nil && e2 == nil && publisherSafeFile(a, false, true) && publisherSameFile(p.lockInfo, a) && publisherSameFile(a, b) && a.Size() == 0
}
func (p *reviewerPublisher) matches(name string, expected os.FileInfo) bool {
	a, e := p.directory.root.Lstat(name)
	if expected == nil {
		return os.IsNotExist(e)
	}
	return e == nil && publisherSafeFile(a, false, true) && publisherSameFile(expected, a)
}
func (p *reviewerPublisher) remove(name string, owned *os.FileInfo) error {
	if *owned == nil {
		return nil
	}
	if !p.valid() {
		return ErrDenied
	}
	a, e := p.directory.root.Lstat(name)
	if os.IsNotExist(e) {
		// An observed absence may follow an earlier uncertain unlink. Establish
		// directory durability before forgetting the captured ownership record.
		if p.directory.file.Sync() != nil || !p.valid() {
			return ErrDenied
		}
		if _, after := p.directory.root.Lstat(name); !os.IsNotExist(after) {
			return ErrDenied
		}
		*owned = nil
		return nil
	}
	if e != nil || !publisherSafeFile(a, false, true) || !publisherSameFile(*owned, a) {
		return ErrDenied
	}
	if p.directory.root.Remove(name) != nil {
		return ErrDenied
	}
	*owned = nil
	if p.directory.file.Sync() != nil || !p.valid() {
		return ErrDenied
	}
	return nil
}
func (p *reviewerPublisher) withdraw() error { return p.remove("credential", &p.output) }
func (p *reviewerPublisher) cleanup() error {
	a := p.remove(".credential.next", &p.stage)
	b := p.withdraw()
	if a != nil || b != nil {
		return ErrDenied
	}
	return nil
}
func newReviewerPublisher(directory *publisherDirectory) (*reviewerPublisher, error) {
	lock, e := directory.root.OpenFile(".publisher.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, ErrDenied
	}
	good := false
	defer func() {
		if !good {
			lock.Close()
		}
	}()
	info, e := lock.Stat()
	if e != nil || !publisherSafeFile(info, false, true) || info.Size() != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrDenied
	}
	p := &reviewerPublisher{directory: directory, lock: lock, lockInfo: info}
	if !p.valid() || lock.Sync() != nil || directory.file.Sync() != nil {
		return nil, ErrDenied
	}
	// Adoption is operator-authorized recovery of this private reserved path,
	// not a claim that these predicates identify the previous writer.
	if _, e = directory.root.Lstat("credential"); e == nil {
		raw, info, e := publisherRead(directory.root, "credential", false, false)
		if e != nil {
			return nil, ErrDenied
		}
		_, ok := publisherExpiry(raw)
		clear(raw)
		if !ok {
			return nil, ErrDenied
		}
		p.output = info
		// Visibility alone does not prove a previous process completed its syncs.
		// Adopt and reuse only after this process establishes file+directory durability.
		if p.syncAdoptedOutput() != nil {
			return nil, ErrDenied
		}
	} else if !os.IsNotExist(e) {
		return nil, ErrDenied
	}
	if _, e = directory.root.Lstat(".credential.next"); e == nil {
		raw, info, e := publisherRead(directory.root, ".credential.next", false, true)
		clear(raw)
		if e != nil {
			return nil, ErrDenied
		}
		p.stage = info
		if p.remove(".credential.next", &p.stage) != nil {
			return nil, ErrDenied
		}
	} else if !os.IsNotExist(e) {
		return nil, ErrDenied
	}
	good = true
	return p, nil
}

func (p *reviewerPublisher) syncAdoptedOutput() error {
	if !p.valid() || !p.matches("credential", p.output) {
		return ErrDenied
	}
	f, e := p.directory.root.OpenFile("credential", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return ErrDenied
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !publisherSafeFile(before, false, false) || !publisherSameFile(p.output, before) {
		return ErrDenied
	}
	if f.Sync() != nil || p.directory.file.Sync() != nil {
		return ErrDenied
	}
	after, e := f.Stat()
	if e != nil || !publisherSameFile(before, after) || !p.valid() || !p.matches("credential", after) {
		return ErrDenied
	}
	p.output = after
	return nil
}

// publish returns expired=true only for cancellation/advisory expiry. All IO or
// namespace uncertainty is fatal and is never converted into a successful poll.
func (p *reviewerPublisher) publish(ctx context.Context, config PublisherConfig, raw []byte, expiry time.Time) (expired bool, err error) {
	if !p.valid() || !p.matches("credential", p.output) {
		return false, ErrDenied
	}
	if !publisherFresh(ctx, expiry, config.MinimumRemainingLifetime) {
		return true, nil
	}
	if p.output != nil {
		current, info, e := publisherRead(p.directory.root, "credential", false, false)
		unchanged := e == nil && publisherSameFile(p.output, info) && bytes.Equal(current, raw)
		clear(current)
		if e != nil || !publisherSameFile(p.output, info) {
			return false, ErrDenied
		}
		if unchanged {
			if !p.valid() {
				return false, ErrDenied
			}
			return !publisherFresh(ctx, expiry, config.MinimumRemainingLifetime), nil
		}
	}
	f, e := p.directory.root.OpenFile(".credential.next", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return false, ErrDenied
	}
	defer f.Close()
	p.stage, e = f.Stat()
	if e != nil || !publisherSafeFile(p.stage, false, true) {
		return false, ErrDenied
	}
	for written := 0; written < len(raw); {
		n, e := f.Write(raw[written:])
		if e != nil || n < 1 {
			p.stage, _ = f.Stat()
			return false, ErrDenied
		}
		written += n
	}
	if f.Sync() != nil {
		p.stage, _ = f.Stat()
		return false, ErrDenied
	}
	p.stage, e = f.Stat()
	if e != nil || !publisherSafeFile(p.stage, false, false) || p.stage.Size() != int64(len(raw)) {
		return false, ErrDenied
	}
	if f.Close() != nil {
		return false, ErrDenied
	}
	if !p.valid() || !p.matches(".credential.next", p.stage) || !p.matches("credential", p.output) {
		return false, ErrDenied
	}
	if !publisherFresh(ctx, expiry, config.MinimumRemainingLifetime) {
		return true, nil
	}
	if p.directory.root.Rename(".credential.next", "credential") != nil {
		return false, ErrDenied
	}
	p.output = p.stage
	p.stage = nil
	// rename changes inode ctime on Linux. Capture the new coherent snapshot
	// before any later cleanup, while retaining the exact inode identity.
	after, e := p.directory.root.Lstat("credential")
	if e != nil || !os.SameFile(p.output, after) || !publisherSafeFile(after, false, false) {
		return false, ErrDenied
	}
	p.output = after
	if p.directory.file.Sync() != nil {
		return false, ErrDenied
	}
	back, info, e := publisherRead(p.directory.root, "credential", false, false)
	defer clear(back)
	if e != nil || !publisherSameFile(p.output, info) || !bytes.Equal(raw, back) || !p.valid() {
		return false, ErrDenied
	}
	p.output = info
	if !publisherFresh(ctx, expiry, config.MinimumRemainingLifetime) {
		return true, nil
	}
	return false, nil
}
func runReviewerPublisher(ctx context.Context, config PublisherConfig) (result error) {
	if ctx == nil {
		return ErrDenied
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.MinimumRemainingLifetime == 0 {
		config.MinimumRemainingLifetime = 30 * time.Second
	}
	if config.PollInterval < 250*time.Millisecond || config.PollInterval > 5*time.Second || config.MinimumRemainingLifetime < 5*time.Second || config.MinimumRemainingLifetime > 5*time.Minute || config.SourceName == "" || config.SourceName == "." || strings.HasPrefix(config.SourceName, "..") || filepath.Base(config.SourceName) != config.SourceName || !ascii(config.SourceName, 1, 128) || strings.ContainsAny(config.SourceName, "/\\") {
		return ErrDenied
	}
	source, e := openPublisherDirectory(config.SourceDirectory, false)
	if e != nil {
		return ErrDenied
	}
	defer source.close()
	destination, e := openPublisherDirectory(config.DestinationDirectory, true)
	if e != nil {
		return ErrDenied
	}
	defer destination.close()
	if os.SameFile(source.initial, destination.initial) {
		return ErrDenied
	}
	p, e := newReviewerPublisher(destination)
	if e != nil {
		return ErrDenied
	}
	defer func() {
		if p.cleanup() != nil {
			result = ErrDenied
		}
		syscall.Flock(int(p.lock.Fd()), syscall.LOCK_UN)
		p.lock.Close()
	}()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !source.valid() || !p.valid() || !p.matches("credential", p.output) {
			return ErrDenied
		}
		raw, expiry, readError := source.source(config)
		if readError != nil || !publisherFresh(ctx, expiry, config.MinimumRemainingLifetime) {
			clear(raw)
			if p.withdraw() != nil {
				return ErrDenied
			}
		} else {
			expired, e := p.publish(ctx, config, raw, expiry)
			clear(raw)
			if e != nil {
				return ErrDenied
			}
			if expired {
				if p.cleanup() != nil {
					return ErrDenied
				}
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
