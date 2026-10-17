//go:build linux

package gatewaypodidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type publisherFixture struct {
	config     PublisherConfig
	generation int
}

func newPublisherFixture(t *testing.T) *publisherFixture {
	t.Helper()
	f := &publisherFixture{config: PublisherConfig{SourceDirectory: t.TempDir(), SourceName: "reviewer-token", DestinationDirectory: t.TempDir(), PollInterval: 250 * time.Millisecond, MinimumRemainingLifetime: 5 * time.Second}}
	if e := os.Symlink("..data/reviewer-token", filepath.Join(f.config.SourceDirectory, "reviewer-token")); e != nil {
		t.Fatal(e)
	}
	f.rotate(t, projectedToken(time.Now().Add(time.Hour).Unix()))
	return f
}
func (f *publisherFixture) rotate(t *testing.T, token string) {
	t.Helper()
	f.generation++
	name := "..generation-" + strings.Repeat("x", f.generation)
	dir := filepath.Join(f.config.SourceDirectory, name)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "reviewer-token"), []byte(token), 0440); e != nil {
		t.Fatal(e)
	}
	next := filepath.Join(f.config.SourceDirectory, "..data-next")
	if e := os.Symlink(name, next); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(next, filepath.Join(f.config.SourceDirectory, "..data")); e != nil {
		t.Fatal(e)
	}
}
func (f *publisherFixture) sourceFile(t *testing.T) string {
	t.Helper()
	dir, e := os.Readlink(filepath.Join(f.config.SourceDirectory, "..data"))
	if e != nil {
		t.Fatal(e)
	}
	return filepath.Join(f.config.SourceDirectory, dir, "reviewer-token")
}
func publisherStart(f *publisherFixture) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunReviewerPublisher(ctx, f.config) }()
	return cancel, done
}
func publisherWait(t *testing.T, f *publisherFixture, done <-chan error, want string) {
	t.Helper()
	until := time.NewTimer(4 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		raw, e := reviewerCredential(filepath.Join(f.config.DestinationDirectory, "credential"))
		match := e == nil && string(raw) == want
		if want == "" {
			_, e = os.Lstat(filepath.Join(f.config.DestinationDirectory, "credential"))
			match = os.IsNotExist(e)
		}
		clear(raw)
		if match {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("publisher stopped before expected state: %v", err)
		case <-until.C:
			t.Fatal("publisher did not reach expected state")
		case <-tick.C:
		}
	}
}
func publisherJoin(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("publisher cancellation: %v", e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("publisher did not join")
	}
}

func TestReviewerPublisherProjectedRotationAndConsumer(t *testing.T) {
	f := newPublisherFixture(t)
	old, _ := os.ReadFile(f.sourceFile(t))
	cancel, done := publisherStart(f)
	defer cancel()
	publisherWait(t, f, done, string(old))
	first, e := os.Stat(filepath.Join(f.config.DestinationDirectory, "credential"))
	if e != nil {
		t.Fatal(e)
	}
	replacement := projectedToken(time.Now().Add(2 * time.Hour).Unix())
	f.rotate(t, replacement)
	publisherWait(t, f, done, replacement)
	second, e := os.Stat(filepath.Join(f.config.DestinationDirectory, "credential"))
	if e != nil || os.SameFile(first, second) {
		t.Fatal("rotation did not atomically replace inode")
	}
	publisherJoin(t, cancel, done)
	if _, e = os.Lstat(filepath.Join(f.config.DestinationDirectory, "credential")); !os.IsNotExist(e) {
		t.Fatal("canceled publisher retained output")
	}
	if _, e = os.Stat(filepath.Join(f.config.DestinationDirectory, ".publisher.lock")); e != nil {
		t.Fatal("stable owner lock removed")
	}
}
func TestReviewerPublisherSourceAndDestinationSafety(t *testing.T) {
	// An interrupted private stage can contain partial bytes. It is never the
	// consumer file and must be safely reclaimed under the stable owner guard.
	f := newPublisherFixture(t)
	if e := os.WriteFile(filepath.Join(f.config.DestinationDirectory, ".credential.next"), []byte("partial"), 0600); e != nil {
		t.Fatal(e)
	}
	token, _ := os.ReadFile(f.sourceFile(t))
	cancel, done := publisherStart(f)
	publisherWait(t, f, done, string(token))
	publisherJoin(t, cancel, done)
	for _, mode := range []string{"source-escape", "source-hardlink", "source-mode", "source-malformed", "source-expired"} {
		f := newPublisherFixture(t)
		switch mode {
		case "source-escape":
			outside := t.TempDir()
			if e := os.Remove(filepath.Join(f.config.SourceDirectory, "..data")); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink(outside, filepath.Join(f.config.SourceDirectory, "..data")); e != nil {
				t.Fatal(e)
			}
		case "source-hardlink":
			if e := os.Link(f.sourceFile(t), filepath.Join(f.config.SourceDirectory, "alias")); e != nil {
				t.Fatal(e)
			}
		case "source-mode":
			if e := os.Chmod(f.sourceFile(t), 0644); e != nil {
				t.Fatal(e)
			}
		case "source-malformed":
			f.rotate(t, "not-a-jwt")
		case "source-expired":
			f.rotate(t, projectedToken(time.Now().Add(-time.Hour).Unix()))
		}
		cancel, done := publisherStart(f)
		select {
		case err := <-done:
			cancel()
			t.Fatalf("%s did not retry recoverable input: %v", mode, err)
		case <-time.After(300 * time.Millisecond):
		}
		if _, e := os.Lstat(filepath.Join(f.config.DestinationDirectory, "credential")); !os.IsNotExist(e) {
			cancel()
			t.Fatalf("%s published", mode)
		}
		publisherJoin(t, cancel, done)
	}
	for _, mode := range []string{"target-symlink", "target-hardlink", "target-mode", "target-malformed", "stage-symlink"} {
		f := newPublisherFixture(t)
		outside := filepath.Join(t.TempDir(), "foreign")
		if e := os.WriteFile(outside, []byte("untouched"), 0600); e != nil {
			t.Fatal(e)
		}
		target := filepath.Join(f.config.DestinationDirectory, "credential")
		switch mode {
		case "target-symlink":
			if e := os.Symlink(outside, target); e != nil {
				t.Fatal(e)
			}
		case "target-hardlink":
			if e := os.Link(outside, target); e != nil {
				t.Fatal(e)
			}
		case "target-mode":
			if e := os.WriteFile(target, []byte("untouched"), 0644); e != nil {
				t.Fatal(e)
			}
		case "target-malformed":
			if e := os.WriteFile(target, []byte("untouched"), 0600); e != nil {
				t.Fatal(e)
			}
		case "stage-symlink":
			if e := os.Symlink(outside, filepath.Join(f.config.DestinationDirectory, ".credential.next")); e != nil {
				t.Fatal(e)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e := RunReviewerPublisher(ctx, f.config)
		cancel()
		if !errors.Is(e, ErrDenied) {
			t.Fatalf("%s unsafe destination: %v", mode, e)
		}
		raw, e := os.ReadFile(outside)
		if e != nil || string(raw) != "untouched" {
			t.Fatalf("%s changed foreign artifact", mode)
		}
	}
}
func TestReviewerPublisherCancellationExpiryAndOwnership(t *testing.T) {
	f := newPublisherFixture(t)
	token, _ := os.ReadFile(f.sourceFile(t))
	cancel, done := publisherStart(f)
	defer cancel()
	publisherWait(t, f, done, string(token))
	ctx, cancelOther := context.WithTimeout(context.Background(), time.Second)
	err := RunReviewerPublisher(ctx, f.config)
	cancelOther()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("second owner: %v", err)
	}
	publisherWait(t, f, done, string(token))
	f.rotate(t, projectedToken(time.Now().Add(2*time.Second).Unix()))
	publisherWait(t, f, done, "")
	replacement := projectedToken(time.Now().Add(3 * time.Hour).Unix())
	f.rotate(t, replacement)
	publisherWait(t, f, done, replacement)
	// A replacement outside the publisher's ownership is not deleted by shutdown.
	foreign := filepath.Join(f.config.DestinationDirectory, "foreign")
	if e := os.WriteFile(foreign, []byte("foreign-output"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(foreign, filepath.Join(f.config.DestinationDirectory, "credential")); e != nil {
		t.Fatal(e)
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, ErrDenied) {
			t.Fatalf("foreign replacement cleanup: %v", e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("publisher did not join")
	}
	raw, e := os.ReadFile(filepath.Join(f.config.DestinationDirectory, "credential"))
	if e != nil || string(raw) != "foreign-output" {
		t.Fatal("publisher removed foreign replacement")
	}
	// Restart adopts only a protected, well-formed old publisher artifact.
	restart := newPublisherFixture(t)
	if e := os.WriteFile(filepath.Join(restart.config.DestinationDirectory, "credential"), []byte(projectedToken(time.Now().Add(-time.Hour).Unix())), 0600); e != nil {
		t.Fatal(e)
	}
	cancelRestart, doneRestart := publisherStart(restart)
	newToken, _ := os.ReadFile(restart.sourceFile(t))
	publisherWait(t, restart, doneRestart, string(newToken))
	publisherJoin(t, cancelRestart, doneRestart)
}
