//go:build darwin && cgo

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsevents"
)

type skillWatcher struct {
	stream  *fsevents.EventStream
	roots   []string
	initial map[string]os.FileInfo
	changed chan struct{}
	stop    chan struct{}
}

func newSkillWatcher(roots []string) (*skillWatcher, error) {
	// A skills folder can be installed for the first time after enrollment.
	// Watch an existing ancestor and filter notifications to the assigned tree.
	paths := []string{}
	initial := make(map[string]os.FileInfo, len(roots))
	for _, root := range roots {
		initial[root], _ = os.Lstat(root)
		parent := filepath.Dir(root)
		for {
			if meta, err := os.Lstat(parent); err == nil && meta.IsDir() {
				break
			}
			next := filepath.Dir(parent)
			if next == parent {
				return nil, errUnavailable
			}
			parent = next
		}
		if !slices.Contains(paths, parent) {
			paths = append(paths, parent)
		}
	}
	stream := &fsevents.EventStream{Paths: paths, Events: make(chan []fsevents.Event, 8), Flags: fsevents.FileEvents | fsevents.WatchRoot, Latency: 250 * time.Millisecond}
	if err := stream.Start(); err != nil {
		return nil, err
	}
	w := &skillWatcher{stream: stream, roots: roots, initial: initial, changed: make(chan struct{}, 1), stop: make(chan struct{})}
	// Drain native batches even while the CLI is hashing a large skill.
	go func() {
		for {
			select {
			case <-w.stop:
				return
			case batch := <-stream.Events:
				if slices.ContainsFunc(batch, w.relevant) {
					select {
					case w.changed <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return w, nil
}

func (w *skillWatcher) relevant(event fsevents.Event) bool {
	// Dropped events invalidate the observation of every watched tree.
	if event.Flags&(fsevents.UserDropped|fsevents.KernelDropped|fsevents.EventIDsWrapped|fsevents.RootChanged) != 0 {
		return true
	}
	path := filepath.Clean("/" + event.Path)
	for _, root := range w.roots {
		if strings.HasPrefix(path, root+"/") {
			return true
		}
		if path != root && !strings.HasPrefix(root, path+"/") {
			continue
		}
		if event.Flags&fsevents.MustScanSubDirs != 0 {
			return true
		}
		// The OS can deliver a batched creation of the already observed
		// parent or socket just after subscription. Wake only when that
		// event actually changed the selected root.
		before := w.initial[root]
		after, err := os.Lstat(root)
		if err != nil && !os.IsNotExist(err) {
			return true
		}
		if before == nil || after == nil {
			if before != after {
				return true
			}
		} else if !os.SameFile(before, after) || before.Mode() != after.Mode() ||
			(before.Mode()&os.ModeSocket == 0 && !before.ModTime().Equal(after.ModTime())) {
			return true
		}
	}
	return false
}

func (w *skillWatcher) wait(ctx context.Context) bool {
	// Coalesce writes during extraction or an atomic save. Idle watchers
	// have no timer and perform no scans.
	select {
	case <-ctx.Done():
		return false
	case <-w.changed:
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(250 * time.Millisecond):
	}
	select {
	case <-w.changed:
	default:
	}
	return true
}

func (w *skillWatcher) close() {
	w.stream.Stop()
	close(w.stop)
}
