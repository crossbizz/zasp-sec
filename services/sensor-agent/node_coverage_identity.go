package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// A sibling of producer/acks/consumer, never a new spool entry or event recipe.
type nodeIdentityWitness struct {
	Schema     string                      `json:"schema"`
	Source     sensoradapter.LineageSource `json:"source"`
	PodName    string                      `json:"pod_name"`
	PodUID     string                      `json:"pod_uid"`
	ObservedAt time.Time                   `json:"observed_at"`
}
type nodeWitnessFile struct {
	mu              sync.Mutex
	root            *os.Root
	writer          bool
	podName, podUID string
	gid             uint32
	closed          bool
}

func openNodeWitness(path, podName, podUID string, gid uint32, writer bool) (*nodeWitnessFile, error) {
	if !validAbsolute(path) || !validKubernetesName(podName) || !validLineageUUID(podUID) {
		return nil, ErrCluster
	}
	before, e := os.Lstat(path)
	if e != nil || !before.IsDir() || before.Mode().Perm() != 0750 {
		return nil, ErrCluster
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid || writer && os.Geteuid() != 0 {
		return nil, ErrCluster
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, ErrCluster
	}
	f, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, ErrCluster
	}
	held, e := f.Stat()
	f.Close()
	if e != nil || !os.SameFile(before, held) {
		root.Close()
		return nil, ErrCluster
	}
	return &nodeWitnessFile{root: root, writer: writer, podName: podName, podUID: podUID, gid: gid}, nil
}
func (w *nodeWitnessFile) publish(ctx context.Context, source sensoradapter.LineageSource) error {
	if w == nil || ctx == nil || ctx.Err() != nil {
		return ErrCluster
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.writer {
		return ErrCluster
	}
	value := nodeIdentityWitness{Schema: "zasp-node-identity-v1", Source: source, PodName: w.podName, PodUID: w.podUID, ObservedAt: time.Now().UTC()}
	body, e := json.Marshal(value)
	if e != nil || len(body) > 8192 {
		return ErrCluster
	}
	// One writer exists per node's existing root-owned layout/producer lifetime.
	f, e := w.root.OpenFile(".identity.pending", os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0640)
	if e != nil {
		return ErrCluster
	}
	info, ie := f.Stat()
	if ie != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 {
		f.Close()
		return ErrCluster
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != w.gid || st.Nlink != 1 || f.Truncate(0) != nil {
		f.Close()
		return ErrCluster
	}
	defer w.root.Remove(".identity.pending")
	if _, e = f.Write(body); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil || ctx.Err() != nil {
		return ErrCluster
	}
	if w.root.Rename(".identity.pending", "identity.json") != nil {
		return ErrCluster
	}
	directory, e := w.root.Open(".")
	if e != nil {
		return ErrCluster
	}
	defer directory.Close()
	return directory.Sync()
}
func (w *nodeWitnessFile) read(now time.Time, ttl time.Duration) (nodeIdentityWitness, error) {
	var value nodeIdentityWitness
	if w == nil {
		return value, ErrCluster
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return value, ErrCluster
	}
	before, e := w.root.Lstat("identity.json")
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0640 || before.Size() < 1 || before.Size() > 8192 {
		return value, ErrCluster
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != w.gid || stat.Nlink != 1 {
		return value, ErrCluster
	}
	f, e := w.root.OpenFile("identity.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return value, ErrCluster
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return value, ErrCluster
	}
	body, e := io.ReadAll(io.LimitReader(f, 8193))
	named, ne := w.root.Lstat("identity.json")
	if e != nil || ne != nil || !os.SameFile(before, named) || len(body) > 8192 {
		return value, ErrCluster
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF || value.Schema != "zasp-node-identity-v1" || value.PodName != w.podName || value.PodUID != w.podUID || !validLineageUUID(value.Source.ClusterUID) || !validLineageUUID(value.Source.NodeUID) || !validLineageUUID(value.Source.BootID) || !validLineageUUID(value.Source.GenerationID) || value.ObservedAt.IsZero() || value.ObservedAt.After(now.Add(5*time.Second)) || value.ObservedAt.Before(now.Add(-ttl)) {
		return nodeIdentityWitness{}, ErrCluster
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, body) {
		return nodeIdentityWitness{}, ErrCluster
	}
	return value, nil
}
func (w *nodeWitnessFile) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.root.Close()
}
func validCoverageWitnessPath(path, spool string) bool {
	return validAbsolute(path) && filepath.Clean(path) == path && filepath.Base(path) == "observations" && filepath.Base(spool) == "producer" && filepath.Dir(path) == filepath.Dir(spool) && path != spool && !stringsCoverageNested(path, spool)
}
func stringsCoverageNested(a, b string) bool {
	return len(a) > len(b) && a[:len(b)] == b && a[len(b)] == '/' || len(b) > len(a) && b[:len(a)] == a && b[len(a)] == '/'
}
