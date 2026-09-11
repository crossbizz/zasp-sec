package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
)

var errLineageIdentity = errors.New("sensor lineage identity unavailable")
var lineageIdentityUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validLineageUUID(value string) bool {
	return lineageIdentityUUIDPattern.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}

type hostBootReader struct {
	mu     sync.Mutex
	root   *os.Root
	name   string
	owner  uint32
	procFS bool
	closed bool
}

// The future production collector must pin the read-only host-proc mount and
// require owner 0. Explicit owner injection supports non-root file fixtures;
// this constructor alone doesn't authenticate a host mount or local endpoint.
func newHostBootReader(path string, owner uint32) (*hostBootReader, error) {
	if !validAbsolute(path) {
		return nil, errLineageIdentity
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageIdentity
	}
	return &hostBootReader{root: root, name: filepath.Base(path), owner: owner}, nil
}

// The production source additionally requires an actual procfs parent. A
// root-owned regular file on another filesystem isn't a kernel boot source.
// Deployment must supply the read-only local host-proc mount; this check isn't
// host attestation or a guarantee that opening arbitrary paths cannot block.
func newProcBootReader(path string) (*hostBootReader, error) {
	if runtime.GOOS != "linux" || filepath.Base(path) != "boot_id" {
		return nil, errLineageIdentity
	}
	reader, err := newHostBootReader(path, 0)
	if err != nil {
		return nil, errLineageIdentity
	}
	directory, err := reader.root.Open(".")
	if err != nil {
		reader.Close()
		return nil, errLineageIdentity
	}
	defer directory.Close()
	var filesystem syscall.Statfs_t
	if syscall.Fstatfs(int(directory.Fd()), &filesystem) != nil || filesystem.Type != 0x9fa0 {
		reader.Close()
		return nil, errLineageIdentity
	}
	reader.procFS = true
	return reader, nil
}

func (reader *hostBootReader) Read() (string, error) {
	if reader == nil {
		return "", errLineageIdentity
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return "", errLineageIdentity
	}
	before, err := reader.root.Lstat(reader.name)
	if err != nil || !reader.validFile(before) {
		return "", errLineageIdentity
	}
	file, err := reader.root.OpenFile(reader.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errLineageIdentity
	}
	defer file.Close()
	opened, err := file.Stat()
	after, afterErr := reader.root.Lstat(reader.name)
	if err != nil || afterErr != nil || !reader.validFile(opened) || !reader.validFile(after) || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return "", errLineageIdentity
	}
	if reader.procFS {
		var filesystem syscall.Statfs_t
		if syscall.Fstatfs(int(file.Fd()), &filesystem) != nil || filesystem.Type != 0x9fa0 {
			return "", errLineageIdentity
		}
	}
	// procfs can report size zero. Bound actual bytes, with one overflow byte.
	raw, err := io.ReadAll(io.LimitReader(file, 38))
	if err != nil || len(raw) < 36 || len(raw) > 37 {
		return "", errLineageIdentity
	}
	value := string(raw)
	if len(value) == 37 {
		if value[36] != '\n' {
			return "", errLineageIdentity
		}
		value = value[:36]
	}
	if !validLineageUUID(value) {
		return "", errLineageIdentity
	}
	return value, nil
}

func (reader *hostBootReader) validFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 0 || info.Size() > 37 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == reader.owner && stat.Nlink == 1
}

func (reader *hostBootReader) Close() error {
	if reader == nil {
		return errLineageIdentity
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	if reader.root.Close() != nil {
		return errLineageIdentity
	}
	return nil
}

type lineageIdentityAPI interface {
	GetNode(context.Context) (*corev1.Node, error)
	GetClusterNamespace(context.Context) (*corev1.Namespace, error)
}

// This copied observation isn't an atomic Kubernetes snapshot, stream freshness
// guarantee, tenant authority or host attestation. The collector must compare
// observations around authenticated local stream creation before binding a new
// generation. Existing exporter files don't gain this identity retroactively.
type lineageHostIdentity struct {
	NodeName   string
	ClusterUID string
	NodeUID    string
	BootID     string
}

func resolveLineageIdentity(ctx context.Context, nodeName string, api lineageIdentityAPI, boot *hostBootReader) (identity lineageHostIdentity, err error) {
	defer func() {
		if recover() != nil {
			identity, err = lineageHostIdentity{}, errLineageIdentity
		}
	}()
	if ctx == nil || ctx.Err() != nil || !validKubernetesName(nodeName) || nilClusterValue(api) || boot == nil {
		return lineageHostIdentity{}, errLineageIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	firstBoot, err := boot.Read()
	if err != nil || ctx.Err() != nil {
		return lineageHostIdentity{}, errLineageIdentity
	}
	var first lineageHostIdentity
	for attempt := 0; attempt < 2; attempt++ {
		namespace, err := api.GetClusterNamespace(ctx)
		if err != nil || ctx.Err() != nil || namespace == nil || namespace.Name != "kube-system" || namespace.Namespace != "" || namespace.DeletionTimestamp != nil || namespace.Status.Phase != corev1.NamespaceActive || !validLineageUUID(string(namespace.UID)) {
			return lineageHostIdentity{}, errLineageIdentity
		}
		// Copy before calling another provider: test clients and caches may reuse
		// object pointers. Resource versions may change without identity changes.
		clusterUID := string(namespace.UID)
		node, err := api.GetNode(ctx)
		if err != nil || ctx.Err() != nil || node == nil || node.Name != nodeName || node.Namespace != "" || node.DeletionTimestamp != nil || !validLineageUUID(string(node.UID)) || node.Status.NodeInfo.BootID != firstBoot {
			return lineageHostIdentity{}, errLineageIdentity
		}
		current := lineageHostIdentity{NodeName: nodeName, ClusterUID: clusterUID, NodeUID: string(node.UID), BootID: firstBoot}
		if attempt == 0 {
			first = current
		} else if current != first {
			return lineageHostIdentity{}, errLineageIdentity
		}
	}
	lastBoot, err := boot.Read()
	if err != nil || ctx.Err() != nil || lastBoot != firstBoot {
		return lineageHostIdentity{}, errLineageIdentity
	}
	return first, nil
}
