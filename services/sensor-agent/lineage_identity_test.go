package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const fixtureHostBootID = "12345678-1234-1234-1234-123456789003"

func fixtureBootReader(t *testing.T) (*hostBootReader, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boot_id")
	writeSensorFixture(t, path, fixtureHostBootID+"\n", 0o600)
	reader, err := newHostBootReader(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return reader, path
}

type lineageIdentityAPIFixture struct {
	node                      *corev1.Node
	namespace                 *corev1.Namespace
	nodeCalls, namespaceCalls int
	onNode                    func()
	onNamespace               func()
}

func newLineageIdentityAPIFixture() *lineageIdentityAPIFixture {
	return &lineageIdentityAPIFixture{node: &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("12345678-1234-1234-1234-123456789002")}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: fixtureHostBootID}}}, namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("12345678-1234-1234-1234-123456789001")}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}}
}

func (api *lineageIdentityAPIFixture) GetNode(context.Context) (*corev1.Node, error) {
	api.nodeCalls++
	if api.onNode != nil {
		api.onNode()
	}
	return api.node, nil
}
func (api *lineageIdentityAPIFixture) GetClusterNamespace(context.Context) (*corev1.Namespace, error) {
	api.namespaceCalls++
	if api.onNamespace != nil {
		api.onNamespace()
	}
	return api.namespace, nil
}

func TestLineageIdentityMatchesHostAndRepeatedKubernetesReads(t *testing.T) {
	reader, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	identity, err := resolveLineageIdentity(context.Background(), "node-a", api, reader)
	want := lineageHostIdentity{NodeName: "node-a", ClusterUID: string(api.namespace.UID), NodeUID: string(api.node.UID), BootID: fixtureHostBootID}
	if err != nil || identity != want || api.nodeCalls != 2 || api.namespaceCalls != 2 {
		t.Fatal("identity not established through bounded repeated reads", identity, err)
	}
	api.node.UID = types.UID("12345678-1234-1234-1234-123456789099")
	if identity != want {
		t.Fatal("returned identity retained mutable provider pointers")
	}
}

func TestLineageIdentityRejectsDisagreementAndMutableObjectReuse(t *testing.T) {
	for _, name := range []string{"boot mismatch", "host boot changes", "node recreated", "namespace recreated", "wrong node", "wrong namespace", "missing node", "missing namespace", "zero UID", "node deleting", "namespace deleting", "namespace terminating", "close during API", "canceled during API"} {
		t.Run(name, func(t *testing.T) {
			reader, path := fixtureBootReader(t)
			api := newLineageIdentityAPIFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "boot mismatch":
				api.node.Status.NodeInfo.BootID = "12345678-1234-1234-1234-123456789099"
			case "host boot changes":
				api.onNode = func() {
					if api.nodeCalls == 2 {
						writeSensorFixture(t, path, "12345678-1234-1234-1234-123456789099\n", 0o600)
					}
				}
			case "node recreated":
				api.onNamespace = func() {
					if api.namespaceCalls == 2 {
						api.node.UID = types.UID("12345678-1234-1234-1234-123456789099")
					}
				}
			case "namespace recreated":
				api.onNode = func() {
					if api.nodeCalls == 1 {
						api.namespace.UID = types.UID("12345678-1234-1234-1234-123456789099")
					}
				}
			case "wrong node":
				api.node.Name = "node-b"
			case "wrong namespace":
				api.namespace.Name = "default"
			case "missing node":
				api.node = nil
			case "missing namespace":
				api.namespace = nil
			case "zero UID":
				api.node.UID = types.UID("00000000-0000-0000-0000-000000000000")
			case "node deleting":
				now := metav1.Now()
				api.node.DeletionTimestamp = &now
			case "namespace deleting":
				now := metav1.Now()
				api.namespace.DeletionTimestamp = &now
			case "namespace terminating":
				api.namespace.Status.Phase = corev1.NamespaceTerminating
			case "close during API":
				api.onNode = func() { _ = reader.Close() }
			case "canceled during API":
				api.onNamespace = cancel
			}
			if identity, err := resolveLineageIdentity(ctx, "node-a", api, reader); err != errLineageIdentity || identity != (lineageHostIdentity{}) {
				t.Fatal("unstable identity accepted", identity, err)
			}
			if name == "canceled during API" && (api.namespaceCalls != 1 || api.nodeCalls != 0) {
				t.Fatal("canceled lookup performed more API calls")
			}
		})
	}
}

func TestHostBootReaderExactBoundedPrivateRegularInput(t *testing.T) {
	for _, value := range []string{"", fixtureHostBootID + "\r\n", fixtureHostBootID + "\n\n", strings.ToUpper(fixtureHostBootID), "00000000-0000-0000-0000-000000000000", strings.Repeat("a", 4096)} {
		// The numeric-only fixture UUID has no uppercase variant; use a hex letter.
		if value == fixtureHostBootID {
			value = "abcdefAB-1234-1234-1234-123456789003"
		}
		reader, path := fixtureBootReader(t)
		writeSensorFixture(t, path, value, 0o600)
		if got, err := reader.Read(); err != errLineageIdentity || got != "" {
			t.Fatal("noncanonical boot accepted", err)
		}
	}
	for _, mode := range []os.FileMode{0o622, 0o664, 0o666} {
		reader, path := fixtureBootReader(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if got, err := reader.Read(); err != errLineageIdentity || got != "" {
			t.Fatal("writable boot source accepted", err)
		}
	}
	reader, path := fixtureBootReader(t)
	writeSensorFixture(t, path, fixtureHostBootID, 0o600)
	if got, err := reader.Read(); err != nil || got != fixtureHostBootID {
		t.Fatal("exact UUID rejected", err)
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Read(); err != errLineageIdentity || got != "" {
		t.Fatal("symlink boot input accepted", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := reader.Read(); err != errLineageIdentity || got != "" {
		t.Fatal("closed boot reader accepted", err)
	}
}

func TestHostBootReaderPinsParentAndSerializesClose(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "host")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "boot_id")
	writeSensorFixture(t, path, fixtureHostBootID+"\n", 0o600)
	reader, err := newHostBootReader(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := os.Rename(parent, parent+".pinned"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSensorFixture(t, path, "12345678-1234-1234-1234-123456789099\n", 0o600)
	if got, err := reader.Read(); err != nil || got != fixtureHostBootID {
		t.Fatal("reader followed a replaced parent", err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for attempt := 0; attempt < 32; attempt++ {
				got, err := reader.Read()
				if err == nil && got != fixtureHostBootID || err != nil && (err != errLineageIdentity || got != "") {
					t.Error("read/close race changed identity")
				}
			}
		}()
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
	if got, err := reader.Read(); err != errLineageIdentity || got != "" {
		t.Fatal("read succeeded after close", err)
	}
}

func TestHostBootReaderActualLinuxProcFS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires real Linux procfs")
	}
	reader, err := newProcBootReader("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	identity, err := reader.Read()
	if err != nil || !validLineageUUID(identity) {
		t.Fatal("actual procfs boot identity rejected", err)
	}
	if again, err := reader.Read(); err != nil || again != identity {
		t.Fatal("procfs boot observation unstable", err)
	}
}

func TestProcBootReaderRejectsOrdinaryFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot_id")
	writeSensorFixture(t, path, fixtureHostBootID+"\n", 0o600)
	if reader, err := newProcBootReader(path); err != errLineageIdentity || reader != nil {
		if reader != nil {
			reader.Close()
		}
		t.Fatal("ordinary file accepted as kernel boot source", err)
	}
}

func TestHostBootReaderChecksOpenedLeafFilesystem(t *testing.T) {
	reader, _ := fixtureBootReader(t)
	reader.procFS = true
	if value, err := reader.Read(); err != errLineageIdentity || value != "" {
		t.Fatal("ordinary leaf accepted by procfs reader", err)
	}
}
